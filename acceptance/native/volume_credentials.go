package native

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// unlockContinuationVolumes uses only credentials independently recorded by
// Apple for the expected output state. Image-envelope credentials never enter
// this lookup, and every encrypted peer must have its own recorded credential.
func (v *Verifier) unlockContinuationVolumes(ctx context.Context, att *fixture.Attachment, expected *schema.Observation, recipe schema.Recipe) error {
	unlock, _ := volumeCredentials(expected)
	for _, vol := range att.Volumes {
		if !vol.Locked {
			continue
		}
		ref, ok := unlock[vol.Name]
		if !ok {
			return fmt.Errorf("encrypted continuation volume %s lacks a native credential", vol.Name)
		}
		password, ok := recipe.Passwords[ref]
		if !ok {
			return fmt.Errorf("unknown continuation volume credential %q", ref)
		}
		cmd := fixture.Command{Label: "unlock:" + ref, Argv: []string{"diskutil", "apfs", "unlockVolume", vol.Dev, "-stdinpassphrase", "-nomount"}, Stdin: []byte(password + "\n"), Expected: "0"}
		t := &fixture.Transcript{}
		v.setTranscript(t)
		if err := t.Record(cmd, v.C.Run(ctx, cmd)); err != nil {
			return err
		}
		vol.Locked = false
	}
	return nil
}

func continuationVolumeArguments(work, selected string, expected *schema.Observation, recipe schema.Recipe) ([]string, error) {
	var args []string
	if expected == nil {
		return nil, nil
	}
	for _, vol := range expected.Volumes {
		if vol.APFS == nil || !vol.APFS.Encrypted {
			continue
		}
		password, ok := recipe.Passwords[vol.APFS.Password]
		if !ok {
			return nil, fmt.Errorf("unknown continuation credential %q", vol.APFS.Password)
		}
		name := filepath.Join(work, fmt.Sprintf("volume-password-%d.bin", vol.Index))
		if err := os.WriteFile(name, []byte(password), 0600); err != nil {
			return nil, err
		}
		if vol.APFS.VolumeUUID == selected {
			args = append(args, "--password-file", name)
		} else {
			args = append(args, "--volume-password-file", vol.APFS.VolumeUUID+"="+name)
		}
	}
	return args, nil
}

func hasEncryptedVolumes(observation *schema.Observation) bool {
	if observation != nil {
		for _, vol := range observation.Volumes {
			if vol.APFS != nil && vol.APFS.Encrypted {
				return true
			}
		}
	}
	return false
}

// Apple's fsck_apfs -F requires unlocked volumes and checks their decrypted
// structures, rather than succeeding after skipping encrypted filesystem data.
// This is read-only; unlocking supplies keys, never a repair authorization.
func (v *Verifier) checkEncryptedVolumes(ctx context.Context, image string, imagePassword []byte, expected *schema.Observation, recipe schema.Recipe) error {
	if !hasEncryptedVolumes(expected) {
		return nil
	}
	att, err := v.Disk.Attach(ctx, image, fixture.AttachOptions{ReadOnly: true, Raw: filepath.Ext(image) == ".raw", Password: imagePassword})
	if err != nil {
		return err
	}
	err = v.unlockContinuationVolumes(ctx, att, expected, recipe)
	if err == nil {
		cmd := fixture.Command{Label: "fsck-unlocked", Argv: []string{"/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs", "-n", "-F", att.RDev}, Expected: "0"}
		t := &fixture.Transcript{}
		v.setTranscript(t)
		err = t.Record(cmd, v.C.Run(ctx, cmd))
	}
	return errors.Join(err, v.Disk.Detach(ctx, att))
}

func (v *Verifier) fsckContinuation(ctx context.Context, raw, fs string, expected *schema.Observation, recipe schema.Recipe) error {
	if hasEncryptedVolumes(expected) {
		return v.checkEncryptedVolumes(ctx, raw, nil, expected, recipe)
	}
	return v.fsckRaw(ctx, raw, fs)
}
