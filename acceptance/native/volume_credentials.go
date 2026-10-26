package native

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
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

func (v *Verifier) checkEncryptedFixture(ctx context.Context, k corpus.Case) (resultErr error) {
	finish := v.recordVerificationCommands(filepath.Join(v.Work, "verify", fmt.Sprintf("native-encrypted-control-macos-%d-%s", k.Producer, k.Profile)))
	defer finish(&resultErr)
	lease, err := v.Corpus.AcquireImage(ctx, k)
	if err != nil {
		return err
	}
	err = v.checkEncryptedVolumes(ctx, lease.Path(), nil, k.Observation, v.Recipes[k.Recipe])
	return errors.Join(err, lease.Release(err))
}

// DiskManagement's verification supplies the unlocked volume's crypto context
// to fsck. Direct fsck_apfs -F cannot validate even the untouched Apple controls
// on macOS 26/27. Require the full decrypted check, never a skipped-filesystem
// success. The attachment and verification are read-only.
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
		t := &fixture.Transcript{}
		v.setTranscript(t)
		for _, wanted := range expected.Volumes {
			if wanted.APFS == nil {
				continue
			}
			var volume *fixture.AttachedVolume
			for _, found := range att.Volumes {
				if strings.EqualFold(found.UUID, wanted.APFS.VolumeUUID) {
					volume = found
					break
				}
			}
			if volume == nil {
				err = fmt.Errorf("verification lacks expected APFS volume %s", wanted.APFS.VolumeUUID)
				break
			}
			cmd := fixture.Command{Label: "verify-unlocked-volume", Argv: []string{"diskutil", "verifyVolume", volume.Dev}, Expected: "0"}
			result := v.C.Run(ctx, cmd)
			err = t.Record(cmd, result)
			if err == nil {
				err = validateAPFSVerification(string(result.Stdout), volume.RDev, wanted.APFS)
			}
			if err != nil {
				break
			}
		}
	}
	return errors.Join(err, v.Disk.Detach(ctx, att))
}

func validateAPFSVerification(output, device string, volume *schema.APFSVolume) error {
	for _, stage := range []string{
		"Checking the container superblock", "Checking the checkpoint with transaction ID ",
		"Checking the space manager", "Checking the space manager free queue trees",
		"Checking the encryption key structures", "Checking the APFS volume superblock",
		"Checking the object map", "Checking the snapshot metadata tree",
		"Checking the snapshot metadata", "Checking the fsroot tree",
		"Checking the extent ref tree", "Verifying volume object map space",
		"Verifying allocated space", "File system check exit code is 0",
		fmt.Sprintf("The volume %s with UUID %s appears to be OK", device, volume.VolumeUUID),
	} {
		if !strings.Contains(output, stage) {
			return fmt.Errorf("APFS verification of %s lacks %q", volume.VolumeUUID, stage)
		}
	}
	for _, snapshot := range volume.Snapshots {
		if !strings.Contains(output, fmt.Sprintf("(%s, transaction ID %d)", snapshot.Name, snapshot.XID)) {
			return fmt.Errorf("APFS verification omitted snapshot %s at %d", snapshot.Name, snapshot.XID)
		}
	}
	for _, failure := range []string{"skipping", "warning:", "error:"} {
		if strings.Contains(strings.ToLower(output), failure) {
			return fmt.Errorf("APFS verification of %s reported %s", volume.VolumeUUID, failure)
		}
	}
	return nil
}

func (v *Verifier) fsckContinuation(ctx context.Context, raw, fs string, expected *schema.Observation, recipe schema.Recipe) error {
	if hasEncryptedVolumes(expected) {
		return v.checkEncryptedVolumes(ctx, raw, nil, expected, recipe)
	}
	return v.fsckRaw(ctx, raw, fs)
}
