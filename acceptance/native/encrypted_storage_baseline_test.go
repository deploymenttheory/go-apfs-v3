//go:build native && darwin

package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func TestEncryptedAPFSStorageBaseline(t *testing.T) {
	v := newVerifier(t)
	ctx := context.Background()
	transcript := &fixture.Transcript{}
	v.setTranscript(transcript)
	type result struct {
		Name  string `json:"name"`
		Error string `json:"error,omitempty"`
	}
	results := []result{}
	record := func(name string, err error) {
		row := result{Name: name}
		if err != nil {
			row.Error = err.Error()
		}
		results = append(results, row)
		t.Logf("%s: %v", name, err)
	}
	defer func() {
		data, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(filepath.Join(v.Work, "result.json"), data, 0644); err != nil {
			t.Error(err)
		}
		data, _ = json.MarshalIndent(transcript.Commands, "", "  ")
		if err := os.WriteFile(filepath.Join(v.Work, "commands.json"), data, 0644); err != nil {
			t.Error(err)
		}
	}()
	for _, recipeName := range []string{"encrypted-snapshot-history", "encrypted-volumes"} {
		stage := "retained"
		selected := "EncryptedHistory"
		if recipeName == "encrypted-volumes" {
			stage = "clone-shared"
			selected = "Primary"
		}
		ref := schema.CaseRef{Producer: v.Major, Recipe: recipeName, Profile: "apfs", Stage: stage}
		k, ok := v.Cases[CaseKey(ref)]
		if !ok {
			t.Fatal("missing original case", ref)
		}
		lease, err := v.Corpus.AcquireImage(ctx, k)
		if err != nil {
			t.Fatal(err)
		}
		recipe := v.Recipes[recipeName]
		input := lease.Path()
		record(recipeName+" native input forced fsck", v.checkEncryptedVolumes(ctx, input, nil, k.Observation, recipe))
		v.setTranscript(transcript)
		att, err := v.Disk.Attach(ctx, input, fixture.AttachOptions{ReadOnly: true})
		if err == nil {
			err = v.unlockContinuationVolumes(ctx, att, k.Observation, recipe)
		}
		if err == nil {
			for _, volume := range att.Volumes {
				if !volume.Locked {
					command := fixture.Command{Label: "fsck-volume", Argv: []string{"/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs", "-n", "-F", volume.RDev}, Expected: "0"}
					record(recipeName+" native volume "+volume.Name+" forced fsck", transcript.Record(command, v.C.Run(ctx, command)))
				}
			}
			if att.Container != "" {
				command := fixture.Command{Label: "fsck-container", Argv: []string{"/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs", "-n", "-F", "/dev/r" + att.Container}, Expected: "0"}
				record(recipeName+" synthesized container forced fsck", transcript.Record(command, v.C.Run(ctx, command)))
			}
			volume := att.Volume(selected)
			if volume == nil {
				err = fmt.Errorf("missing selected volume")
			} else {
				err = v.Disk.Mount(ctx, volume, "owners,noatime", filepath.Join(v.Work, recipeName+"-mount"), false)
				if err == nil {
					command := fixture.Command{Label: "verify-volume", Argv: []string{"diskutil", "verifyVolume", volume.Dev}, Expected: "0"}
					record(recipeName+" native diskutil verifyVolume", transcript.Record(command, v.C.Run(ctx, command)))
					command = fixture.Command{Label: "fsck-mounted-volume", Argv: []string{"/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs", "-n", "-l", "-F", volume.RDev}, Expected: "0"}
					record(recipeName+" mounted volume forced fsck", transcript.Record(command, v.C.Run(ctx, command)))
					command = fixture.Command{Label: "fsck-mounted", Argv: []string{"/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs", "-n", "-l", "-F", att.RDev}, Expected: "0"}
					err = transcript.Record(command, v.C.Run(ctx, command))
				}
			}
		}
		if att != nil {
			err = errors.Join(err, v.Disk.Detach(ctx, att))
		}
		record(recipeName+" native input mounted forced fsck", err)
		options := imageedit.Options{Format: "UDZO", Time: time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)}
		if recipeName == "encrypted-snapshot-history" {
			options.Partition = 1
		}
		for _, volume := range k.Observation.Volumes {
			if volume.APFS == nil || !volume.APFS.Encrypted {
				continue
			}
			password := []byte(recipe.Passwords[volume.APFS.Password])
			if volumeName(volume) == selected {
				options.Volume = volume.APFS.VolumeUUID
				options.VolumePassword = password
			} else {
				options.VolumeCredentials = append(options.VolumeCredentials, apfs.VolumeCredential{VolumeUUID: volume.APFS.VolumeUUID, Password: password})
			}
		}
		output := filepath.Join(v.Work, recipeName+"-password.dmg")
		change := apfs.PasswordChange{OldPassword: options.VolumePassword, NewPassword: []byte("public-probe-replacement")}
		_, err = imageedit.ChangeVolumePassword(ctx, input, output, options, change)
		record(recipeName+" Go password change", err)
		if err == nil {
			expected := *k.Observation
			expected.Volumes = append([]schema.Volume(nil), expected.Volumes...)
			for i := range expected.Volumes {
				if volumeName(expected.Volumes[i]) != selected {
					continue
				}
				volume := *expected.Volumes[i].APFS
				volume.Password = "probe"
				volume.Rejected = []string{"primary"}
				expected.Volumes[i].APFS = &volume
			}
			recipe.Passwords["probe"] = "public-probe-replacement"
			record(recipeName+" Go password output forced fsck", v.checkEncryptedVolumes(ctx, output, nil, &expected, recipe))
			v.setTranscript(transcript)
			outputAtt, openErr := v.Disk.Attach(ctx, output, fixture.AttachOptions{ReadOnly: true})
			if openErr == nil {
				openErr = v.unlockContinuationVolumes(ctx, outputAtt, &expected, recipe)
			}
			if openErr == nil {
				for _, volume := range outputAtt.Volumes {
					command := fixture.Command{Label: "fsck-output-volume", Argv: []string{"/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs", "-n", "-F", volume.RDev}, Expected: "0"}
					record(recipeName+" output volume "+volume.Name+" forced fsck", transcript.Record(command, v.C.Run(ctx, command)))
				}
			}
			if outputAtt != nil {
				openErr = errors.Join(openErr, v.Disk.Detach(ctx, outputAtt))
			}
			record(recipeName+" output volume attachment", openErr)

			spec := schema.ObserveSpec{Snapshots: true}
			spec.Unlock, spec.Rejected = volumeCredentials(&expected)
			_, err = v.observeImage(ctx, recipeName+"-password-output", output, "UDZO", nil, spec, recipe)
			record(recipeName+" Go password output native mount/read", err)
		}
		record(recipeName+" source lease close", lease.Release(nil))
	}
}
