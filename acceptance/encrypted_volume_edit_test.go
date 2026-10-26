package acceptance_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

func encryptedHistoryCases(t *testing.T, stages ...string) []corpus.Case {
	t.Helper()
	return storageCases(t, map[string]map[string][]string{"encrypted-snapshot-history": {"apfs": stages, "apfsx": stages}})
}

func encryptedVolumeOptions(t *testing.T, ctx context.Context, k corpus.Case, recipe schema.Recipe) imageedit.Options {
	t.Helper()
	var imagePassword []byte
	if k.Observation.Image.Encryption != nil {
		imagePassword = []byte(recipe.Passwords[k.Observation.Image.Encryption.Password])
	}
	options := imageedit.Options{Partition: encryptedEditPartition(t, ctx, k, imagePassword), Format: "UDZO", Time: fixedClock, ImagePassword: imagePassword}
	for _, vol := range k.Observation.Volumes {
		if vol.APFS == nil || !vol.APFS.Encrypted {
			continue
		}
		password, ok := recipe.Passwords[vol.APFS.Password]
		if !ok {
			t.Fatal("unknown native credential", vol.APFS.Password)
		}
		if volumeName(vol) == "EncryptedHistory" {
			options.Volume = vol.APFS.VolumeUUID
			options.VolumePassword = []byte(password)
		} else {
			options.VolumeCredentials = append(options.VolumeCredentials, apfs.VolumeCredential{VolumeUUID: vol.APFS.VolumeUUID, Password: []byte(password)})
		}
	}
	if options.Volume == "" || len(options.VolumeCredentials) != 1 {
		t.Fatal("encrypted history control lacks selected volume and independent peer")
	}
	return options
}

func TestEncryptedVolumeEditsPreserveHistoryAndPeers(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipe := recipesByName(t)["encrypted-snapshot-history"]
	registerOutputPassword(t, "encrypted-snapshot-history.image", recipe.Passwords["image"])
	for _, before := range encryptedHistoryCases(t, "retained", "retained-again", "aes128-nested", "aes256-nested") {
		t.Run(native.CaseKey(caseRef(before)), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			storageImageUnchanged(t, before)
			target := "final"
			if before.Stage == "retained" {
				target = "edited"
			}
			after := encryptedHistoryCase(t, cases, before, target)
			options := encryptedVolumeOptions(t, ctx, before, recipe)
			name := outputName(before, "edit.UDZO.dmg")
			output := produceTwice(t, name, options.ImagePassword == nil, func(path string) error {
				return editEncryptedVolumeCLI(t, ctx, fixtureImage(t, before), path, options, recipe, target)
			})
			checkEncryptedVolumeOutput(t, ctx, output, before, after, recipe, options.ImagePassword, false)
			recordOutput(t, schema.Output{Name: name, File: filepath.Base(output), Operation: "edit", Format: "UDZO", Encrypted: options.ImagePassword != nil, Password: func() string {
				if options.ImagePassword != nil {
					return "encrypted-snapshot-history.image"
				}
				return ""
			}(), Source: caseRef(before), Expect: schema.Expectation{View: target, Volume: "EncryptedHistory", NewIdentities: true, CommandClockNS: fixedClock.UnixNano(), Continuation: true}})
		})
	}
}

func editEncryptedVolumeCLI(t *testing.T, ctx context.Context, source, output string, options imageedit.Options, recipe schema.Recipe, target string) error {
	t.Helper()
	root := t.TempDir()
	args := []string{"edit", "--image", source, "--output", output, "--volume", options.Volume, "--partition", strconv.Itoa(options.Partition), "--time", fixedClock.Format("2006-01-02T15:04:05Z07:00")}
	args = append(args, encryptedVolumeCredentialArguments(t, root, options)...)
	args = append(args, "--")
	writes := 0
	for _, stage := range recipe.Stages {
		if stage.Name != target {
			continue
		}
		for _, step := range stage.Steps {
			if step.FS == nil {
				continue
			}
			write := step.FS
			if write.Op != "write" || !strings.HasPrefix(write.Path, "$MOUNT:EncryptedHistory/") {
				return fmt.Errorf("unsupported encrypted native journey command")
			}
			payload := filepath.Join(root, fmt.Sprintf("payload-%d", writes))
			if err := os.WriteFile(payload, []byte(write.Content), 0644); err != nil {
				return err
			}
			if writes > 0 {
				args = append(args, "--next")
			}
			args = append(args, "cp", "-X", "--from-host", payload, strings.TrimPrefix(write.Path, "$MOUNT:EncryptedHistory"))
			writes++
		}
	}
	if writes == 0 {
		return fmt.Errorf("missing encrypted native journey writes")
	}
	command := exec.CommandContext(ctx, portableCommandBinary(t), args...)
	log, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("encrypted volume CLI edit: %w: %s", err, log)
	}
	for _, credential := range append([]apfs.VolumeCredential{{Password: options.VolumePassword}, {Password: options.ImagePassword}}, options.VolumeCredentials...) {
		if len(credential.Password) > 0 && bytes.Contains(log, credential.Password) {
			return fmt.Errorf("encrypted edit exposed credential bytes")
		}
	}
	return nil
}

func encryptedVolumeCredentialArguments(t *testing.T, root string, options imageedit.Options) []string {
	t.Helper()
	var args []string
	for i, credential := range append([]apfs.VolumeCredential{{Password: options.VolumePassword}, {Password: options.ImagePassword}}, options.VolumeCredentials...) {
		if credential.Password == nil {
			continue
		}
		path := filepath.Join(root, fmt.Sprintf("credential-%d", i))
		if err := os.WriteFile(path, credential.Password, 0600); err != nil {
			t.Fatal(err)
		}
		switch i {
		case 0:
			args = append(args, "--password-file", path)
		case 1:
			args = append(args, "--image-password-file", path)
		default:
			args = append(args, "--volume-password-file", credential.VolumeUUID+"="+path)
		}
	}
	return args
}

func TestEncryptedVolumePasswordsReplaceOnlySelectedUser(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipe := recipesByName(t)["encrypted-snapshot-history"]
	for _, before := range encryptedHistoryCases(t, "final") {
		t.Run(native.CaseKey(caseRef(before)), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			storageImageUnchanged(t, before)
			after := encryptedHistoryCase(t, cases, before, "password-changed")
			options := encryptedVolumeOptions(t, ctx, before, recipe)
			change := apfs.PasswordChange{OldPassword: options.VolumePassword, NewPassword: []byte(recipe.Passwords["replacement"])}
			for _, invalid := range []apfs.PasswordChange{{OldPassword: []byte(recipe.Passwords["wrong"]), NewPassword: change.NewPassword}, {CryptoUser: "00000000-0000-0000-0000-000000000000", OldPassword: change.OldPassword, NewPassword: change.NewPassword}} {
				out := filepath.Join(t.TempDir(), "refused.dmg")
				if _, err := imageedit.ChangeVolumePassword(ctx, fixtureImage(t, before), out, options, invalid); err == nil {
					t.Fatal("invalid password transition succeeded")
				}
				if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("invalid password transition published output", err)
				}
			}
			name := outputName(before, "password-changed.UDZO.dmg")
			output := produceTwice(t, name, false, func(path string) error {
				// Exercise the public library and the ordinary CLI against the same native
				// password-only reference. Both preserve the same original KEK and VEK.
				report, err := imageedit.ChangeVolumePassword(ctx, fixtureImage(t, before), path, options, change)
				if err == nil && !strings.EqualFold(report.CryptoUser, options.Volume) {
					return fmt.Errorf("password change lost selected crypto-user identity")
				}
				return err
			})
			cliOutput := filepath.Join(t.TempDir(), "password-changed.dmg")
			root := t.TempDir()
			newPassword := filepath.Join(root, "new-password")
			if err := os.WriteFile(newPassword, change.NewPassword, 0600); err != nil {
				t.Fatal(err)
			}
			args := []string{"passwd", "--image", fixtureImage(t, before), "--output", cliOutput, "--volume", options.Volume, "--crypto-user", options.Volume, "--partition", strconv.Itoa(options.Partition), "--time", fixedClock.Format("2006-01-02T15:04:05Z07:00"), "--new-password-file", newPassword}
			args = append(args, encryptedVolumeCredentialArguments(t, root, options)...)
			if log, err := exec.CommandContext(ctx, portableCommandBinary(t), args...).CombinedOutput(); err != nil {
				t.Fatalf("password CLI: %v: %s", err, log)
			}
			checkEncryptedVolumeOutput(t, ctx, cliOutput, before, after, recipe, nil, true)
			checkEncryptedVolumeOutput(t, ctx, output, before, after, recipe, nil, true)
			recordOutput(t, schema.Output{Name: name, File: filepath.Base(output), Operation: "change-password", Format: "UDZO", Source: caseRef(before), Expect: schema.Expectation{View: after.Stage, Volume: "EncryptedHistory", Continuation: true}})
		})
	}
}

func checkEncryptedVolumeOutput(t *testing.T, ctx context.Context, path string, before, after corpus.Case, recipe schema.Recipe, imagePassword []byte, passwordChanged bool) {
	t.Helper()
	image, err := diskimage.OpenWithPassword(ctx, path, imagePassword)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture(t, image)
	report, err := inspect.Image(ctx, image)
	if err != nil {
		t.Fatal(err)
	}
	for _, volume := range after.Observation.Volumes {
		reader, close := openVolume(t, ctx, report, volume, volumeName(volume), recipe, image)
		if close != nil {
			defer close()
		}
		for _, want := range after.Observation.Views {
			if want.Volume != volume.Index {
				continue
			}
			selected := reader
			if want.Snapshot != "" {
				snapshotReader, ok := reader.(*apfs.Volume)
				if !ok {
					t.Fatal("encrypted reader lacks retained history")
				}
				snapshot, err := snapshotReader.OpenSnapshotName(ctx, want.Snapshot)
				if err != nil {
					t.Fatal(err)
				}
				selected = snapshot
			}
			existing := map[string]bool{}
			for _, view := range before.Observation.Views {
				if view.Volume == volume.Index && view.Snapshot == want.Snapshot {
					for _, entry := range view.Entries {
						existing[entry.Path] = true
					}
				}
			}
			if volumeName(volume) == "EncryptedHistory" && want.Snapshot == "" && !passwordChanged {
				var steps []schema.Step
				for _, stage := range recipe.Stages {
					if stage.Name == after.Stage {
						for _, step := range stage.Steps {
							if step.FS != nil {
								command := *step.FS
								command.Path = strings.Replace(command.Path, "$MOUNT:EncryptedHistory/", "$MOUNT/", 1)
								steps = append(steps, schema.Step{FS: &command})
							}
						}
					}
				}
				var source schema.View
				for _, view := range before.Observation.Views {
					if view.Volume == volume.Index && view.Snapshot == "" {
						source = view
					}
				}
				want, err = native.ProjectEditedViewClocks(source, want, steps, before.Profile, fixedClock.UnixNano())
				if err != nil {
					t.Fatal(err)
				}
			}
			compareViewWith(t, ctx, filepath.Base(path), selected, want, compareOptions{ignoreIDFor: func(path string) bool { return !existing[path] }})
		}
	}
}

func encryptedHistoryCase(t *testing.T, cases []corpus.Case, before corpus.Case, stage string) corpus.Case {
	t.Helper()
	key := stageKey(before.Producer, before.Recipe, before.Profile, stage)
	result, ok := indexCases(cases)[key]
	if !ok {
		t.Fatal("missing encrypted native reference", key)
	}
	return result
}

func TestEncryptedEditsDiscardIncompleteTransactions(t *testing.T) {
	recipe := recipesByName(t)["encrypted-snapshot-history"]
	for _, before := range encryptedHistoryCases(t, "retained") {
		t.Run(native.CaseKey(caseRef(before)), func(t *testing.T) {
			t.Parallel()
			storageImageUnchanged(t, before)
			ctx := context.Background()
			options := encryptedVolumeOptions(t, ctx, before, recipe)
			root := t.TempDir()
			output := filepath.Join(root, "incomplete.dmg")
			// Authentication and allocation succeed, then a real replacement stream
			// fails after its first encrypted data write in the private transaction.
			_, err := imageedit.Apply(ctx, fixtureImage(t, before), output, options, []imageedit.Change{{Path: "/Fixture/clone", Data: cloneFailureInput{size: 1 << 20, readError: true}}})
			if !errors.Is(err, io.ErrUnexpectedEOF) {
				t.Fatal("wrong encrypted stream failure", err)
			}
			if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
				t.Fatal("incomplete encrypted edit left published output or private scratch", entries, err)
			}
		})
	}
}
