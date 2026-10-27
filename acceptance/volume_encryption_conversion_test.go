package acceptance_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func TestVolumeConversionsPreserveNativeHistorySharingAndPeers(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipes := recipesByName(t)
	matrix := map[string]map[string][]string{
		"encrypted-volumes":          {"apfs": {"password-changed", "converted"}, "apfsx": {"password-changed", "converted"}},
		"encrypted-snapshot-history": {"apfs": {"retained-again", "aes128-nested", "aes256-nested", "decrypted"}, "apfsx": {"retained-again", "aes128-nested", "aes256-nested", "decrypted"}},
	}
	for _, before := range storageCases(t, matrix) {
		t.Run(native.CaseKey(caseRef(before)), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			storageImageUnchanged(t, before)
			selected, target, encrypt, err := native.VolumeConversionTarget(caseRef(before))
			if err != nil {
				t.Fatal(err)
			}
			after := encryptedHistoryCase(t, cases, before, target)
			recipe := recipes[before.Recipe]
			options := volumeConversionOptions(t, ctx, before, selected, recipe)
			conversion := apfs.EncryptionConversion{Encrypt: encrypt}
			if encrypt {
				for _, v := range after.Observation.Volumes {
					if volumeName(v) == selected {
						conversion.Password = []byte(recipe.Passwords[v.APFS.Password])
					}
				}
				if conversion.Password == nil {
					t.Fatal("native converted volume lacks credential")
				}
			}
			name := outputName(before, "convert-volume.UDZO.dmg")
			output := produceTwice(t, name, !encrypt && options.ImagePassword == nil, func(path string) error {
				return convertNativeVolumeCLI(t, ctx, fixtureImage(t, before), path, options, conversion)
			})
			checkEncryptedVolumeOutput(t, ctx, output, before, after, recipe, options.ImagePassword, true)
			password := ""
			if options.ImagePassword != nil {
				password = "encrypted-snapshot-history.image"
				registerOutputPassword(t, password, string(options.ImagePassword))
			}
			recordOutput(t, schema.Output{Name: name, File: filepath.Base(output), Operation: "convert-volume", Format: "UDZO", Encrypted: options.ImagePassword != nil, Password: password, Source: caseRef(before), Expect: schema.Expectation{View: target, Volume: selected, Continuation: true}})
		})
	}
}

func volumeConversionOptions(t *testing.T, ctx context.Context, k corpus.Case, selected string, recipe schema.Recipe) imageedit.Options {
	t.Helper()
	options := imageedit.Options{Format: "UDZO", Time: fixedClock}
	if k.Observation.Image.Encryption != nil {
		options.ImagePassword = []byte(recipe.Passwords[k.Observation.Image.Encryption.Password])
	}
	var image *diskimage.Image
	var err error
	if options.ImagePassword == nil {
		image, err = diskimage.Open(fixtureImage(t, k))
	} else {
		image, err = diskimage.OpenWithPassword(ctx, fixtureImage(t, k), options.ImagePassword)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer closeFixture(t, image)
	_, options.Partition = storagePartition(t, image)
	for _, v := range k.Observation.Volumes {
		if v.APFS == nil {
			t.Fatal("conversion source has a non-APFS peer")
		}
		if volumeName(v) == selected {
			options.Volume = v.APFS.VolumeUUID
		}
		if !v.APFS.Encrypted {
			continue
		}
		password, ok := recipe.Passwords[v.APFS.Password]
		if !ok {
			t.Fatal("native source lacks credential", v.APFS.Password)
		}
		if volumeName(v) == selected {
			options.VolumePassword = []byte(password)
		} else {
			options.VolumeCredentials = append(options.VolumeCredentials, apfs.VolumeCredential{VolumeUUID: v.APFS.VolumeUUID, Password: []byte(password)})
		}
	}
	if options.Volume == "" {
		t.Fatal("native selected volume is absent")
	}
	return options
}

func convertNativeVolumeCLI(t *testing.T, ctx context.Context, source, output string, options imageedit.Options, conversion apfs.EncryptionConversion) error {
	t.Helper()
	root := t.TempDir()
	command := "decrypt"
	if conversion.Encrypt {
		command = "encrypt"
	}
	args := []string{command, "--image", source, "--output", output, "--partition", strconv.Itoa(options.Partition), "--volume", options.Volume, "--time", fixedClock.Format("2006-01-02T15:04:05Z07:00")}
	args = append(args, encryptedVolumeCredentialArguments(t, root, options)...)
	if conversion.Encrypt {
		path := filepath.Join(root, "new-password")
		if err := os.WriteFile(path, conversion.Password, 0600); err != nil {
			return err
		}
		args = append(args, "--new-password-file", path)
	}
	log, err := exec.CommandContext(ctx, portableCommandBinary(t), args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("volume conversion CLI: %w: %s", err, log)
	}
	return nil
}
