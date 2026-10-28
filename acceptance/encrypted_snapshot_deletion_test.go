package acceptance_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func TestEncryptedSnapshotDeletionPreservesSurvivingHistorySharingAndPeers(t *testing.T) {
	recipe := recipesByName(t)["encrypted-snapshot-history"]
	cases := encryptedHistoryCases(
		t, "password-changed", "decrypted", "converted", "aes128-nested", "aes256-nested",
	)
	for _, before := range cases {
		t.Run(native.CaseKey(caseRef(before)), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			storageImageUnchanged(t, before)
			options := volumeConversionOptions(t, ctx, before, "EncryptedHistory", recipe)
			orders, err := native.EncryptedSnapshotDeletionOrders(caseRef(before), before.Observation)
			if err != nil {
				t.Fatal(err)
			}
			for index, deleted := range orders {
				suffix := "oldest"
				for _, volume := range before.Observation.Volumes {
					if volumeName(volume) == "EncryptedHistory" {
						snapshots := volume.APFS.Snapshots
						if deleted[0].XID != min(snapshots[0].XID, snapshots[1].XID) {
							suffix = "newest"
						}
					}
				}
				if len(deleted) == 2 {
					suffix = "all-" + suffix + "-first"
				}
				t.Run(suffix, func(t *testing.T) {
					reference, err := native.VolumeSnapshotDeletionReference(before.Observation, "EncryptedHistory", deleted)
					if err != nil {
						t.Fatal(err)
					}
					name := outputName(before, "snapshot-delete."+suffix+".UDZO.dmg")
					output := produceTwice(t, name, options.ImagePassword == nil, func(destination string) error {
						if index == 0 && len(deleted) == 1 {
							args := []string{"snapshot", "delete", "--json", "--image", fixtureImage(t, before), "--output", destination,
								"--partition", strconv.Itoa(options.Partition), "--volume", options.Volume,
								"--snapshot-name", deleted[0].Name, "--time", fixedClock.Format("2006-01-02T15:04:05Z07:00")}
							args = append(args, encryptedVolumeCredentialArguments(t, t.TempDir(), options)...)
							log, err := exec.CommandContext(ctx, portableCommandBinary(t), args...).CombinedOutput()
							if err != nil {
								return fmt.Errorf("encrypted snapshot deletion CLI: %w: %s", err, log)
							}
							return nil
						}
						_, err := imageedit.Edit(ctx, fixtureImage(t, before), destination, options, func(editor *imageedit.Editor) error {
							for _, snapshot := range deleted {
								if _, err := editor.DeleteSnapshot(apfs.SnapshotSelector{XID: apfs.XID(snapshot.XID)}); err != nil {
									return err
								}
							}
							return nil
						})
						return err
					})
					after := before
					after.Observation = reference
					checkEncryptedVolumeOutput(
						t, ctx, output, before, after, recipe, options.ImagePassword, true,
					)
					password := ""
					if options.ImagePassword != nil {
						password = "encrypted-snapshot-history.image"
						registerOutputPassword(t, password, string(options.ImagePassword))
					}
					recordOutput(t, schema.Output{Name: name, File: filepath.Base(output), Operation: "delete-snapshot",
						Format: "UDZO", Encrypted: options.ImagePassword != nil, Password: password, Source: caseRef(before),
						Expect: schema.Expectation{Volume: "EncryptedHistory", DeletedSnapshots: deleted, Continuation: true}})
				})
			}
		})
	}
}

func TestEncryptedSnapshotDeletionFailuresNeverPublishOrChangeSource(t *testing.T) {
	recipe := recipesByName(t)["encrypted-snapshot-history"]
	for _, before := range encryptedHistoryCases(t, "password-changed") {
		t.Run(native.CaseKey(caseRef(before)), func(t *testing.T) {
			ctx := context.Background()
			source := fixtureImage(t, before)
			digest := packingFileDigest(t, source)
			for _, failure := range []string{"after-deletion", "wrong-password", "missing-peer"} {
				t.Run(failure, func(t *testing.T) {
					options := volumeConversionOptions(t, ctx, before, "EncryptedHistory", recipe)
					want := io.ErrClosedPipe
					if failure == "wrong-password" {
						options.VolumePassword = []byte(recipe.Passwords["wrong"])
						want = filesystem.ErrAuthentication
					}
					if failure == "missing-peer" {
						options.VolumeCredentials = nil
						want = filesystem.ErrAuthentication
					}
					orders, err := native.EncryptedSnapshotDeletionOrders(caseRef(before), before.Observation)
					if err != nil {
						t.Fatal(err)
					}
					output := filepath.Join(t.TempDir(), "unpublished.dmg")
					called := false
					_, err = imageedit.Edit(ctx, source, output, options, func(editor *imageedit.Editor) error {
						called = true
						if _, err := editor.DeleteSnapshot(apfs.SnapshotSelector{XID: apfs.XID(orders[0][0].XID)}); err != nil {
							return err
						}
						return io.ErrClosedPipe
					})
					if !errors.Is(err, want) || called != (failure == "after-deletion") {
						t.Fatal("deletion lost failure or ran before authentication", err, called)
					}
					if _, err := os.Lstat(output); !errors.Is(err, fs.ErrNotExist) || packingFileDigest(t, source) != digest {
						t.Fatal("failed encrypted deletion changed source or published output", err)
					}
				})
			}
		})
	}
}
