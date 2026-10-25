package acceptance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func TestSnapshotDeletionPreservesLiveAndRemainingHistories(t *testing.T) {
	for _, k := range snapshotEditingCases(t) {
		t.Run(native.CaseKey(caseRef(k)), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			storageImageUnchanged(t, k)
			source := fixtureImage(t, k)
			digest := packingFileDigest(t, source)
			image, err := diskimage.Open(source)
			if err != nil {
				t.Fatal(err)
			}
			_, partition := storagePartition(t, image)
			closeFixture(t, image)
			orders, err := native.SnapshotDeletionOrders(k.Observation)
			if err != nil {
				t.Fatal(err)
			}
			for index, deleted := range orders {
				suffix := []string{"oldest", "newest", "all-oldest-first", "all-newest-first"}[index]
				t.Run(suffix, func(t *testing.T) {
					reference, err := native.SnapshotDeletionReference(k.Observation, deleted)
					if err != nil {
						t.Fatal(err)
					}
					name := outputName(k, "snapshot-delete."+suffix+".UDZO.dmg")
					out := produceTwice(t, name, true, func(destination string) error {
						options := imageedit.Options{Partition: partition, Format: "UDZO", Time: fixedClock}
						if index == 0 {
							args := []string{"snapshot", "delete", "--json", "--image", source, "--output", destination, "--partition", strconv.Itoa(partition), "--snapshot-name", deleted[0].Name, "--time", fixedClock.Format(time.RFC3339)}
							data, err := exec.CommandContext(ctx, portableCommandBinary(t), args...).CombinedOutput()
							if err != nil {
								return fmt.Errorf("snapshot delete CLI: %w: %s", err, data)
							}
							var r struct {
								Schema int `json:"schema"`
								imageedit.Report
							}
							if err := json.Unmarshal(data, &r); err != nil {
								return err
							}
							if r.Schema != 1 || r.VolumeID == "" || r.Transaction == 0 {
								return fmt.Errorf("snapshot delete report incomplete")
							}
							return nil
						}
						if index == 1 {
							_, err := imageedit.DeleteSnapshot(ctx, source, destination, options, apfs.SnapshotSelector{XID: apfs.XID(deleted[0].XID)})
							return err
						}
						_, err := imageedit.Edit(ctx, source, destination, options, func(editor *imageedit.Editor) error {
							var previous uint64
							for n, d := range deleted {
								selector := apfs.SnapshotSelector{Name: d.Name}
								if n == 1 {
									selector = apfs.SnapshotSelector{XID: apfs.XID(d.XID)}
								}
								report, err := editor.DeleteSnapshot(selector)
								if err != nil {
									return err
								}
								if report.Transaction <= previous {
									return fmt.Errorf("snapshot deletion reused a checkpoint")
								}
								previous = report.Transaction
							}
							return nil
						})
						return err
					})
					checkSnapshotDeletion(t, ctx, out, reference, deleted)
					recordOutput(t, schema.Output{Name: name, File: filepath.Base(out), Operation: "delete-snapshot", Format: "UDZO", Source: caseRef(k), Expect: schema.Expectation{DeletedSnapshots: deleted, Continuation: true}})
				})
			}
			if packingFileDigest(t, source) != digest {
				t.Fatal("snapshot deletion changed original evidence")
			}
		})
	}
}

func checkSnapshotDeletion(t *testing.T, ctx context.Context, output string, reference *schema.Observation, deleted []schema.SnapshotIdentity) {
	t.Helper()
	image, err := diskimage.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { closeFixture(t, image) }()
	partition, _ := storagePartition(t, image)
	container, err := apfs.Open(partition)
	if err != nil || len(container.Volumes) != 1 {
		t.Fatal("deleted image volume", err)
	}
	volume := &container.Volumes[0]
	// Zero native observation clocks mean unavailable, not timestamp zero.
	// Reuse the established inventory comparison without changing originals.
	compareSnapshots(t, ctx, "snapshot-delete", volume, append([]schema.Snapshot(nil), reference.Volumes[0].APFS.Snapshots...))
	for _, d := range deleted {
		if _, err := volume.OpenSnapshotName(ctx, d.Name); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("deleted name remains selectable", d, err)
		}
		if _, err := volume.OpenSnapshot(ctx, apfs.XID(d.XID)); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("deleted xid remains selectable", d, err)
		}
	}
	if _, err := apfs.InspectStorage(ctx, partition); err != nil {
		t.Fatal("deleted image ownership", err)
	}
	for _, view := range reference.Views {
		var reader filesystem.Reader = volume
		if view.Snapshot != "" {
			reader, err = volume.OpenSnapshotName(ctx, view.Snapshot)
		}
		if err != nil {
			t.Fatal(err)
		}
		compareView(t, ctx, "snapshot-delete/"+view.Snapshot, reader, view)
	}
}

func TestSnapshotDeletionFailuresDiscardSuccessfulDeletion(t *testing.T) {
	for _, k := range snapshotEditingCases(t) {
		t.Run(native.CaseKey(caseRef(k)), func(t *testing.T) {
			source := fixtureImage(t, k)
			digest := packingFileDigest(t, source)
			image, err := diskimage.Open(source)
			if err != nil {
				t.Fatal(err)
			}
			_, partition := storagePartition(t, image)
			closeFixture(t, image)
			for _, failure := range []string{"callback-interrupted", "disk-full"} {
				t.Run(failure, func(t *testing.T) {
					destination := filepath.Join(t.TempDir(), "unpublished.dmg")
					want := io.ErrClosedPipe
					if failure == "disk-full" {
						want = filesystem.ErrLimit
					}
					_, err := imageedit.Edit(context.Background(), source, destination, imageedit.Options{Partition: partition, Time: fixedClock}, func(editor *imageedit.Editor) error {
						if _, err := editor.DeleteSnapshot(apfs.SnapshotSelector{Name: k.Observation.Volumes[0].APFS.Snapshots[0].Name}); err != nil {
							return err
						}
						if failure == "callback-interrupted" {
							return io.ErrClosedPipe
						}
						_, err := editor.Apply([]imageedit.Change{{Path: "/Fixture/clone.bin", Data: cloneFailureInput{size: k.Observation.Image.DiskBytes}}})
						return err
					})
					if !errors.Is(err, want) {
						t.Fatal("wrong failure after successful deletion", err, want)
					}
					if _, err := os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
						t.Fatal("failed deletion transaction published", err)
					}
					if packingFileDigest(t, source) != digest {
						t.Fatal("failed deletion transaction changed original")
					}
				})
			}
		})
	}
}
