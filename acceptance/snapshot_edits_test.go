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
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func snapshotEditingCases(t *testing.T) []corpus.Case {
	t.Helper()
	return storageCases(t, map[string]map[string][]string{"snapshot-history": {"apfs": {"live"}, "apfsx": {"live"}}})
}

// Live streams are replaced and restored repeatedly across real checkpoints.
// The final live contents and every retained historical inode/fork/attribute
// remain bound to Apple's original observations, never to a Go-produced image.
func TestLiveEditsPreserveRetainedSnapshotHistories(t *testing.T) {
	recipes := recipesByName(t)
	for _, k := range snapshotEditingCases(t) {
		t.Run(native.CaseKey(caseRef(k)), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			storageImageUnchanged(t, k)
			image, reader, closeSource := openSingleVolume(t, ctx, k, recipes[k.Recipe])
			defer closeSource()
			partition, index := storagePartition(t, image)
			if err := apfs.ValidateMutation(ctx, partition); err != nil {
				t.Fatal("retained ordinary snapshots were refused", err)
			}
			data := map[string][]byte{}
			for _, path := range []string{"Fixture/hard-link", "Fixture/clone.bin"} {
				id, err := filesystem.LookupExact(ctx, reader, path)
				if err != nil {
					t.Fatal(err)
				}
				value, err := reader.OpenData(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				data[path] = snapshotEditPayload(t, value)
			}
			id, err := filesystem.LookupExact(ctx, reader, "Fixture/example.txt")
			if err != nil {
				t.Fatal(err)
			}
			for _, attribute := range []string{filesystem.ResourceFork, "org.go-apfs.binary"} {
				value, err := reader.OpenAttribute(ctx, id, attribute)
				if err != nil {
					t.Fatal(err)
				}
				data[attribute] = snapshotEditPayload(t, value)
			}
			name := outputName(k, "snapshot-edit.UDZO.dmg")
			out := produceTwice(t, name, true, func(destination string) error {
				_, err := imageedit.Edit(ctx, fixtureImage(t, k), destination, imageedit.Options{Partition: index, Format: "UDZO", Time: fixedClock}, func(editor *imageedit.Editor) error {
					var previous uint64
					for round := 0; round < 4; round++ {
						private := bytes.Repeat([]byte(fmt.Sprintf("private live streams %d\n", round)), 4097)
						changes := []imageedit.Change{
							{Path: "/Fixture/hard-link", Data: bytes.NewReader(private)},
							{Path: "/Fixture/clone.bin", Data: bytes.NewReader(private)},
							{Path: "/Fixture/example.txt", ResourceFork: true, Data: bytes.NewReader(private)},
							{Operation: "xattr", Path: "/Fixture/example.txt", Attribute: "org.go-apfs.binary", Data: bytes.NewReader(private)},
							{Path: "/Fixture/allocation-probe", Data: bytes.NewReader(bytes.Repeat([]byte{byte(round + 1)}, 4<<20))},
						}
						report, err := editor.Apply(changes)
						if err != nil {
							return err
						}
						if report.Transaction <= previous {
							return fmt.Errorf("live snapshot edit did not commit a newer checkpoint")
						}
						previous = report.Transaction
						report, err = editor.Apply([]imageedit.Change{
							{Path: "/Fixture/hard-link", Data: bytes.NewReader(data["Fixture/hard-link"])},
							{Path: "/Fixture/clone.bin", Data: bytes.NewReader(data["Fixture/clone.bin"])},
							{Path: "/Fixture/example.txt", ResourceFork: true, Data: bytes.NewReader(data[filesystem.ResourceFork])},
							{Operation: "xattr", Path: "/Fixture/example.txt", Attribute: "org.go-apfs.binary", Data: bytes.NewReader(data["org.go-apfs.binary"])},
							{Operation: "rm", Path: "/Fixture/allocation-probe"},
						})
						if err != nil {
							return err
						}
						if report.Transaction <= previous {
							return fmt.Errorf("snapshot stream restoration reused a checkpoint")
						}
						previous = report.Transaction
					}
					return nil
				})
				return err
			})
			checkSnapshotEditedImage(t, ctx, out, k)
			recordOutput(t, schema.Output{Name: name, File: filepath.Base(out), Operation: "edit", Format: "UDZO", Source: caseRef(k), Expect: schema.Expectation{CommandClockNS: fixedClock.UnixNano(), Continuation: true}})
		})
	}
}

func snapshotEditPayload(t *testing.T, value filesystem.Value) []byte {
	t.Helper()
	defer func() { closeFixture(t, value) }()
	if value.Size() < 0 || value.Size() > 4<<20 {
		t.Fatal("snapshot editing payload exceeds its bounded fixture scope")
	}
	data, err := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func checkSnapshotEditedImage(t *testing.T, ctx context.Context, filename string, k corpus.Case) {
	t.Helper()
	image, err := diskimage.Open(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { closeFixture(t, image) }()
	partition, _ := storagePartition(t, image)
	container, err := apfs.Open(partition)
	if err != nil || len(container.Volumes) != 1 {
		t.Fatal("snapshot edit lost its volume", err)
	}
	volume := &container.Volumes[0]
	compareSnapshots(t, ctx, "edited", volume, k.Observation.Volumes[0].APFS.Snapshots)
	if _, err := apfs.InspectStorage(ctx, partition); err != nil {
		t.Fatal("edited history has invalid ownership", err)
	}
	for _, view := range k.Observation.Views {
		var reader filesystem.Reader = volume
		if view.Snapshot != "" {
			reader, err = volume.OpenSnapshotName(ctx, view.Snapshot)
		} else {
			view, err = native.SnapshotEditClocks(view, k.Profile, fixedClock.UnixNano())
		}
		if err != nil {
			t.Fatal(err)
		}
		compareView(t, ctx, "edited/"+view.Snapshot, reader, view)
	}
}

func TestSnapshotEditFailuresNeverPublishOrAlterSource(t *testing.T) {
	if os.Getenv("APFS_SNAPSHOT_EDIT_INTERRUPT_CHILD") == "1" {
		partition, err := strconv.Atoi(os.Getenv("APFS_SNAPSHOT_EDIT_PARTITION"))
		if err != nil {
			t.Fatal(err)
		}
		_, err = imageedit.Apply(context.Background(), os.Getenv("APFS_SNAPSHOT_EDIT_SOURCE"), os.Getenv("APFS_SNAPSHOT_EDIT_DESTINATION"), imageedit.Options{Partition: partition, Time: fixedClock}, []imageedit.Change{{Path: "/Fixture/clone.bin", Data: cloneFailureInput{size: 1 << 20, exit: true}}})
		fmt.Fprintln(os.Stderr, "snapshot interruption did not reach its input reader:", err)
		os.Exit(99)
	}
	for _, k := range snapshotEditingCases(t) {
		t.Run(native.CaseKey(caseRef(k)), func(t *testing.T) {
			storageImageUnchanged(t, k)
			source := fixtureImage(t, k)
			image, err := diskimage.Open(source)
			if err != nil {
				t.Fatal(err)
			}
			_, partition := storagePartition(t, image)
			closeFixture(t, image)
			for _, failure := range []string{"disk-full", "read-interrupted", "process-interrupted", "existing-output"} {
				t.Run(failure, func(t *testing.T) {
					root := t.TempDir()
					destination := filepath.Join(root, "edited.dmg")
					sourceDigest := packingFileDigest(t, source)
					if failure == "process-interrupted" {
						command := exec.Command(os.Args[0], "-test.run=^TestSnapshotEditFailuresNeverPublishOrAlterSource$")
						command.Env = append(os.Environ(), "APFS_SNAPSHOT_EDIT_INTERRUPT_CHILD=1", "APFS_SNAPSHOT_EDIT_SOURCE="+source, "APFS_SNAPSHOT_EDIT_DESTINATION="+destination, "APFS_SNAPSHOT_EDIT_PARTITION="+strconv.Itoa(partition), "TMPDIR="+root, "TMP="+root, "TEMP="+root)
						var exit *exec.ExitError
						if err := command.Run(); !errors.As(err, &exit) || exit.ExitCode() != 17 {
							t.Fatal("child did not stop during retained-history editing", err)
						}
					} else {
						want := filesystem.ErrLimit
						if failure == "read-interrupted" {
							want = io.ErrUnexpectedEOF
						}
						if failure == "existing-output" {
							want = fs.ErrExist
							if err := os.WriteFile(destination, []byte("retain existing output"), 0o600); err != nil {
								t.Fatal(err)
							}
						}
						_, err := imageedit.Apply(context.Background(), source, destination, imageedit.Options{Partition: partition, Time: fixedClock}, []imageedit.Change{{Path: "/Fixture/clone.bin", Data: cloneFailureInput{size: k.Observation.Image.DiskBytes, readError: failure == "read-interrupted"}}})
						if !errors.Is(err, want) {
							t.Fatal("wrong retained-history failure", err, want)
						}
					}
					if failure == "existing-output" {
						if data, err := os.ReadFile(destination); err != nil || string(data) != "retain existing output" {
							t.Fatal("failed edit changed existing output", err)
						}
					} else if _, err := os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
						t.Fatal("failed retained-history edit published output", err)
					}
					if packingFileDigest(t, source) != sourceDigest {
						t.Fatal("failed retained-history edit changed source")
					}
				})
			}
		})
	}
}
