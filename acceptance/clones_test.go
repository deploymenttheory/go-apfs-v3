package acceptance_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

var cloneEditingStages = []string{"shared", "data-replaced", "data-truncated", "fork-replaced", "attribute-replaced", "metadata-changed", "compressed-replaced", "sparse-replaced", "source-removed", "clones-removed", "final-owner-removed", "allocation-reused"}

func cloneEditingCases(t *testing.T) []corpus.Case {
	t.Helper()
	return storageCases(t, map[string]map[string][]string{"apfs-clones": {"apfs": cloneEditingStages, "apfsx": cloneEditingStages}})
}

// Every producer/profile/stage is mandatory. The writer's admission is checked
// against original plaintext native controls, and physical reads are compared
// to kernel F_LOG2PHYS_EXT rather than equal-content guesses or Go metadata.
func TestAPFSCloneControlsRetainNativeSharingAndAdmitMutation(t *testing.T) {
	recipes := recipesByName(t)
	for _, k := range cloneEditingCases(t) {
		t.Run(native.CaseKey(caseRef(k)), func(t *testing.T) {
			t.Parallel()
			storageImageUnchanged(t, k)
			ctx := context.Background()
			img := openImage(t, ctx, k, recipes[k.Recipe])
			defer func() { _ = img.Close() }()
			part, _ := storagePartition(t, img)
			trace := &physicalReads{Source: part}
			container, err := apfs.Open(trace)
			if err != nil || len(container.Volumes) != 1 || container.Volumes[0].Encrypted || container.Volumes[0].Snapshots != 0 {
				t.Fatal("clone writer control is not a plaintext live-only volume", err)
			}
			if err := apfs.ValidateMutation(ctx, trace); err != nil {
				t.Fatal("native clone editing profile was refused", err)
			}
			if len(k.Observation.Views) != 1 || k.Observation.Views[0].Snapshot != "" {
				t.Fatal("native clone control has extra/missing historical views")
			}
			view := k.Observation.Views[0]
			if err := native.CheckCloneEditingControl(view, k.Stage); err != nil {
				t.Fatal(err)
			}
			volume := &container.Volumes[0]
			for _, entry := range view.Entries {
				if entry.Kind != "file" || entry.Extents == nil || entry.Compression != nil || len(entry.Sparse) != 0 {
					continue
				}
				id, err := filesystem.LookupExact(ctx, volume, entry.Path)
				if err != nil || id != entry.ID {
					t.Fatal("clone inode identity differs", entry.Path, id, entry.ID, err)
				}
				for _, fork := range []string{"data", "resource"} {
					var value filesystem.Value
					var sum string
					var runs [][3]int64
					if fork == "data" {
						value, err = volume.OpenRawData(ctx, id)
						sum, runs = entry.SHA256, entry.Extents.Data
					} else {
						runs = entry.Extents.Resource
						if len(runs) == 0 {
							continue
						}
						value, err = volume.OpenAttribute(ctx, id, filesystem.ResourceFork)
						for _, attr := range entry.Xattrs {
							if attr.Name == filesystem.ResourceFork {
								sum = attr.SHA256
							}
						}
					}
					if err != nil {
						t.Fatal(entry.Path, fork, err)
					}
					if value.Size() != 0 {
						checkClonePhysicalReads(t, trace, entry.Path+"/"+fork, value, runs, sum)
					}
					if err := value.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}

func checkClonePhysicalReads(t *testing.T, trace *physicalReads, label string, value filesystem.Value, runs [][3]int64, sum string) {
	t.Helper()
	if !schema.ValidDigest(sum) || len(runs) == 0 {
		t.Fatal("plaintext clone fork lacks native physical/digest evidence", label)
	}
	hash := sha256.New()
	var end int64
	for _, run := range runs {
		if run[0] != end || run[1] < 0 || run[2] <= 0 || run[2] > 1<<20 || run[2] > value.Size()-end {
			t.Fatal("invalid plaintext clone native run", label, run)
		}
		data := make([]byte, run[2])
		trace.begin()
		err := block.ReadFull(value, data, run[0])
		reads := trace.end()
		if err != nil {
			t.Fatal(label, err)
		}
		// Plaintext values read exact logical bytes. The encrypted-control
		// helper's 512-byte XTS expansion does not apply to these sources.
		if err := native.ComparePhysicalRead(reads, run, 1); err != nil {
			t.Fatal(label, err)
		}
		_, _ = hash.Write(data)
		end += run[2]
	}
	if end != value.Size() || hex.EncodeToString(hash.Sum(nil)) != sum {
		t.Fatal("plaintext clone fork differs from native bytes", label)
	}
}

type clonePhysicalValue struct{ block.Source }

func (clonePhysicalValue) Close() error { return nil }

func TestPlaintextClonePhysicalReadsKeepUnalignedTailsExact(t *testing.T) {
	data := []byte("abc")
	trace := &physicalReads{Source: bytes.NewReader(append(make([]byte, 4096), data...))}
	section, err := block.NewSection(trace, 4096, int64(len(data)))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	checkClonePhysicalReads(t, trace, "plain tail", clonePhysicalValue{section}, [][3]int64{{0, 4096, 3}}, hex.EncodeToString(sum[:]))
}

type cloneFailureInput struct {
	size      int64
	exit      bool
	readError bool
}

func (s cloneFailureInput) Size() int64 { return s.size }
func (s cloneFailureInput) ReadAt(data []byte, offset int64) (int, error) {
	if offset > 0 && s.exit {
		os.Exit(17)
	}
	if offset > 0 && s.readError {
		return 0, io.ErrUnexpectedEOF
	}
	if offset >= s.size {
		return 0, io.EOF
	}
	n := min(int64(len(data)), s.size-offset)
	clear(data[:n])
	if n < int64(len(data)) {
		return int(n), io.EOF
	}
	return int(n), nil
}

func TestAPFSCloneEditFailuresNeverPublishOrAlterSource(t *testing.T) {
	if os.Getenv("APFS_CLONE_EDIT_INTERRUPT_CHILD") == "1" {
		_, _ = imageedit.Apply(context.Background(), os.Getenv("APFS_CLONE_EDIT_SOURCE"), os.Getenv("APFS_CLONE_EDIT_DESTINATION"), imageedit.Options{Time: fixedClock}, []imageedit.Change{{Path: "/Fixture/edit", Data: cloneFailureInput{size: 1 << 20, exit: true}}})
		os.Exit(99)
	}
	for _, k := range cloneEditingCases(t) {
		if k.Stage != "shared" {
			continue
		}
		t.Run(native.CaseKey(caseRef(k)), func(t *testing.T) {
			storageImageUnchanged(t, k)
			for _, failure := range []string{"disk-full", "read-interrupted", "process-interrupted"} {
				t.Run(failure, func(t *testing.T) {
					root := t.TempDir()
					destination := filepath.Join(root, "edited.dmg")
					if failure == "process-interrupted" {
						command := exec.Command(os.Args[0], "-test.run=^TestAPFSCloneEditFailuresNeverPublishOrAlterSource$")
						command.Env = append(os.Environ(), "APFS_CLONE_EDIT_INTERRUPT_CHILD=1", "APFS_CLONE_EDIT_SOURCE="+k.Image(), "APFS_CLONE_EDIT_DESTINATION="+destination, "TMPDIR="+root, "TMP="+root, "TEMP="+root)
						var exit *exec.ExitError
						if err := command.Run(); !errors.As(err, &exit) || exit.ExitCode() != 17 {
							t.Fatal("child did not stop during clone COW", err)
						}
					} else {
						input := cloneFailureInput{size: k.Observation.Image.DiskBytes, readError: failure == "read-interrupted"}
						_, err := imageedit.Apply(context.Background(), k.Image(), destination, imageedit.Options{Time: fixedClock}, []imageedit.Change{{Path: "/Fixture/edit", Data: input}})
						want := filesystem.ErrLimit
						if failure == "read-interrupted" {
							want = io.ErrUnexpectedEOF
						}
						if !errors.Is(err, want) {
							t.Fatal("wrong clone failure", err, want)
						}
					}
					if _, err := os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) {
						t.Fatal("failed clone edit published a destination", err)
					}
					if sum, err := schema.FileDigest(k.Image()); err != nil || sum != k.Observation.Image.SHA256 {
						t.Fatal("failed clone edit changed its immutable source", err)
					}
				})
			}
		})
	}
}
