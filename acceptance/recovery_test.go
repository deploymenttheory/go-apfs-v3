package acceptance_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

func TestRecoveryMatchesAppleStates(t *testing.T) {
	cases, _ := loadCorpus(t)
	byKey := map[string]corpus.Case{}
	for _, k := range cases {
		byKey[stageKey(k.Producer, k.Recipe, k.Profile, k.Stage)] = k
	}
	for _, k := range cases {
		if k.Observation.Recovery == nil {
			continue
		}
		t.Run(fmt.Sprintf("macos-%d/%s/%s/%s", k.Producer, k.Recipe, k.Profile, k.Stage), func(t *testing.T) {
			t.Parallel()
			recovery := k.Observation.Recovery
			expected, ok := byKey[stageKey(k.Producer, k.Recipe, k.Profile, recovery.ExpectedStage)]
			if !ok || len(expected.Observation.Views) == 0 {
				t.Fatalf("missing independent recovery expectation %s", recovery.ExpectedStage)
			}
			ctx := context.Background()
			sourcePath := fixtureImage(t, k)
			source, err := block.Open(sourcePath)
			if err != nil {
				t.Fatal(err)
			}
			trackFixturePath(t, source, sourcePath)
			defer closeFixture(t, source)
			before, err := recoveryDiskDigest(source, source.Size())
			if err != nil {
				t.Fatal(err)
			}
			if recovery.Damage != nil {
				parent, ok := byKey[stageKey(k.Producer, k.Recipe, k.Profile, "window-committed")]
				if !ok {
					t.Fatal("damage control has no original parent")
				}
				assertDeclaredRecoveryDamage(t, source, fixtureImage(t, parent), recovery.Damage)
			}
			var replay block.Source
			var closeReplay func() error
			switch recovery.Kind {
			case "journal":
				journal, err := hfsplus.InspectJournal(source)
				if err != nil || !journal.Pending {
					t.Fatalf("pending native journal: %+v %v", journal, err)
				}
				geometry, ok := recovery.Acquisition["journal"].(map[string]any)
				if !ok {
					t.Fatal("native journal acquisition geometry is missing")
				}
				for name, value := range map[string]uint64{"offset": journal.Offset, "size": journal.Size, "start": journal.Start, "end": journal.End, "sequence": uint64(journal.Sequence), "headerSize": uint64(journal.HeaderSize), "blockListSize": uint64(journal.BlockListSize)} {
					if uint64(number(geometry[name])) != value {
						t.Errorf("journal inspect %s: got %d, recorded %v", name, value, geometry[name])
					}
				}
				if err := hfsplus.ValidateMutation(ctx, source); err == nil {
					t.Fatal("ordinary mutation admitted an unreplayed journal")
				}
				if strings.HasSuffix(k.Stage, "linear") && journal.Start >= journal.End {
					t.Fatal("linear native journal is not linear")
				}
				if strings.HasSuffix(k.Stage, "wrapped") && journal.Start <= journal.End {
					t.Fatal("wrapped native journal is not wrapped")
				}
				ref := expected.Observation.ReplayOnly
				if ref == nil || ref.DiskSHA256 == "" {
					t.Fatal("missing Apple replay-only evidence")
				}
				path := filepath.Join(t.TempDir(), "apple-replay.raw")
				if err := corpus.ExpandGzip(filepath.Join(expected.Dir, ref.File), path); err != nil {
					t.Fatal(err)
				}
				native, err := block.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				replay = native
				closeReplay = native.Close
				defer closeReplay()
				if sum, err := recoveryDiskDigest(native, native.Size()); err != nil || sum != ref.DiskSHA256 {
					t.Fatalf("replay-only evidence digest: %s %v", sum, err)
				}
				scratch, err := block.Stage(ctx, source, "")
				if err != nil {
					t.Fatal(err)
				}
				defer closeFixture(t, scratch)
				report, err := hfsplus.ReplayJournal(ctx, scratch)
				if err != nil || report.Transactions == 0 || report.Sectors == 0 {
					t.Fatalf("journal replay: %+v %v", report, err)
				}
				if strings.HasSuffix(k.Stage, "complete-tail") && !strings.HasSuffix(k.Stage, "incomplete-tail") && report.ExtraBlockLists == 0 {
					t.Fatal("complete native tail was not replayed")
				}
				if strings.HasSuffix(k.Stage, "incomplete-tail") && report.RecoveredEnd != journal.End {
					t.Fatal("incomplete native tail changed the committed boundary")
				}
				if sum, err := recoveryDiskDigest(scratch, scratch.Size()); err != nil || sum != ref.DiskSHA256 {
					t.Fatalf("Go replay differs from Apple's replay-only bytes: %s, want %s (%v)", sum, ref.DiskSHA256, err)
				}
			case "checkpoint":
				report, err := apfs.InspectCheckpoints(ctx, source)
				if err != nil || uint64(report.SelectedTransaction) != expected.Observation.Checks.SelectedXID {
					t.Fatalf("checkpoint selected %+v, Apple selected %d (%v)", report, expected.Observation.Checks.SelectedXID, err)
				}
				if recovery.RefuseOpen {
					if _, err := apfs.Open(source); err == nil {
						t.Fatal("ordinary open silently fell back through damaged checkpoint")
					}
				}
			default:
				t.Fatalf("unknown recovery kind %q", recovery.Kind)
			}
			for _, format := range []string{"UDRO", "UDZO"} {
				name := outputName(k, "recover."+format+".dmg")
				path := produceTwice(t, name, true, func(path string) error {
					_, err := recoverImage(ctx, fixtureImage(t, k), path, recovery.Kind, format)
					return err
				})
				image, err := diskimage.Open(path)
				if err != nil {
					t.Fatal(err)
				}
				report, err := inspect.Image(ctx, image)
				if err != nil {
					closeFixture(t, image)
					t.Fatal(err)
				}
				if len(report.Partitions) != 1 {
					closeFixture(t, image)
					t.Fatal("recovery changed the partition inventory")
				}
				var reader filesystem.Reader
				if report.Partitions[0].HFSPlus != nil {
					reader = report.Partitions[0].HFSPlus
				} else if report.Partitions[0].APFS != nil && len(report.Partitions[0].APFS.Volumes) == 1 {
					reader = &report.Partitions[0].APFS.Volumes[0]
				}
				if reader == nil {
					closeFixture(t, image)
					t.Fatal("recovered output has no single filesystem")
				}
				for _, view := range expected.Observation.Views {
					compareView(t, ctx, name, reader, view)
				}
				diskHash := ""
				if replay != nil {
					diskHash = replayPublicationDigest(t, replay)
					if got, err := recoveryDiskDigest(image, image.Size()); err != nil || got != diskHash {
						t.Errorf("journal publication changed bytes beyond the primary unmounted flag: %s want %s (%v)", got, diskHash, err)
					}
				}
				if recovery.Kind == "checkpoint" {
					if uint64(report.Partitions[0].APFS.XID) != expected.Observation.Checks.SelectedXID {
						t.Error("published output selected a different transaction")
					}
					assertCheckpointNormalization(t, source, image)
				}
				if err := image.Close(); err != nil {
					t.Fatal(err)
				}
				recordOutput(t, schema.Output{Name: name, File: filepath.Base(path), Operation: "recover-" + recovery.Kind, Format: format, Source: caseRef(k), Expect: schema.Expectation{View: recovery.ExpectedStage, DiskSHA256: diskHash, SelectedXID: expected.Observation.Checks.SelectedXID, Codesign: []string{"Fixture/Example.app"}, Continuation: format == "UDZO"}})
			}
			failed := filepath.Join(t.TempDir(), "canceled.dmg")
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if _, err := recoverImage(canceled, fixtureImage(t, k), failed, recovery.Kind, "UDZO"); !errors.Is(err, context.Canceled) {
				t.Fatalf("canceled recovery: %v", err)
			}
			if _, err := os.Lstat(failed); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("canceled recovery published an output", err)
			}
			if _, err := recoverImage(ctx, fixtureImage(t, k), fixtureImage(t, k), recovery.Kind, "UDRO"); !errors.Is(err, fs.ErrExist) {
				t.Fatal("source overwrite admitted", err)
			}
			if after, err := recoveryDiskDigest(source, source.Size()); err != nil || after != before {
				t.Fatal("recovery changed original evidence", err)
			}
		})
	}
}

// Presence is checked against the recipes, rather than trusting whatever the
// current bundle happens to contain. Missing recovery cases cannot turn green.
func TestCorpusContainsEveryRecoveryProfileAndStage(t *testing.T) {
	cases, _ := loadCorpus(t)
	seen := map[string]bool{}
	for _, k := range cases {
		seen[stageKey(k.Producer, k.Recipe, k.Profile, k.Stage)] = true
	}
	for _, recipe := range recipesByName(t) {
		if recipe.Name != "hfs-journal-interruption" && recipe.Name != "apfs-checkpoint-interruption" {
			continue
		}
		for _, producer := range schema.Producers {
			for _, profile := range recipe.Profiles {
				for _, stage := range recipe.Stages {
					key := stageKey(producer, recipe.Name, profile, stage.Name)
					if !seen[key] {
						t.Errorf("required recovery case missing: %s", key)
					}
				}
			}
		}
	}
}

// The child pauses only after the real staging file contains an incomplete
// copy. Killing that process then exercises production publication and source
// ownership without timing a fast copy or adding a production fault hook.
func TestRecoveryCopyInterruptedBeforePublication(t *testing.T) {
	if source := os.Getenv("APFS_RECOVERY_COPY_SOURCE"); source != "" {
		work := os.Getenv("APFS_RECOVERY_COPY_WORK")
		info, err := os.Stat(source)
		if err != nil {
			t.Fatal(err)
		}
		ctx := &recoveryCopyContext{Context: context.Background(), work: work, size: info.Size()}
		if _, err := recoverImage(ctx, source, os.Getenv("APFS_RECOVERY_COPY_OUTPUT"), os.Getenv("APFS_RECOVERY_COPY_KIND"), "UDZO"); err != nil {
			t.Fatal(err)
		}
		t.Fatal("recovery completed without observing its staging copy")
	}
	cases, _ := loadCorpus(t)
	for _, k := range cases {
		journal := k.Profile == "hfsplus-j" && k.Stage == "interrupted-linear"
		checkpoint := k.Profile == "apfs" && k.Stage == "window-data"
		if !journal && !checkpoint {
			continue
		}
		if k.Observation.Recovery == nil {
			t.Fatal("interruption fixture lacks recovery evidence")
		}
		t.Run(fmt.Sprintf("macos-%d/%s", k.Producer, k.Recipe), func(t *testing.T) {
			source := fixtureImage(t, k)
			before, err := schema.FileDigest(source)
			if err != nil {
				t.Fatal(err)
			}
			work := t.TempDir()
			output := filepath.Join(work, "output.dmg")
			child := exec.Command(os.Args[0], "-test.run=^TestRecoveryCopyInterruptedBeforePublication$", "-test.timeout=30s")
			child.Env = append(os.Environ(), "APFS_RECOVERY_COPY_SOURCE="+source, "APFS_RECOVERY_COPY_WORK="+work, "APFS_RECOVERY_COPY_OUTPUT="+output, "APFS_RECOVERY_COPY_KIND="+k.Observation.Recovery.Kind, "TMPDIR="+work, "TMP="+work, "TEMP="+work)
			if err := child.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- child.Wait() }()
			defer func() { _ = child.Process.Kill() }()
			deadline := time.After(20 * time.Second)
			for {
				if _, err := os.Stat(filepath.Join(work, "copy-observed")); err == nil {
					break
				}
				select {
				case err := <-done:
					t.Fatalf("child exited before a partial copy was observed: %v", err)
				case <-deadline:
					t.Fatal("no partial recovery copy observed within 20 seconds")
				case <-time.After(time.Millisecond):
				}
			}
			if err := child.Process.Kill(); err != nil {
				t.Fatal(err)
			}
			if err := <-done; err == nil {
				t.Fatal("interrupted recovery exited successfully")
			}
			if _, err := os.Lstat(output); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("interrupted recovery published an output", err)
			}
			if after, err := schema.FileDigest(source); err != nil || after != before {
				t.Fatal("interrupted recovery changed its source", err)
			}
		})
	}
}

type recoveryCopyContext struct {
	context.Context
	work string
	size int64
}

func (c *recoveryCopyContext) Err() error {
	paths, _ := filepath.Glob(filepath.Join(c.work, ".apfs-edit-disk-*"))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err == nil && info.Size() > 0 && info.Size() < c.size {
			if err := os.WriteFile(filepath.Join(c.work, "copy-observed"), []byte("partial staged disk\n"), 0o600); err != nil {
				return err
			}
			time.Sleep(time.Hour) // the parent kills this child at the observed copy
		}
	}
	return c.Context.Err()
}

func recoverImage(ctx context.Context, source, out, kind, format string) (imageedit.Report, error) {
	if kind == "journal" {
		return imageedit.RecoverJournal(ctx, source, out, imageedit.JournalRecoveryOptions{Format: format})
	}
	return imageedit.RecoverCheckpoint(ctx, source, out, imageedit.CheckpointRecoveryOptions{Format: format})
}

func recoveryDiskDigest(source io.ReaderAt, size int64) (string, error) {
	h := sha256.New()
	n, err := io.Copy(h, io.NewSectionReader(source, 0, size))
	if err == nil && n != size {
		err = io.ErrUnexpectedEOF
	}
	return hex.EncodeToString(h.Sum(nil)), err
}

func assertDeclaredRecoveryDamage(t *testing.T, source block.Source, parentPath string, damage *schema.Damage) {
	t.Helper()
	parent, err := block.Open(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	trackFixturePath(t, parent, parentPath)
	defer closeFixture(t, parent)
	if digest, err := recoveryDiskDigest(parent, parent.Size()); err != nil || digest != damage.ParentSHA256 {
		t.Fatal("damage parent digest differs", err)
	}
	before, err := hex.DecodeString(damage.Before)
	if err != nil {
		t.Fatal(err)
	}
	after, err := hex.DecodeString(damage.After)
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != 1 || len(after) != 1 || before[0]^after[0] != 1 || damage.Offset < 0 || damage.Offset >= parent.Size() || source.Size() != parent.Size() {
		t.Fatal("damage is not the declared single checksum-bit change")
	}
	want, got := make([]byte, 128<<10), make([]byte, 128<<10)
	for offset := int64(0); offset < parent.Size(); offset += int64(len(want)) {
		n := min(int64(len(want)), parent.Size()-offset)
		if err := block.ReadFull(parent, want[:n], offset); err != nil {
			t.Fatal(err)
		}
		if damage.Offset >= offset && damage.Offset < offset+n {
			if want[damage.Offset-offset] != before[0] {
				t.Fatal("damage does not match its original byte")
			}
			want[damage.Offset-offset] = after[0]
		}
		if err := block.ReadFull(source, got[:n], offset); err != nil {
			t.Fatal(err)
		}
		if string(want[:n]) != string(got[:n]) {
			t.Fatalf("damage changed undeclared bytes at offset %d", offset)
		}
	}
}

func replayPublicationDigest(t *testing.T, source block.Source) string {
	t.Helper()
	h := sha256.New()
	buf := make([]byte, 128<<10)
	for off := int64(0); off < source.Size(); {
		b := buf[:min(int64(len(buf)), source.Size()-off)]
		if err := block.ReadFull(source, b, off); err != nil {
			t.Fatal(err)
		}
		if off == 0 {
			binary.BigEndian.PutUint32(b[1028:], binary.BigEndian.Uint32(b[1028:])|0x100)
		}
		_, _ = h.Write(b)
		off += int64(len(b))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Only descriptor normalization and block zero may differ. The selected
// address comes from the complete independently XID-checked inspection above.
func assertCheckpointNormalization(t *testing.T, source block.Source, output io.ReaderAt) {
	t.Helper()
	r, err := apfs.InspectCheckpoints(context.Background(), source)
	if err != nil {
		t.Fatal(err)
	}
	selected := make([]byte, r.BlockSize)
	if err := block.ReadFull(source, selected, int64(r.SelectedAddress)*int64(r.BlockSize)); err != nil {
		t.Fatal(err)
	}
	discard := map[uint64]bool{}
	for _, c := range r.Candidates {
		if c.Transaction >= r.SelectedTransaction && c.State == "invalid" {
			discard[uint64(c.Address)] = true
		}
	}
	want, got := make([]byte, r.BlockSize), make([]byte, r.BlockSize)
	for off := int64(0); off < source.Size(); off += int64(r.BlockSize) {
		if err := block.ReadFull(source, want, off); err != nil {
			t.Fatal(err)
		}
		if off == 0 {
			copy(want, selected)
		} else if discard[uint64(off/int64(r.BlockSize))] {
			clear(want)
		}
		if _, err := output.ReadAt(got, off); err != nil {
			t.Fatal(err)
		}
		if string(got) != string(want) {
			t.Fatalf("checkpoint recovery changed unrelated disk bytes at offset %d", off)
		}
	}
}
