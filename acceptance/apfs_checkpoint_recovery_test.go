package acceptance_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

type checkpointDamage struct {
	ParentSHA256              string
	Offset                    int64
	Before, After             byte
	DisabledControlDescriptor uint64
}

type checkpointRecoveryCase struct {
	ID         string
	Source     hfsGrowthArchive
	Checkpoint struct {
		BlockZeroXID uint64
		Latest       struct{ XID, Address uint64 }
		Candidates   []struct{ XID, Address uint64 }
		Future       map[string]struct{ XID, Address uint64 }
	}
	Native struct {
		SelectedXID    uint64
		CheckerStatus  int
		VolumeUUID     string
		Files          fileObservation
		ControlArchive hfsGrowthArchive
	}
	Damage *checkpointDamage
}

type checkpointRecoveryManifest struct {
	Schema, Major  int
	Scenario       string
	Complete       bool
	CommandsSHA256 string
	Producer       struct {
		System, Version, Build, Architecture, Run, Revision string
		Sources, Tools                                      map[string]string
	}
	Cases []checkpointRecoveryCase
}

func loadCheckpointManifest(t *testing.T, path string) checkpointRecoveryManifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 16<<20 {
		t.Fatal("native checkpoint manifest", err)
	}
	var index struct {
		Schema   int
		Scenario string
		Producer map[string]any
		Evidence hfsGrowthArchive
		Cases    []struct {
			ID, SourceSHA256                       string
			LatestTransaction, SelectedTransaction uint64
			DerivedDamage                          *checkpointDamage
		}
	}
	if err = json.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	if index.Scenario == "apfs-checkpoint-recovery-reference" {
		original := openGrowthArchive(t, filepath.Dir(path), index.Evidence)
		data, err = io.ReadAll(io.NewSectionReader(original, 0, original.Size()))
		if err != nil {
			t.Fatal(err)
		}
		var native struct{ Producer map[string]any }
		if err = json.Unmarshal(data, &native); err != nil || index.Schema != 1 || !reflect.DeepEqual(index.Producer, native.Producer) {
			t.Fatal("retention changes native provenance", err)
		}
	}
	var result checkpointRecoveryManifest
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if index.Scenario == "apfs-checkpoint-recovery-reference" {
		if len(index.Cases) != len(result.Cases) {
			t.Fatal("retained checkpoint cases missing")
		}
		for i, entry := range index.Cases {
			c := result.Cases[i]
			if entry.ID != c.ID || entry.SourceSHA256 != c.Source.UncompressedSHA256 || entry.LatestTransaction != c.Checkpoint.Latest.XID || entry.SelectedTransaction != c.Native.SelectedXID || !reflect.DeepEqual(entry.DerivedDamage, c.Damage) {
				t.Fatal("retention changes recovery boundaries or damage provenance")
			}
		}
	}
	return result
}

// Hash complete disk bytes, refreshing only block zero from the independently
// selected native descriptor. For damage cases the native control already
// disables the damaged newest descriptor, so equality also proves that Go did
// not modify old/new file records, unused data, forks or unrelated sectors.
func checkpointDiskHash(t *testing.T, source block.Source, selectedAddress uint64) string {
	t.Helper()
	var selected []byte
	if selectedAddress != 0 {
		selected = make([]byte, 4096)
		if err := block.ReadFull(source, selected, int64(selectedAddress)*4096); err != nil {
			t.Fatal(err)
		}
	}
	hash := sha256.New()
	buffer := make([]byte, 128<<10)
	for offset := int64(0); offset < source.Size(); {
		chunk := buffer[:min(int64(len(buffer)), source.Size()-offset)]
		if err := block.ReadFull(source, chunk, offset); err != nil {
			t.Fatal(err)
		}
		if offset == 0 && selected != nil {
			copy(chunk, selected)
		}
		if _, err := hash.Write(chunk); err != nil {
			t.Fatal(err)
		}
		offset += int64(len(chunk))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// Apple creates both name profiles and supplies actual pre-publication,
// post-publication and wrapped checkpoint windows. Its checker supplies the
// selected XID and its read-only mount supplies every expected file value.
// Deliberate checksum damage has separate provenance and Apple-checked controls.
func TestNativeAPFSCheckpointRecovery(t *testing.T) {
	root := nativeInput(t, "APFS_NATIVE_CHECKPOINT_RECOVERY", "testdata/apfs-recovery")
	paths, err := filepath.Glob(filepath.Join(root, "*", "recovery.json"))
	if err != nil || len(paths) != 3 {
		t.Fatal("macOS 15, 26 and 27 checkpoint references required", err)
	}
	majors := map[int]bool{}
	for _, path := range paths {
		manifest := loadCheckpointManifest(t, path)
		p := manifest.Producer
		if manifest.Schema != 1 || manifest.Scenario != "apfs-checkpoint-recovery" || !manifest.Complete || majors[manifest.Major] || (manifest.Major != 15 && manifest.Major != 26 && manifest.Major != 27) || len(manifest.Cases) != 12 || p.System != "macOS" || p.Build == "" || p.Architecture == "" || p.Run == "" || len(p.Revision) != 40 || len(p.Sources) != 12 || len(p.Tools) != 3 || !strings.HasPrefix(p.Version, fmt.Sprint(manifest.Major)+".") {
			t.Fatal("incomplete native checkpoint inventory/provenance")
		}
		majors[manifest.Major] = true
		dir := filepath.Dir(path)
		verifyDigest(t, dir, "commands.json", manifest.CommandsSHA256)
		scripts := filepath.Join(dir, "scripts")
		if _, err = os.Stat(scripts); os.IsNotExist(err) {
			scripts = filepath.Join(filepath.Dir(dir), "scripts")
		}
		for name, digest := range p.Sources {
			verifyDigest(t, scripts, name, digest)
		}
		t.Run(fmt.Sprintf("macos-%d", manifest.Major), func(t *testing.T) {
			seen := map[string]bool{}
			for _, c := range manifest.Cases {
				if seen[c.ID] || c.Native.CheckerStatus != 0 || len(c.Native.Files.Entries) < 260 || c.Source.UncompressedBytes != 128<<20 {
					t.Fatal("incomplete native checkpoint case")
				}
				seen[c.ID] = true
				t.Run(c.ID, func(t *testing.T) {
					compareCheckpointRecovery(t, dir, manifest.Major, c)
				})
			}
			for _, prefix := range []string{"apfs", "apfs-case-sensitive"} {
				for _, shape := range []string{"data", "mapping", "committed", "wrapped", "bad-mapping", "bad-object"} {
					if !seen[prefix+"-"+shape] {
						t.Fatal("checkpoint shape missing", prefix, shape)
					}
				}
			}
			for _, c := range manifest.Cases {
				if c.ID == "apfs-committed" {
					t.Run("interrupted-Go-commits", func(t *testing.T) { compareInterruptedGoCheckpoints(t, dir, manifest.Major, c) })
				}
			}
		})
	}
}

func compareCheckpointRecovery(t *testing.T, dir string, major int, c checkpointRecoveryCase) {
	t.Helper()
	ctx := context.Background()
	sourcePath := openAPFSEditArchive(t, dir, c.Source)
	before := fileDigest(t, sourcePath)
	source, err := block.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	report, err := apfs.InspectCheckpoints(ctx, source)
	if err != nil || !report.BlockZeroValid || uint64(report.BlockZeroTransaction) != c.Checkpoint.BlockZeroXID || uint64(report.SelectedTransaction) != c.Native.SelectedXID {
		t.Fatal("checkpoint selection differs from native checker", report, err)
	}
	var nativeAddress uint64
	for _, candidate := range c.Checkpoint.Candidates {
		if candidate.XID == c.Native.SelectedXID {
			if nativeAddress != 0 {
				t.Fatal("ambiguous native selected descriptor")
			}
			nativeAddress = candidate.Address
		}
	}
	if uint64(report.SelectedAddress) != nativeAddress {
		t.Fatal("wrong native descriptor selected")
	}
	expected := block.Source(source)
	if c.Damage != nil {
		if _, err = apfs.Open(source); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatal("ordinary reader implicitly recovered damaged checkpoint", err)
		}
		if report.Candidates[0].State != "invalid" || c.Damage.After != c.Damage.Before^1 {
			t.Fatal("damage control not distinguished from interruption")
		}
		controlPath := openAPFSEditArchive(t, dir, c.Native.ControlArchive)
		control, err := block.Open(controlPath)
		if err != nil {
			t.Fatal(err)
		}
		defer control.Close()
		expected = control
		// Restore the single recorded checksum byte only while hashing. This
		// proves the damaged fixture derives from the retained genuine parent.
		hash := sha256.New()
		buffer := make([]byte, 128<<10)
		for offset := int64(0); offset < source.Size(); offset += int64(len(buffer)) {
			if err = block.ReadFull(source, buffer, offset); err != nil {
				t.Fatal(err)
			}
			if c.Damage.Offset >= offset && c.Damage.Offset < offset+int64(len(buffer)) {
				if buffer[c.Damage.Offset-offset] != c.Damage.After {
					t.Fatal("damage byte differs from native provenance")
				}
				buffer[c.Damage.Offset-offset] = c.Damage.Before
			}
			hash.Write(buffer)
		}
		if hex.EncodeToString(hash.Sum(nil)) != c.Damage.ParentSHA256 {
			t.Fatal("damage changes more than the recorded checksum byte")
		}
	} else {
		if report.Candidates[0].Transaction != report.SelectedTransaction || c.Checkpoint.Latest.XID != c.Native.SelectedXID {
			t.Fatal("native genuine interruption did not select newest complete checkpoint")
		}
		for _, shape := range []string{"data", "mapping"} {
			if strings.HasSuffix(c.ID, "-"+shape) && c.Checkpoint.Future[shape].XID <= c.Native.SelectedXID {
				t.Fatal("uncommitted newer object/map window missing")
			}
		}
	}
	want := checkpointDiskHash(t, expected, nativeAddress)
	outputRoot := os.Getenv("APFS_CHECKPOINT_RECOVERY_OUTPUT")
	if outputRoot == "" {
		outputRoot = t.TempDir()
	}
	outputRoot = filepath.Join(outputRoot, fmt.Sprintf("macos-%d", major))
	if err = os.MkdirAll(outputRoot, 0700); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"UDRO", "UDZO"} {
		t.Run(format, func(t *testing.T) {
			output := filepath.Join(outputRoot, c.ID+"-"+format+".dmg")
			result, err := imageedit.RecoverCheckpoint(ctx, sourcePath, output, imageedit.CheckpointRecoveryOptions{Format: format})
			if err != nil || result.Checkpoint == nil || !result.Checkpoint.FilesystemValidated || result.Transaction != c.Native.SelectedXID {
				t.Fatal("completed checkpoint recovery", result, err)
			}
			if c.Damage != nil && (len(result.Checkpoint.DiscardedDescriptors) != 1 || uint64(result.Checkpoint.DiscardedDescriptors[0]) != c.Damage.DisabledControlDescriptor) {
				t.Fatal("wrong damaged descriptor discarded", result.Checkpoint)
			}
			image, err := diskimage.Open(output)
			if err != nil {
				t.Fatal(err)
			}
			view, err := image.Partition(0)
			if err != nil || checkpointDiskHash(t, view, 0) != want {
				t.Fatal("recovery changed sectors beyond explicit checkpoint normalization", err)
			}
			container, err := apfs.Open(view)
			if err != nil || len(container.Volumes) != 1 || container.Volumes[0].UUID != c.Native.VolumeUUID || uint64(container.XID) != c.Native.SelectedXID {
				t.Fatal("recovered identity/transaction", err)
			}
			compareMetadataState(t, &container.Volumes[0], c.Native.Files, "apfs")
			if err = image.Close(); err != nil {
				t.Fatal(err)
			}
			if format == "UDRO" {
				repeat := filepath.Join(t.TempDir(), "repeat.dmg")
				if _, err = imageedit.RecoverCheckpoint(ctx, sourcePath, repeat, imageedit.CheckpointRecoveryOptions{Format: format}); err != nil || fileDigest(t, repeat) != fileDigest(t, output) {
					t.Fatal("checkpoint recovery not reproducible", err)
				}
				edited := filepath.Join(outputRoot, c.ID+"-edited.dmg")
				if _, err = imageedit.Apply(ctx, output, edited, imageedit.Options{Format: "UDZO", Time: time.Unix(1749283750, 0)}, []filesystem.Change{{Operation: "chmod", Path: "/Fixture/retained", Mode: "0600"}}); err != nil {
					t.Fatal("recovered image not editable", err)
				}
			}
		})
	}
	if _, err = imageedit.RecoverCheckpoint(ctx, sourcePath, sourcePath, imageedit.CheckpointRecoveryOptions{}); !os.IsExist(err) {
		t.Fatal("source overwrite admitted", err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	failed := filepath.Join(t.TempDir(), "canceled.dmg")
	if _, err = imageedit.RecoverCheckpoint(canceled, sourcePath, failed, imageedit.CheckpointRecoveryOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err = os.Stat(failed); !os.IsNotExist(err) {
		t.Fatal("canceled recovery published output", err)
	}
	if fileDigest(t, sourcePath) != before {
		t.Fatal("recovery changed original evidence")
	}
}
