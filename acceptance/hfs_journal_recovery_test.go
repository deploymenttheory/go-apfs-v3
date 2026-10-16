package acceptance_test

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

type journalRecoveryManifest struct {
	Schema, Major  int
	Scenario       string
	Complete       bool
	CommandsSHA256 string
	Producer       struct {
		System, Version, Build, Architecture, Run, Revision string
		Sources                                             map[string]string
	}
	Cases []struct {
		ID      string
		Source  hfsGrowthArchive
		Journal struct {
			Offset, Size, Start, End            uint64
			HeaderSize, BlockListSize, Sequence uint32
		}
		Recovered struct {
			Files                  fileObservation
			Archive, ReplayArchive hfsGrowthArchive
			CheckerStatus          int
		}
	}
}

func loadJournalRecoveryManifest(t *testing.T, path string) journalRecoveryManifest {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil || len(data) > 16<<20 {
		t.Fatal("recovery manifest", err)
	}
	var index struct {
		Schema   int
		Scenario string
		Producer map[string]any
		Evidence hfsGrowthArchive
		Cases    []struct {
			ID           string
			Start, End   uint64
			ReplaySHA256 string
		}
	}
	if err = json.Unmarshal(data, &index); err != nil {
		t.Fatal(err)
	}
	if index.Scenario == "hfs-journal-recovery-reference" {
		original := openGrowthArchive(t, filepath.Dir(path), index.Evidence)
		data, err = io.ReadAll(io.NewSectionReader(original, 0, original.Size()))
		if err != nil {
			t.Fatal(err)
		}
		var producer struct{ Producer map[string]any }
		if err = json.Unmarshal(data, &producer); err != nil || index.Schema != 1 || !reflect.DeepEqual(producer.Producer, index.Producer) {
			t.Fatal("retention changes native provenance", err)
		}
	}
	var result journalRecoveryManifest
	if err = json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	if index.Scenario == "hfs-journal-recovery-reference" {
		if len(index.Cases) != len(result.Cases) {
			t.Fatal("incomplete retained recovery index")
		}
		for i, entry := range index.Cases {
			c := result.Cases[i]
			if entry.ID != c.ID || entry.Start != c.Journal.Start || entry.End != c.Journal.End || entry.ReplaySHA256 != c.Recovered.ReplayArchive.UncompressedSHA256 {
				t.Fatal("retention changes native recovery boundaries")
			}
		}
	}
	return result
}

func journalDiskHash(t *testing.T, source block.Source, markUnmounted bool) string {
	t.Helper()
	hash := sha256.New()
	buffer := make([]byte, 128<<10)
	for offset := int64(0); offset < source.Size(); {
		chunk := buffer[:min(int64(len(buffer)), source.Size()-offset)]
		if err := block.ReadFull(source, chunk, offset); err != nil {
			t.Fatal(err)
		}
		if markUnmounted && offset == 0 {
			binary.BigEndian.PutUint32(chunk[1028:], binary.BigEndian.Uint32(chunk[1028:])|0x100)
		}
		if _, err := hash.Write(chunk); err != nil {
			t.Fatal(err)
		}
		offset += int64(len(chunk))
	}
	return hex.EncodeToString(hash.Sum(nil))
}

// The source and expected replay bytes come from Apple's writer and replay-only
// kernel operation. Exact full-disk comparison catches changes that a logical
// readback misses. Publishing additionally proves complete recovered ownership,
// metadata/forks/link identities, source immutability and reproducible encoding.
func TestNativeHFSJournalRecovery(t *testing.T) {
	root := nativeInput(t, "APFS_NATIVE_HFS_RECOVERY", "testdata/hfs-recovery")
	paths, err := filepath.Glob(filepath.Join(root, "*", "recovery.json"))
	if err != nil || len(paths) != 3 {
		t.Fatal("macOS 15, 26 and 27 journal recovery references required", err)
	}
	ctx := context.Background()
	majors := map[int]bool{}
	for _, path := range paths {
		manifest := loadJournalRecoveryManifest(t, path)
		producer := manifest.Producer
		if manifest.Schema != 1 || manifest.Scenario != "hfs-journal-recovery" || !manifest.Complete || majors[manifest.Major] || (manifest.Major != 15 && manifest.Major != 26 && manifest.Major != 27) || producer.System != "macOS" || producer.Build == "" || producer.Architecture == "" || producer.Run == "" || len(producer.Revision) != 40 || len(producer.Sources) != 9 || !strings.HasPrefix(producer.Version, fmt.Sprint(manifest.Major)+".") || len(manifest.Cases) != 8 {
			t.Fatal("incomplete native recovery provenance")
		}
		majors[manifest.Major] = true
		dir := filepath.Dir(path)
		scripts := filepath.Join(dir, "scripts")
		if _, err := os.Stat(scripts); os.IsNotExist(err) {
			scripts = filepath.Join(filepath.Dir(dir), "scripts")
		}
		verifyDigest(t, dir, "commands.json", manifest.CommandsSHA256)
		for _, name := range []string{"hfs_journal_recovery.py", "hfs_replay.c", "hfs_capture.c", "hfs_header_growth.py", "image_repacking.py", "container_building.py", "image_building.py", "file_compression.py", "capture.py"} {
			verifyDigest(t, scripts, name, producer.Sources[name])
		}
		t.Run(fmt.Sprintf("macos-%d", manifest.Major), func(t *testing.T) {
			seen := map[string]bool{}
			for _, c := range manifest.Cases {
				format, shape, found := strings.Cut(c.ID, "-")
				if seen[c.ID] || !found || (format != "hfsplus" && format != "hfsx") || (shape != "linear" && shape != "wrapped" && shape != "complete-tail" && shape != "incomplete-tail") || c.Recovered.CheckerStatus != 0 || len(c.Recovered.Files.Entries) < 260 || c.Journal.Start == c.Journal.End {
					t.Fatal("incomplete native interrupted/recovered cases")
				}
				seen[c.ID] = true
				t.Run(c.ID, func(t *testing.T) {
					sourcePath := openEditArchive(t, dir, c.Source)
					source, err := block.Open(sourcePath)
					if err != nil {
						t.Fatal(err)
					}
					defer source.Close()
					before := journalDiskHash(t, source, false)
					journal, err := hfsplus.InspectJournal(source)
					if err != nil || !journal.Pending || journal.Offset != c.Journal.Offset || journal.Size != c.Journal.Size || journal.Start != c.Journal.Start || journal.End != c.Journal.End || journal.Sequence != c.Journal.Sequence || journal.HeaderSize != c.Journal.HeaderSize || journal.BlockListSize != c.Journal.BlockListSize {
						t.Fatal("native journal geometry", journal, err)
					}
					if (shape == "linear" || shape == "wrapped") && (shape == "wrapped") != (journal.Start > journal.End) {
						t.Fatal("ring wrap control missing")
					}
					if err = hfsplus.ValidateMutation(ctx, source); err == nil {
						t.Fatal("pending source admitted without explicit recovery")
					}
					nativePath := openEditArchive(t, dir, c.Recovered.ReplayArchive)
					native, err := block.Open(nativePath)
					if err != nil {
						t.Fatal(err)
					}
					defer native.Close()
					scratch, err := block.Stage(ctx, source, "")
					if err != nil {
						t.Fatal(err)
					}
					defer scratch.Close()
					report, err := hfsplus.ReplayJournal(ctx, scratch)
					if err != nil || report.Transactions == 0 || report.Sectors == 0 {
						t.Fatal(report, err)
					}
					if shape == "complete-tail" && report.ExtraBlockLists == 0 {
						t.Fatal("native complete tail was not replayed")
					}
					if shape == "incomplete-tail" && report.RecoveredEnd != journal.End {
						t.Fatal("native incomplete tail changed recovery boundary")
					}
					if got := journalDiskHash(t, scratch, false); got != c.Recovered.ReplayArchive.UncompressedSHA256 {
						t.Fatalf("Go replay differs from Apple's replay-only bytes: got %s want %s", got, c.Recovered.ReplayArchive.UncompressedSHA256)
					}
					want := journalDiskHash(t, native, true)
					outputRoot := os.Getenv("APFS_HFS_RECOVERY_OUTPUT")
					if outputRoot == "" {
						outputRoot = t.TempDir()
					}
					outputRoot = filepath.Join(outputRoot, fmt.Sprintf("macos-%d", manifest.Major))
					if err = os.MkdirAll(outputRoot, 0700); err != nil {
						t.Fatal(err)
					}
					for _, format := range []string{"UDRO", "UDZO"} {
						t.Run(format, func(t *testing.T) {
							output := filepath.Join(outputRoot, c.ID+"-"+format+".dmg")
							result, err := imageedit.RecoverJournal(ctx, sourcePath, output, imageedit.JournalRecoveryOptions{Format: format})
							if err != nil || result.Journal == nil {
								t.Fatal("completed recovery", result, err)
							}
							image, err := diskimage.Open(output)
							if err != nil {
								t.Fatal(err)
							}
							view, err := image.Partition(0)
							if err != nil {
								t.Fatal(err)
							}
							if journalDiskHash(t, view, false) != want {
								t.Fatal("publication changed sectors beyond validated unmounted marking")
							}
							volume, err := hfsplus.Open(view)
							if err != nil || !volume.Clean || !volume.Journaled {
								t.Fatal("recovered filesystem", err)
							}
							compareMetadataState(t, volume, c.Recovered.Files, "hfs")
							if err = image.Close(); err != nil {
								t.Fatal(err)
							}
							if format == "UDRO" {
								repeat := filepath.Join(t.TempDir(), "repeat.dmg")
								if _, err = imageedit.RecoverJournal(ctx, sourcePath, repeat, imageedit.JournalRecoveryOptions{Format: format}); err != nil {
									t.Fatal(err)
								}
								if fileDigest(t, output) != fileDigest(t, repeat) {
									t.Fatal("recovery is not reproducible")
								}
								edited := filepath.Join(outputRoot, c.ID+"-edited.dmg")
								if _, err = imageedit.Apply(ctx, output, edited, imageedit.Options{Format: "UDRO", Time: time.Unix(1749283750, 0)}, []filesystem.Change{{Operation: "chmod", Path: "/Fixture/retained", Mode: "0600"}}); err != nil {
									t.Fatal("recovered image not editable", err)
								}
							}
						})
					}
					failed := filepath.Join(t.TempDir(), "canceled.dmg")
					canceled, cancel := context.WithCancel(ctx)
					cancel()
					if _, err = imageedit.RecoverJournal(canceled, sourcePath, failed, imageedit.JournalRecoveryOptions{}); !errors.Is(err, context.Canceled) {
						t.Fatal(err)
					}
					if _, err = os.Stat(failed); !os.IsNotExist(err) {
						t.Fatal("canceled recovery published", err)
					}
					if _, err = imageedit.RecoverJournal(ctx, sourcePath, sourcePath, imageedit.JournalRecoveryOptions{}); !os.IsExist(err) {
						t.Fatal("source overwrite accepted", err)
					}
					if journalDiskHash(t, source, false) != before {
						t.Fatal("recovery changed source evidence")
					}
				})
			}
		})
	}
}
