package acceptance_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

type directoryStatisticsVolume struct {
	editingVolumeState
	DirectoryStatistics map[string]string
	OutsideFiles        fileObservation
}

type directoryStatisticsCase struct {
	ID                  string
	Source, NativeAfter hfsGrowthArchive
	Before, After       []directoryStatisticsVolume
}
type directoryStatisticsManifest struct {
	apfsGeometryManifest
	Cases []directoryStatisticsCase
}

func compareDirectoryStatistics(t *testing.T, volume *apfs.Volume, expected map[string]string) {
	t.Helper()
	for path, value := range expected {
		want := nativeStatisticsValues(t, value)
		id, err := filesystem.LookupExact(context.Background(), volume, path)
		if err != nil {
			t.Fatal(path, err)
		}
		got, err := volume.DirectoryStatistics(context.Background(), id)
		if err != nil || got.NumChildren != want[0] || got.TotalSize != want[1] || got.GenCount != want[2] {
			t.Fatal("native directory statistics", path, got, want, err)
		}
	}
}

func nativeStatisticsValues(t *testing.T, value string) (want [3]uint64) {
	t.Helper()
	fields := regexp.MustCompile(`(?:descendants|physical size|gen-count): (\d+)`).FindAllStringSubmatch(value, -1)
	if len(fields) != 3 {
		t.Fatal("native apfs.util statistics layout", value)
	}
	for n, field := range fields {
		v, err := strconv.ParseUint(field[1], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		want[n] = v
	}
	return want
}

type statisticsGeneration struct{ native, portable uint64 }

// Native generations invalidate caches. Their stride differs across kernels
// and allocation strategies; counts and physical bytes remain exact. Bind
// monotonic changes and unchanged generations to each original directory ID,
// retaining that identity through moves outside and back into a tracked tree.
func compareStatisticsChanges(t *testing.T, volume *apfs.Volume, state directoryStatisticsVolume, generations map[uint64]statisticsGeneration) {
	t.Helper()
	identities := map[string]uint64{}
	for _, entry := range state.Files.Entries {
		identities[entry.Path] = entry.Object
	}
	for name, text := range state.DirectoryStatistics {
		want := nativeStatisticsValues(t, text)
		id, err := filesystem.LookupExact(context.Background(), volume, name)
		if err != nil {
			t.Fatal(name, err)
		}
		got, err := volume.DirectoryStatistics(context.Background(), id)
		if err != nil || got.NumChildren != want[0] || got.TotalSize != want[1] || got.Origin != (want[2] != 0) {
			t.Fatal("native directory statistics totals/origin", name, got, want, err)
		}
		identity := identities[name]
		if identity == 0 {
			t.Fatal("native statistics directory identity missing", name)
		}
		previous, exists := generations[identity]
		if exists && previous.native != 0 && want[2] != 0 {
			if want[2] < previous.native || got.GenCount < previous.portable ||
				(want[2] == previous.native) != (got.GenCount == previous.portable) {
				t.Fatal("native statistics invalidation", name, previous, got.GenCount, want[2])
			}
		} else if want[2] == 0 && got.GenCount != 0 || want[2] != 0 && got.GenCount == 0 {
			t.Fatal("native statistics initial generation", name, got.GenCount, want[2])
		}
		generations[identity] = statisticsGeneration{want[2], got.GenCount}
	}
}

func TestNativeAPFSDirectoryStatistics(t *testing.T) {
	root := nativeInput(t, "APFS_NATIVE_DIRECTORY_STATISTICS", "testdata/apfs-directory-statistics")
	paths, err := filepath.Glob(filepath.Join(root, "macos-*", "manifest.json"))
	if err != nil || len(paths) == 0 {
		t.Fatal("native directory statistics absent", err)
	}
	majors := map[int]bool{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		var manifest directoryStatisticsManifest
		if err != nil || json.Unmarshal(data, &manifest) != nil {
			t.Fatal("native statistics manifest", err)
		}
		if manifest.Schema != 1 || manifest.Contract != "apfs-directory-statistics" || len(manifest.Cases) != 2 ||
			manifest.Producer.System != "macOS" || len(manifest.Producer.Revision) != 40 || manifest.Producer.Run == "" ||
			len(manifest.Producer.Sources) != 14 || len(manifest.Producer.Tools) != 4 || majors[manifest.Major] {
			t.Fatal("native statistics provenance")
		}
		majors[manifest.Major] = true
		directory := filepath.Dir(path)
		if manifest.OriginalManifestSHA256 != "" {
			verifyDigest(t, directory, "original-manifest.json", manifest.OriginalManifestSHA256)
		}
		verifyDigest(t, directory, "commands.json", manifest.CommandsSHA256)
		for name, digest := range manifest.Producer.Sources {
			verifyDigest(t, directory, name, digest)
		}
		t.Run("macos-"+strconv.Itoa(manifest.Major), func(t *testing.T) {
			for _, c := range manifest.Cases {
				t.Run(c.ID, func(t *testing.T) {
					if len(c.Before) != 1 || len(c.After) != 1 || len(c.Before[0].DirectoryStatistics) == 0 {
						t.Fatal("complete native statistics state")
					}
					source := openNativeDiskArchive(t, directory, c.Source)
					before := &openAPFSEditVolume(t, source).Volumes[0]
					compareMetadataState(t, before, c.Before[0].Files, "apfs")
					compareDirectoryStatistics(t, before, c.Before[0].DirectoryStatistics)
					verifyDigest(t, directory, c.NativeAfter.Image, c.NativeAfter.SHA256)
					when := time.Unix(1749283750, 0)
					outputRoot := os.Getenv("APFS_DIRECTORY_STATISTICS_OUTPUT")
					if outputRoot == "" {
						outputRoot = t.TempDir()
					}
					outputRoot = filepath.Join(outputRoot, "macos-"+strconv.Itoa(manifest.Major))
					if err := os.MkdirAll(outputRoot, 0700); err != nil {
						t.Fatal(err)
					}
					for _, format := range []string{"UDRO", "UDZO"} {
						t.Run(format, func(t *testing.T) {
							output := filepath.Join(outputRoot, c.ID+"-"+format+".dmg")
							_, err := imageedit.Edit(context.Background(), source, output, imageedit.Options{Format: format, Time: when}, func(editor *imageedit.Editor) error {
								for _, change := range apfsGeometryChanges() {
									if _, err := editor.Apply([]imageedit.Change{change}); err != nil {
										return err
									}
								}
								return nil
							})
							if err != nil {
								t.Fatal(format, err)
							}
							volume := &openAPFSEditVolume(t, output).Volumes[0]
							compareAPFSEditedState(t, volume, c.Before[0].Files, c.After[0].Files, when)
							generations := map[uint64]statisticsGeneration{}
							compareStatisticsChanges(t, before, c.Before[0], generations)
							compareStatisticsChanges(t, volume, c.After[0], generations)
						})
					}
				})
			}
		})
	}
	required := os.Getenv("APFS_REQUIRED_NATIVE_MAJORS")
	if required == "" {
		required = "15,26,27"
	}
	for _, value := range strings.Split(required, ",") {
		major, err := strconv.Atoi(value)
		if err != nil {
			t.Fatal("invalid required statistics major", value)
		}
		if !majors[major] {
			t.Fatal("missing native statistics source", major)
		}
	}
}
