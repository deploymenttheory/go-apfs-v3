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

type phase5StatisticsVolume struct {
	phase5VolumeState
	DirectoryStatistics map[string]string
	OutsideFiles        fileObservation
}

type phase5StatisticsCase struct {
	ID                  string
	Source, NativeAfter hfsGrowthArchive
	Before, After       []phase5StatisticsVolume
}
type phase5StatisticsManifest struct {
	phase5Manifest
	Cases []phase5StatisticsCase
}

func compareDirectoryStatistics(t *testing.T, volume *apfs.Volume, expected map[string]string) {
	t.Helper()
	for path, value := range expected {
		fields := regexp.MustCompile(`(?:descendants|physical size|gen-count): (\d+)`).FindAllStringSubmatch(value, -1)
		if len(fields) != 3 {
			t.Fatal("native apfs.util statistics layout", value)
		}
		var want [3]uint64
		for n, field := range fields {
			v, err := strconv.ParseUint(field[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			want[n] = v
		}
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

func TestNativePhase5DirectoryStatistics(t *testing.T) {
	root := os.Getenv("APFS_NATIVE_PHASE5_STATISTICS")
	if root == "" {
		root = "testdata/phase5-directory-statistics"
	}
	paths, err := filepath.Glob(filepath.Join(root, "macos-*", "manifest.json"))
	if err != nil || len(paths) == 0 {
		t.Fatal("native directory statistics absent", err)
	}
	majors := map[int]bool{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		var manifest phase5StatisticsManifest
		if err != nil || json.Unmarshal(data, &manifest) != nil {
			t.Fatal("native statistics manifest", err)
		}
		if manifest.Schema != 1 || manifest.Contract != "phase5-directory-statistics" || len(manifest.Cases) != 2 ||
			manifest.Producer.System != "macOS" || len(manifest.Producer.Revision) != 40 || manifest.Producer.Run == "" ||
			len(manifest.Producer.Sources) != 14 || len(manifest.Producer.Tools) != 4 || majors[manifest.Major] {
			t.Fatal("native statistics provenance")
		}
		majors[manifest.Major] = true
		directory := filepath.Dir(path)
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
					source := openPhase5Archive(t, directory, c.Source)
					before := &openAPFSEditVolume(t, source).Volumes[0]
					compareMetadataState(t, before, c.Before[0].Files, "apfs")
					compareDirectoryStatistics(t, before, c.Before[0].DirectoryStatistics)
					verifyDigest(t, directory, c.NativeAfter.Image, c.NativeAfter.SHA256)
					when := time.Unix(1749283750, 0)
					outputRoot := os.Getenv("APFS_PHASE5_STATISTICS_OUTPUT")
					if outputRoot == "" {
						outputRoot = t.TempDir()
					}
					outputRoot = filepath.Join(outputRoot, "macos-"+strconv.Itoa(manifest.Major))
					if err := os.MkdirAll(outputRoot, 0700); err != nil {
						t.Fatal(err)
					}
					for _, format := range []string{"UDRO", "UDZO"} {
						output := filepath.Join(outputRoot, c.ID+"-"+format+".dmg")
						_, err := imageedit.Edit(context.Background(), source, output, imageedit.Options{Format: format, Time: when}, func(editor *imageedit.Editor) error {
							for _, change := range phase5APFSChanges() {
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
						comparePhase5APFS(t, volume, c.Before[0].Files, c.After[0].Files, when)
						compareDirectoryStatistics(t, volume, c.After[0].DirectoryStatistics)
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
