package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/pack"
)

type statisticsOperation struct {
	Op, Path, Destination, Mode, Target string
	Size                                int64
	ModifyNS                            int64
}
type statisticsTransitionCase struct {
	ID     string
	Source hfsGrowthArchive
	Before []directoryStatisticsVolume
	States []struct {
		Operation statisticsOperation
		Volumes   []directoryStatisticsVolume
		Archive   hfsGrowthArchive
	}
}
type statisticsTransitionManifest struct {
	apfsGeometryManifest
	Cases []statisticsTransitionCase
}

func statisticsChange(op statisticsOperation) imageedit.Change {
	c := imageedit.Change{Operation: op.Op, Path: path.Clean("/Fixture/" + op.Path), Mode: op.Mode}
	switch op.Op {
	case "create":
		c.Operation, c.Data = "cp", bytes.NewReader(make([]byte, op.Size))
	case "resource-fork":
		c.Operation, c.ResourceFork, c.Data = "cp", true, bytes.NewReader(make([]byte, op.Size))
	case "unlink", "rmdir":
		c.Operation, c.Recursive = "rm", op.Op == "rmdir"
	case "rename":
		c.Operation, c.Destination = "mv", path.Clean("/Fixture/"+op.Destination)
	case "link":
		c.Operation, c.Destination = "ln", path.Clean("/Fixture/"+op.Destination)
	case "symlink":
		c.Operation, c.Path, c.Destination, c.Symbolic = "ln", op.Target, c.Path, true
	case "xattr":
		c.Attribute, c.Data = "org.go-apfs.statistics", bytes.NewReader([]byte("Native metadata transition"))
	case "touch":
		c.Modify = true
		c.Metadata = &filesystem.Metadata{ModifyTime: filesystem.Observed(time.Unix(0, op.ModifyNS))}
	}
	return c
}

func statisticsFiles(state directoryStatisticsVolume) fileObservation {
	result := state.Files
	result.Entries = append(append([]nativeFile(nil), state.Files.Entries...), state.OutsideFiles.Entries...)
	result.Root = "."
	return result
}

func compareStatisticsTransition(t *testing.T, volume *apfs.Volume, original, expected fileObservation, when time.Time, forward, reverse map[uint64]uint64) {
	t.Helper()
	originals := map[uint64]nativeFile{}
	for _, entry := range original.Entries {
		originals[entry.Object] = entry
	}
	expected.Entries = append([]nativeFile(nil), expected.Entries...)
	for n := range expected.Entries {
		entry := &expected.Entries[n]
		id, err := filesystem.LookupExact(context.Background(), volume, entry.Path)
		if err != nil {
			t.Fatal(entry.Path, err)
		}
		if old, ok := forward[entry.Object]; ok && old != id {
			t.Fatal("statistics native identity changed", entry.Path)
		}
		if old, ok := reverse[id]; ok && old != entry.Object {
			t.Fatal("statistics identities conflated", entry.Path)
		}
		forward[entry.Object], reverse[id] = id, entry.Object
		if source, ok := originals[entry.Object]; ok {
			if id != source.Object {
				t.Fatal("statistics original inode replaced", entry.Path)
			}
			if entry.ChangeNS != source.ChangeNS {
				entry.ChangeNS = when.UnixNano()
			}
			if entry.ModifyNS != source.ModifyNS && entry.ModifyNS > when.UnixNano() {
				entry.ModifyNS = when.UnixNano()
			}
		} else {
			if entry.BirthSeconds > when.Unix() {
				entry.BirthSeconds = when.Unix()
				entry.BirthNS = nil
			}
			if entry.ModifyNS > when.UnixNano() {
				entry.ModifyNS = when.UnixNano()
			}
			if entry.AccessNS > when.UnixNano() {
				entry.AccessNS = when.UnixNano()
			}
			entry.ChangeNS = when.UnixNano()
		}
		entry.Object = id
	}
	compareMetadataState(t, volume, expected, "apfs")
}

func TestNativeAPFSDirectoryStatisticsTransitions(t *testing.T) {
	root := nativeInput(t, "APFS_NATIVE_DIRECTORY_STATISTICS_TRANSITIONS", "testdata/apfs-directory-statistics-transitions")
	paths, err := filepath.Glob(filepath.Join(root, "macos-*", "manifest.json"))
	if err != nil || len(paths) == 0 {
		t.Fatal("native statistics transitions absent", err)
	}
	majors := map[int]bool{}
	for _, name := range paths {
		data, err := os.ReadFile(name)
		var manifest statisticsTransitionManifest
		if err != nil || json.Unmarshal(data, &manifest) != nil {
			t.Fatal("native statistics transitions manifest", err)
		}
		if manifest.Contract != "apfs-directory-statistics-transitions" || manifest.Schema != 1 || len(manifest.Cases) != 2 || len(manifest.Producer.Revision) != 40 || manifest.Producer.Run == "" || manifest.Producer.System != "macOS" || manifest.Producer.Build == "" || manifest.Producer.Architecture == "" || len(manifest.Producer.Sources) != 15 || len(manifest.Producer.Tools) != 4 || majors[manifest.Major] {
			t.Fatal("native transition provenance")
		}
		majors[manifest.Major] = true
		dir := filepath.Dir(name)
		if manifest.OriginalManifestSHA256 != "" {
			verifyDigest(t, dir, "original-manifest.json", manifest.OriginalManifestSHA256)
		}
		verifyDigest(t, dir, "commands.json", manifest.CommandsSHA256)
		for source, digest := range manifest.Producer.Sources {
			verifyDigest(t, dir, source, digest)
		}
		t.Run("macos-"+strconv.Itoa(manifest.Major), func(t *testing.T) {
			for _, c := range manifest.Cases {
				t.Run(c.ID, func(t *testing.T) {
					if len(c.Before) != 1 || len(c.States) != 37 {
						t.Fatal("incomplete statistics transitions")
					}
					source := openNativeDiskArchive(t, dir, c.Source)
					original := statisticsFiles(c.Before[0])
					initial := &openAPFSEditVolume(t, source).Volumes[0]
					compareMetadataState(t, initial, original, "apfs")
					compareDirectoryStatistics(t, initial, c.Before[0].DirectoryStatistics)
					forward, reverse := map[uint64]uint64{}, map[uint64]uint64{}
					current := source
					generations := map[uint64]statisticsGeneration{}
					compareStatisticsChanges(t, &openAPFSEditVolume(t, source).Volumes[0], c.Before[0], generations)
					when := time.Unix(1749283750, 0)
					export := func(segment string) {
						root := os.Getenv("APFS_DIRECTORY_STATISTICS_TRANSITIONS_OUTPUT")
						if root == "" {
							return
						}
						root = filepath.Join(root, "macos-"+strconv.Itoa(manifest.Major), c.ID)
						if err := os.MkdirAll(root, 0700); err != nil {
							t.Fatal(err)
						}
						for _, format := range []string{"UDRO", "UDZO"} {
							t.Run(segment+"/"+format, func(t *testing.T) {
								if _, err := pack.Repack(context.Background(), current, filepath.Join(root, segment+"-"+format+".dmg"), format); err != nil {
									t.Fatal("export native statistics check", err)
								}
							})
						}
					}
					for index, state := range c.States {
						t.Logf("operation %d: %+v", index, state.Operation)
						if len(state.Volumes) != 1 {
							t.Fatal("statistics transition volume count")
						}
						verifyDigest(t, dir, state.Archive.Image, state.Archive.SHA256)
						if state.Operation.Op == "compressed" {
							export("before-compression")
							// Existing-image edits preserve/read active compression but
							// do not create it. Apple's original compressed state supplies
							// the independent source for the subsequent deletion segment.
							current = openNativeDiskArchive(t, dir, state.Archive)
							original = statisticsFiles(state.Volumes[0])
							generations = map[uint64]statisticsGeneration{}
							compareStatisticsChanges(t, &openAPFSEditVolume(t, current).Volumes[0], state.Volumes[0], generations)
							forward, reverse = map[uint64]uint64{}, map[uint64]uint64{}
							continue
						}
						output := filepath.Join(t.TempDir(), "step-"+strconv.Itoa(index)+".dmg")
						if _, err := imageedit.Apply(context.Background(), current, output, imageedit.Options{Format: "UDRO", Time: when}, []imageedit.Change{statisticsChange(state.Operation)}); err != nil {
							t.Fatal(index, state.Operation, err)
						}
						volume := &openAPFSEditVolume(t, output).Volumes[0]
						compareStatisticsTransition(t, volume, original, statisticsFiles(state.Volumes[0]), when, forward, reverse)
						compareStatisticsChanges(t, volume, state.Volumes[0], generations)
						current = output
					}
					export("final")
				})
			}
		})
	}
	requireNativeVersions(t, majors)
}
