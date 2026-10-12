package acceptance_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func apfsDirectoryChanges(phase string) []imageedit.Change {
	changes := catalogChanges(phase)
	if phase == "catalog" {
		changes = append(changes, imageedit.Change{Operation: "mv", Path: "/Fixture/symlink", Destination: "/Fixture/Catalog"}, imageedit.Change{Operation: "mv", Path: "/Fixture/dir-link", Destination: "/Fixture/Catalog"}, imageedit.Change{Operation: "chmod", Path: "/Fixture/Catalog/other", Mode: "0751"})
	} else {
		changes = append(changes, imageedit.Change{Operation: "rm", Path: "/Fixture/Catalog/symlink", Recursive: true}, imageedit.Change{Operation: "rm", Path: "/Fixture/Catalog/dir-link", Recursive: true})
	}
	return changes
}

// New inode numbers depend on native allocation history. Check a bijection of
// identity relationships while requiring all surviving original IDs unchanged.
func compareAPFSDirectoryState(t *testing.T, v *apfs.Volume, before, want fileObservation, when time.Time) {
	t.Helper()
	original := map[string]uint64{}
	originalIDs := map[uint64]bool{}
	for _, e := range before.Entries {
		original[e.Path] = e.Object
		originalIDs[e.Object] = true
	}
	want.Entries = append([]nativeFile(nil), want.Entries...)
	nativeToGo, goToNative := map[uint64]uint64{}, map[uint64]uint64{}
	for i := range want.Entries {
		e := &want.Entries[i]
		id, err := filesystem.LookupExact(context.Background(), v, e.Path)
		if err != nil {
			t.Fatal(e.Path, err)
		}
		if other, ok := nativeToGo[e.Object]; ok && other != id {
			t.Fatal("native aliases separated", e.Path)
		}
		if other, ok := goToNative[id]; ok && other != e.Object {
			t.Fatal("distinct native objects conflated", e.Path)
		}
		nativeToGo[e.Object], goToNative[id] = id, e.Object
		source := e.Path
		switch source {
		case "Fixture/Catalog/Forked":
			source = "Fixture/independent"
		case "Fixture/Catalog/linked":
			source = "Fixture/alias"
		case "Fixture/Catalog/symlink":
			source = "Fixture/symlink"
		case "Fixture/Catalog/dir-link":
			source = "Fixture/dir-link"
		case "Fixture/small":
			source = ""
		}
		if old, ok := original[source]; ok {
			if id != old {
				t.Fatal("surviving original identity changed", e.Path, id, old)
			}
		} else if originalIDs[id] {
			t.Fatal("new file reused original inode", e.Path, id)
		}
		e.Object = id
		if e.Path == "Fixture" || e.Path == "Fixture/small" || e.Path == "Fixture/third" || strings.HasPrefix(e.Path, "Fixture/Catalog") {
			e.ChangeNS = when.UnixNano()
			if e.Mode&0170000 == 0040000 {
				e.ModifyNS = when.UnixNano()
			}
		}
	}
	compareFiles(t, v, want)
	compareAPFSEditAttributes(t, v, want)
}
func TestNativeAPFSImageDirectoryEditing(t *testing.T) {
	root := os.Getenv("APFS_NATIVE_APFS_DIRECTORY_EDITS")
	if root == "" {
		root = "testdata/apfs-directory-editing"
	}
	paths, e := filepath.Glob(filepath.Join(root, "macos-*", "manifest.json"))
	if e != nil || len(paths) == 0 {
		t.Fatal("required APFS directory evidence absent", e)
	}
	majors := map[int]bool{}
	for _, path := range paths {
		var manifest nativeEditManifest
		b, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(b, &manifest); e != nil {
			t.Fatal(e)
		}
		if manifest.Schema != 1 || manifest.Contract != "existing-apfs-directory-edits" || manifest.CapacityBytes != 128<<20 || len(manifest.Cases) != 2 || len(manifest.Producer.Sources) != 13 || majors[manifest.Major] {
			t.Fatal("invalid APFS directory inventory")
		}
		majors[manifest.Major] = true
		dir := filepath.Dir(path)
		verifyDigest(t, dir, "commands.json", manifest.CommandsSHA256)
		for name, digest := range manifest.Producer.Sources {
			verifyDigest(t, dir, name, digest)
		}
		for _, c := range manifest.Cases {
			t.Run(filepath.Base(dir)+"/"+c.ID, func(t *testing.T) {
				source := openAPFSEditArchive(t, dir, c.Source)
				originalHash := fileDigest(t, source)
				original := openAPFSEditVolume(t, source)
				compareFiles(t, &original.Volumes[0], c.Before.Files)
				compareAPFSEditAttributes(t, &original.Volumes[0], c.Before.Files)
				output := os.Getenv("APFS_APFS_DIRECTORY_OUTPUT")
				if output == "" {
					output = t.TempDir()
				}
				output = filepath.Join(output, filepath.Base(dir), c.ID)
				if e = os.MkdirAll(output, 0700); e != nil {
					t.Fatal(e)
				}
				when := time.Unix(manifest.ModificationSeconds, 0).UTC()
				for _, format := range []string{"UDRO", "UDZO"} {
					current := source
					for _, phase := range []string{"catalog", "catalog-final"} {
						state, ok := c.States[phase]
						if !ok || state.CheckerStatus != 0 {
							t.Fatal("native directory state missing")
						}
						destination := filepath.Join(output, phase+"-"+format+".dmg")
						changes := apfsDirectoryChanges(phase)
						report, e := imageedit.Apply(context.Background(), current, destination, imageedit.Options{Format: format, Time: when}, changes)
						if e != nil {
							t.Fatal(phase, e)
						}
						repeat := filepath.Join(t.TempDir(), "repeat.dmg")
						if _, e = imageedit.Apply(context.Background(), current, repeat, imageedit.Options{Format: format, Time: when}, changes); e != nil {
							t.Fatal(e)
						}
						if fileDigest(t, repeat) != fileDigest(t, destination) {
							t.Fatal("nonreproducible directory edits")
						}
						got := openAPFSEditVolume(t, destination)
						if got.UUID != original.UUID || got.Volumes[0].UUID != original.Volumes[0].UUID || got.BlockCount != original.BlockCount || report.Transaction != uint64(got.XID) {
							t.Fatal("container identity/geometry changed")
						}
						compareAPFSDirectoryState(t, &got.Volumes[0], c.Before.Files, state.Files, when)
						current = destination
					}
				}
				for _, phase := range []string{"catalog", "catalog-final"} {
					state := c.States[phase]
					native := openAPFSEditVolume(t, openAPFSEditArchive(t, dir, state.Archive))
					compareFiles(t, &native.Volumes[0], state.Files)
					compareAPFSEditAttributes(t, &native.Volumes[0], state.Files)
				}
				for _, change := range []imageedit.Change{{Operation: "mv", Path: "/Fixture", Destination: "/Fixture/guards/cycle"}, {Operation: "mkdir", Path: "/Fixture"}, {Operation: "rm", Path: "/Fixture"}, {Path: "/Fixture/new-full", Data: editPattern{"full", 1 << 30}}, {Operation: "cp", Path: "/Fixture/small", NoClobber: true, Data: editPattern{"copy", 1}}} {
					destination := filepath.Join(t.TempDir(), "failed.dmg")
					if _, e = imageedit.Apply(context.Background(), source, destination, imageedit.Options{Time: when}, []imageedit.Change{change}); e == nil {
						t.Fatal("unsafe directory edit admitted", change.Operation)
					}
					if _, e = os.Stat(destination); !errors.Is(e, fs.ErrNotExist) {
						t.Fatal("failed edit published output", e)
					}
				}
				if fileDigest(t, source) != originalHash {
					t.Fatal("directory edits changed source")
				}
			})
		}
	}
	required := os.Getenv("APFS_REQUIRED_NATIVE_MAJORS")
	if required == "" {
		required = "15,26,27"
	}
	for _, s := range strings.Split(required, ",") {
		if !majors[map[string]int{"15": 15, "26": 26, "27": 27}[s]] {
			t.Fatal("required native directory major absent", s)
		}
	}
}
func TestNativeAPFSImageDirectoryEditingContinuation(t *testing.T) {
	root := os.Getenv("APFS_APFS_DIRECTORY_CONTINUATION")
	if root == "" {
		return
	}
	paths, e := filepath.Glob(filepath.Join(root, "*.raw"))
	if e != nil || len(paths) != 6 {
		t.Fatal("complete APFS directory continuation inventory", e)
	}
	output := os.Getenv("APFS_APFS_DIRECTORY_CONTINUED_OUTPUT")
	if e = os.MkdirAll(output, 0700); e != nil {
		t.Fatal(e)
	}
	for _, source := range paths {
		destination := filepath.Join(output, strings.TrimSuffix(filepath.Base(source), ".raw")+".dmg")
		changes := []imageedit.Change{{Operation: "mkdir", Path: "/Fixture/Catalog/continued-go"}, {Path: "/Fixture/Catalog/continued-go/payload", Data: editPattern{"continued-catalog", 8193}}, {Operation: "mv", Path: "/Fixture/Catalog/continued-go/payload", Destination: "/Fixture/Catalog/continued-go/renamed"}, {Operation: "rm", Path: "/Fixture/Catalog/native-dir-link", Recursive: true}, {Operation: "rm", Path: "/Fixture/Catalog/native-created", Recursive: true}, {Operation: "rm", Path: "/Fixture/third"}}
		if _, e = imageedit.Apply(context.Background(), source, destination, imageedit.Options{Time: time.Unix(1749283750, 0)}, changes); e != nil {
			t.Fatal(e)
		}
		openAPFSEditVolume(t, destination)
	}
}
