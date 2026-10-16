package acceptance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func catalogFilename(n int) string { return fmt.Sprintf("%03d-", n) + strings.Repeat("x", 100) }
func catalogChanges(phase string) []hfsplus.Change {
	base := "/Fixture/Catalog"
	if phase == "catalog" {
		changes := []hfsplus.Change{{Operation: "mkdir", Path: base + "/A/B", Parents: true, Mode: "0750"}, {Operation: "mkdir", Path: base + "/other"}, {Operation: "mkdir", Path: base + "/obsolete"}}
		for i := range 96 {
			changes = append(changes, hfsplus.Change{Path: base + "/A/B/" + catalogFilename(i), Data: editPattern{"catalog", 8193}})
		}
		return append(changes,
			hfsplus.Change{Path: base + "/obsolete/child", Data: editPattern{"catalog", 8193}}, hfsplus.Change{Path: base + "/caf\u00e9:resource", Data: editPattern{"catalog", 8193}},
			hfsplus.Change{Operation: "mv", Path: "/Fixture/independent", Destination: base + "/forked"}, hfsplus.Change{Operation: "mv", Path: base + "/forked", Destination: base + "/Forked"},
			hfsplus.Change{Operation: "mv", Path: base + "/A/B", Destination: base + "/other/Moved"}, hfsplus.Change{Operation: "mv", Path: base + "/other/Moved/" + catalogFilename(1), Destination: "/Fixture/small"},
			hfsplus.Change{Operation: "mv", Path: "/Fixture/alias", Destination: base + "/linked"}, hfsplus.Change{Operation: "rm", Path: "/Fixture/fragmented-data"}, hfsplus.Change{Operation: "rm", Path: base + "/obsolete", Recursive: true})
	}
	changes := []hfsplus.Change{{Operation: "rm", Path: base + "/linked"}, {Operation: "rm", Path: "/Fixture/inline-compressed"}, {Operation: "rm", Path: "/Fixture/resource-compressed"}}
	for i := 0; i < 96; i += 2 {
		changes = append(changes, hfsplus.Change{Operation: "rm", Path: base + "/other/Moved/" + catalogFilename(i)})
	}
	return append(changes, hfsplus.Change{Operation: "rm", Path: base + "/A", Recursive: true}, hfsplus.Change{Operation: "mkdir", Path: base + "/reused"}, hfsplus.Change{Path: base + "/reused/contents", Data: editPattern{"catalog", 8193}})
}

// Native CNIDs allocated after creation need not match Apple's allocation
// history. Preserve every pre-existing identity and independently compare the
// complete equality partition of native and portable IDs; never erase aliases.
func compareCatalogState(t *testing.T, v *hfsplus.Volume, before fileObservation, want fileObservation, when time.Time) {
	t.Helper()
	ctx := context.Background()
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
		id, err := filesystem.LookupExact(ctx, v, e.Path)
		if err != nil {
			t.Fatal(e.Path, err)
		}
		if other, ok := nativeToGo[e.Object]; ok && other != id {
			t.Fatal("native aliases separated", e.Path)
		}
		if other, ok := goToNative[id]; ok && other != e.Object {
			t.Fatal("distinct native identities conflated", e.Path)
		}
		nativeToGo[e.Object], goToNative[id] = id, e.Object
		source := e.Path
		switch source {
		case "Fixture/Catalog/Forked":
			source = "Fixture/independent"
		case "Fixture/Catalog/linked":
			source = "Fixture/alias"
		case "Fixture/small":
			source = ""
		}
		if old, ok := original[source]; ok && id != old {
			t.Fatal("pre-existing identity lost", e.Path, id, old)
		}
		if _, ok := original[source]; !ok && originalIDs[id] {
			t.Fatal("new entry reused a pre-existing CNID", e.Path, id)
		}
		e.Object = id
		if e.Path == "Fixture" || e.Path == "Fixture/small" || strings.HasPrefix(e.Path, "Fixture/Catalog") {
			e.ChangeNS = when.UnixNano()
			if e.Mode&0170000 == 0040000 {
				e.ModifyNS = when.UnixNano()
			}
		}
	}
	compareFiles(t, v, want)
	// Native raw attribute inventory uses its independently allocated IDs.
	want.RawAttributes = nil
	for _, entry := range want.Entries {
		want.RawAttributes = append(want.RawAttributes, nativeRawAttributes{Object: entry.Object, Attributes: entry.RawAttributes})
	}
	compareEditRawAttributes(t, v, want)
}

func TestNativeHFSImageCatalogEditing(t *testing.T) { t.Parallel(); testCatalogEditing(t, false) }
func TestNativeHFSJournaledImageCatalogEditing(t *testing.T) {
	t.Parallel()
	testCatalogEditing(t, true)
}
func testCatalogEditing(t *testing.T, journaled bool) {
	t.Helper()
	ctx := context.Background()
	env, retained, outputEnv, contract := "APFS_NATIVE_HFS_EDITS", "testdata/hfs-catalog-editing", "APFS_HFS_CATALOG_OUTPUT", "existing-hfs-catalog-edits"
	if journaled {
		env, retained, outputEnv, contract = "APFS_NATIVE_HFS_JOURNALED_EDITS", "testdata/hfs-journaled-catalog-editing", "APFS_HFS_JOURNALED_CATALOG_OUTPUT", "journaled-hfs-catalog-edits"
	}
	root := nativeInput(t, env, retained)
	paths, e := filepath.Glob(filepath.Join(root, "*", "catalog-manifest.json"))
	if e != nil || len(paths) == 0 {
		t.Fatal("required native catalog references absent", e)
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
		if manifest.Schema != 1 || manifest.Contract != contract || len(manifest.Cases) != 2 || len(manifest.Producer.Sources) != 11 || majors[manifest.Major] {
			t.Fatal("native catalog inventory")
		}
		majors[manifest.Major] = true
		dir := filepath.Dir(path)
		verifyDigest(t, dir, "commands.json", manifest.CommandsSHA256)
		for name, digest := range manifest.Producer.Sources {
			verifyDigest(t, dir, name, digest)
		}
		for _, c := range manifest.Cases {
			t.Run(filepath.Base(dir)+"/"+c.ID, func(t *testing.T) {
				source := openEditArchive(t, dir, c.Source)
				originalHash := fileDigest(t, source)
				current := source
				output := os.Getenv(outputEnv)
				if output == "" {
					output = t.TempDir()
				}
				output = filepath.Join(output, filepath.Base(dir), c.ID)
				if e = os.MkdirAll(output, 0700); e != nil {
					t.Fatal(e)
				}
				when := time.Unix(manifest.ModificationSeconds, 0).UTC()
				for _, phase := range []string{"catalog", "catalog-final"} {
					t.Run(phase, func(t *testing.T) {
						state, ok := c.States[phase]
						if !ok || state.CheckerStatus != 0 {
							t.Fatal("native catalog state absent")
						}
						destination := filepath.Join(output, phase+".dmg")
						report, e := imageedit.Apply(ctx, current, destination, imageedit.Options{Format: "UDZO", Time: when}, catalogChanges(phase))
						if e != nil {
							t.Fatal(phase, e)
						}
						repeat := filepath.Join(t.TempDir(), "repeat.dmg")
						if _, e = imageedit.Apply(ctx, current, repeat, imageedit.Options{Format: "UDZO", Time: when}, catalogChanges(phase)); e != nil {
							t.Fatal(e)
						}
						if fileDigest(t, destination) != fileDigest(t, repeat) {
							t.Fatal("catalog operations are not reproducible")
						}
						image, e := diskimage.Open(destination)
						if e != nil {
							t.Fatal(e)
						}
						part, e := image.Partition(0)
						if e != nil {
							t.Fatal(e)
						}
						v, e := hfsplus.Open(part)
						if e != nil {
							t.Fatal(e)
						}
						if v.Journaled != journaled || v.VolumeID != report.VolumeID || v.BlockCount != uint32((64<<20)/4096) {
							t.Fatal("volume identity/profile")
						}
						if e = hfsplus.ValidateMutation(ctx, part); e != nil {
							t.Fatal(e)
						}
						compareCatalogState(t, v, c.Before.Files, state.Files, when)
						verifyEditJournal(t, part, c.Before.Journal)
						var h [512]byte
						if _, e = part.ReadAt(h[:], 1024); e != nil {
							t.Fatal(e)
						}
						if phase == "catalog" && v.FreeBlocks >= c.Before.Headers.Primary.FreeBlocks {
							t.Fatal("catalog/file allocation not exercised")
						}
						image.Close()
						current = destination
						raw := openEditArchive(t, dir, state.Archive)
						native, e := diskimage.Open(raw)
						if e != nil {
							t.Fatal(e)
						}
						p, e := native.Partition(0)
						if e != nil {
							t.Fatal(e)
						}
						nv, e := hfsplus.Open(p)
						if e != nil {
							t.Fatal(e)
						}
						compareFiles(t, nv, state.Files)
						compareEditRawAttributes(t, nv, state.Files)
						native.Close()
					})
				}
				if fileDigest(t, source) != originalHash {
					t.Fatal("catalog editing changed original")
				}
				for _, change := range []hfsplus.Change{{Operation: "mv", Path: "/Fixture", Destination: "/Fixture/Catalog/cycle"}, {Operation: "mkdir", Path: "/Fixture", Parents: false}, {Operation: "rm", Path: "/Fixture", Recursive: false}, {Path: "/Fixture/new-failure", Data: editPattern{"too-big", 1 << 30}}} {
					destination := filepath.Join(t.TempDir(), "failed.dmg")
					if _, e = imageedit.Apply(ctx, source, destination, imageedit.Options{Time: when}, []hfsplus.Change{change}); e == nil {
						t.Fatal("unsafe namespace operation admitted")
					}
					if _, e = os.Stat(destination); !errors.Is(e, fs.ErrNotExist) {
						t.Fatal("failed namespace edit published output", e)
					}
				}
				if fileDigest(t, source) != originalHash {
					t.Fatal("failed catalog editing changed original")
				}
			})
		}
	}
	for _, major := range []int{15, 26, 27} {
		if !majors[major] {
			t.Fatal("required native catalog major absent", major)
		}
	}
}

func TestNativeHFSImageCatalogEditingContinuation(t *testing.T) {
	root := os.Getenv("APFS_HFS_CATALOG_CONTINUATION")
	if root == "" {
		t.Skip("native continuation supplied by disposable VM gate")
	}
	paths, e := filepath.Glob(filepath.Join(root, "*.raw"))
	if e != nil || len(paths) != 6 {
		t.Fatal("complete native catalog continuation inventory", e)
	}
	output := os.Getenv("APFS_HFS_CATALOG_CONTINUED_OUTPUT")
	if output == "" {
		t.Fatal("continued catalog output required")
	}
	if e = os.MkdirAll(output, 0700); e != nil {
		t.Fatal(e)
	}
	for _, source := range paths {
		t.Run(filepath.Base(source), func(t *testing.T) {
			originalHash := fileDigest(t, source)
			destination := filepath.Join(output, strings.TrimSuffix(filepath.Base(source), ".raw")+".dmg")
			changes := []hfsplus.Change{{Operation: "mkdir", Path: "/Fixture/Catalog/continued-go"}, {Path: "/Fixture/Catalog/continued-go/payload", Data: editPattern{"continued-catalog", 8193}}, {Operation: "mv", Path: "/Fixture/Catalog/continued-go/payload", Destination: "/Fixture/Catalog/continued-go/renamed"}, {Operation: "rm", Path: "/Fixture/Catalog/native-created", Recursive: true}}
			if _, e := imageedit.Apply(context.Background(), source, destination, imageedit.Options{Time: time.Unix(1749283750, 0)}, changes); e != nil {
				t.Fatal(e)
			}
			if fileDigest(t, source) != originalHash {
				t.Fatal("failed catalog editing changed original")
			}
		})
	}
}
