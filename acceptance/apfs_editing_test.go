package acceptance_test

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

// The same contract runs against retained evidence and independently refreshed
// CI captures. It proves existing identities and native semantics, not rebuilds.
func TestNativeAPFSImageEditing(t *testing.T) {
	root := os.Getenv("APFS_NATIVE_APFS_EDITS")
	if root == "" {
		root = "testdata/apfs-editing"
	}
	paths, e := filepath.Glob(filepath.Join(root, "macos-*", "manifest.json"))
	if e != nil || len(paths) == 0 {
		t.Fatal("required APFS editing evidence absent", e)
	}
	majors := map[int]bool{}
	for _, manifestPath := range paths {
		var manifest nativeEditManifest
		b, e := os.ReadFile(manifestPath)
		if e != nil {
			t.Fatal(e)
		}
		if e = json.Unmarshal(b, &manifest); e != nil {
			t.Fatal(e)
		}
		if manifest.Schema != 1 || manifest.Contract != "existing-apfs-file-edits" || manifest.CapacityBytes != 128<<20 || len(manifest.Cases) != 2 || len(manifest.Producer.Sources) != 12 || majors[manifest.Major] {
			t.Fatal("invalid native APFS edit inventory")
		}
		majors[manifest.Major] = true
		dir := filepath.Dir(manifestPath)
		verifyDigest(t, dir, "commands.json", manifest.CommandsSHA256)
		for name, digest := range manifest.Producer.Sources {
			verifyDigest(t, dir, name, digest)
		}
		t.Run(filepath.Base(dir), func(t *testing.T) {
			for _, c := range manifest.Cases {
				t.Run(c.ID, func(t *testing.T) {
					ctx := context.Background()
					source := openAPFSEditArchive(t, dir, c.Source)
					before := fileDigest(t, source)
					original := openAPFSEditVolume(t, source)
					compareFiles(t, &original.Volumes[0], c.Before.Files)
					compareAPFSEditAttributes(t, &original.Volumes[0], c.Before.Files)
					output := os.Getenv("APFS_APFS_EDIT_OUTPUT")
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
						for _, phase := range []string{"peak", "final"} {
							state, ok := c.States[phase]
							if !ok || state.CheckerStatus != 0 {
								t.Fatal("missing independent native state")
							}
							changes := apfsEditChanges(phase)
							destination := filepath.Join(output, phase+"-"+format+".dmg")
							report, e := imageedit.Apply(ctx, current, destination, imageedit.Options{Format: format, Time: when}, changes)
							if e != nil {
								t.Fatal(e)
							}
							repeat := filepath.Join(t.TempDir(), "repeat.dmg")
							if _, e = imageedit.Apply(ctx, current, repeat, imageedit.Options{Format: format, Time: when}, changes); e != nil {
								t.Fatal(e)
							}
							if fileDigest(t, repeat) != fileDigest(t, destination) {
								t.Fatal("nonreproducible APFS edit")
							}
							got := openAPFSEditVolume(t, destination)
							if got.UUID != original.UUID || got.Volumes[0].UUID != original.Volumes[0].UUID || got.BlockCount != original.BlockCount || report.Transaction != uint64(got.XID) {
								t.Fatal("APFS identity/geometry/transaction changed")
							}
							want := state.Files
							want.Entries = append([]nativeFile(nil), want.Entries...)
							changed := map[string]bool{"small": true, "inline-compressed": true, "resource-compressed": true, "alias": true, "fragmented-data": true}
							if phase == "final" {
								for _, name := range []string{"fragmented-resource", "empty", "independent"} {
									changed[name] = true
								}
							}
							for i := range want.Entries {
								if changed[strings.TrimPrefix(want.Entries[i].Path, "Fixture/")] {
									want.Entries[i].ChangeNS = when.UnixNano()
								}
							}
							compareFiles(t, &got.Volumes[0], want)
							compareAPFSEditAttributes(t, &got.Volumes[0], want)
							current = destination
						}
					}
					if fileDigest(t, source) != before {
						t.Fatal("APFS edit changed source")
					}
					// Read native-edited allocation states too, keeping expected storage separate.
					for _, phase := range []string{"peak", "final"} {
						state := c.States[phase]
						native := openAPFSEditArchive(t, dir, state.Archive)
						volume := openAPFSEditVolume(t, native)
						compareFiles(t, &volume.Volumes[0], state.Files)
						compareAPFSEditAttributes(t, &volume.Volumes[0], state.Files)
					}
				})
			}
		})
	}
	if required := os.Getenv("APFS_REQUIRED_NATIVE_MAJORS"); required != "" {
		for _, major := range strings.Split(required, ",") {
			found := false
			for n := range majors {
				if major == map[int]string{15: "15", 26: "26", 27: "27"}[n] {
					found = true
				}
			}
			if !found {
				t.Fatal("required native major absent", major)
			}
		}
	} else {
		for _, major := range []int{15, 26, 27} {
			if !majors[major] {
				t.Fatal("required native major absent", major)
			}
		}
	}
}
func apfsEditChanges(phase string) []imageedit.Change {
	changes := editChanges(phase)
	if phase == "peak" {
		changes[1].Mode = ""
		changes = append(changes, imageedit.Change{Path: "/Fixture/small", Mode: "0755"})
	}
	return changes
}
func openAPFSEditVolume(t *testing.T, path string) *apfs.Container {
	t.Helper()
	img, e := diskimage.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { img.Close() })
	part, e := img.Partition(0)
	if e != nil {
		t.Fatal(e)
	}
	if e = apfs.ValidateMutation(context.Background(), part); e != nil {
		t.Fatal(e)
	}
	c, e := apfs.Open(part)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func openAPFSEditArchive(t *testing.T, dir string, a hfsGrowthArchive) string {
	t.Helper()
	if a.UncompressedBytes != 128<<20 {
		t.Fatal("unbounded APFS edit archive")
	}
	verifyDigest(t, dir, a.Image, a.SHA256)
	in, e := os.Open(filepath.Join(dir, a.Image))
	if e != nil {
		t.Fatal(e)
	}
	defer in.Close()
	z, e := gzip.NewReader(in)
	if e != nil {
		t.Fatal(e)
	}
	defer z.Close()
	path := filepath.Join(t.TempDir(), "native.raw")
	out, e := os.Create(path)
	if e != nil {
		t.Fatal(e)
	}
	h := sha256.New()
	n, e := io.Copy(io.MultiWriter(out, h), io.LimitReader(z, (128<<20)+1))
	ce := out.Close()
	if e != nil || ce != nil || n != 128<<20 || hex.EncodeToString(h.Sum(nil)) != a.UncompressedSHA256 {
		t.Fatal("corrupt APFS archive", e, ce)
	}
	return path
}
func compareAPFSEditAttributes(t *testing.T, v *apfs.Volume, want fileObservation) {
	t.Helper()
	for _, entry := range want.Entries {
		listed := map[string]bool{}
		if e := v.ListAttributes(context.Background(), entry.Object, func(name string) error { listed[name] = true; return nil }); e != nil {
			t.Fatal(e)
		}
		// APFS's symlink target record is filesystem-owned and isn't enumerable
		// through Darwin's xattr interface. Readlink already independently checks it.
		delete(listed, "com.apple.fs.symlink")
		for name, expected := range entry.RawAttributes {
			if !listed[name] {
				t.Fatal("native raw attribute missing", entry.Path, name)
			}
			value, e := v.OpenAttribute(context.Background(), entry.Object, name)
			if e != nil {
				t.Fatal(e)
			}
			compareValue(t, name, value, expected)
			delete(listed, name)
		}
		if len(listed) != 0 {
			t.Fatal("unexpected raw APFS attributes", entry.Path, listed)
		}
	}
}

// Native continuation changes the tree and allocator after Go's first edits.
// The next Go transaction must consume that state instead of assuming a layout.
func TestNativeAPFSImageEditingContinuation(t *testing.T) {
	root := os.Getenv("APFS_APFS_EDIT_CONTINUATION")
	if root == "" {
		return
	}
	paths, e := filepath.Glob(filepath.Join(root, "*.raw"))
	if e != nil || len(paths) != 6 {
		t.Fatal("complete APFS continuation inventory required", e)
	}
	output := os.Getenv("APFS_APFS_EDIT_CONTINUED_OUTPUT")
	if e = os.MkdirAll(output, 0700); e != nil {
		t.Fatal(e)
	}
	for _, source := range paths {
		destination := filepath.Join(output, strings.TrimSuffix(filepath.Base(source), ".raw")+".dmg")
		if _, e = imageedit.Apply(context.Background(), source, destination, imageedit.Options{Time: time.Unix(1749283750, 0)}, []imageedit.Change{{Path: "/Fixture/alias", Data: editPattern{"continued-go", 8193}}}); e != nil {
			t.Fatal(e)
		}
		openAPFSEditVolume(t, destination)
	}
}
