package acceptance_test

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
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

type nativeEditState struct {
	Files         fileObservation
	Archive       hfsGrowthArchive
	CheckerStatus int
	Headers       struct {
		Primary, Alternate hfsGrowthHeader
		ExtentsTree        struct{ NodeSize, TotalNodes uint32 }
	}
}
type nativeEditManifest struct {
	Schema, Major       int
	Contract            string
	ModificationSeconds int64
	CapacityBytes       int64
	Producer            struct {
		Sources        map[string]string
		Version, Build string
	}
	Cases []struct {
		ID     string
		Source hfsGrowthArchive
		Before nativeEditState
		States map[string]nativeEditState
	}
}

// TestNativeHFSImageEditing modifies Apple-created fragmented volumes. It
// compares original identities and native final contents/metadata/forks, forces
// overflow-tree allocation, verifies both headers, and emits actual images for
// independent Apple fsck, mounted readback and further native/Go editing.
func TestNativeHFSImageEditing(t *testing.T) {
	ctx := context.Background()
	root := os.Getenv("APFS_NATIVE_HFS_EDITS")
	if root == "" {
		root = "testdata/hfs-editing"
	}
	paths, err := filepath.Glob(filepath.Join(root, "*", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		if os.Getenv("APFS_NATIVE_HFS_EDITS") != "" {
			t.Fatal("required HFS editing references absent")
		}
		t.Skip("native HFS edit corpus not retained yet")
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
		if manifest.Schema != 1 || manifest.Contract != "existing-hfs-file-edits" || manifest.CapacityBytes != 64<<20 || len(manifest.Cases) != 2 || len(manifest.Producer.Sources) != 8 || majors[manifest.Major] {
			t.Fatal("invalid native HFS edit inventory")
		}
		majors[manifest.Major] = true
		dir := filepath.Dir(manifestPath)
		for name, digest := range manifest.Producer.Sources {
			verifyDigest(t, dir, name, digest)
		}
		for _, c := range manifest.Cases {
			t.Run(filepath.Base(dir)+"/"+c.ID, func(t *testing.T) {
				source := openEditArchive(t, dir, c.Source)
				sourceHash := fileDigest(t, source)
				input, e := diskimage.Open(source)
				if e != nil {
					t.Fatal(e)
				}
				p, e := input.Partition(0)
				if e != nil {
					t.Fatal(e)
				}
				original, e := hfsplus.Open(p)
				if e != nil {
					t.Fatal(e)
				}
				defer input.Close()
				compareFiles(t, original, c.Before.Files)
				compareEditRawAttributes(t, original, c.Before.Files)
				output := os.Getenv("APFS_HFS_EDIT_OUTPUT")
				if output == "" {
					output = t.TempDir()
				}
				output = filepath.Join(output, filepath.Base(dir), c.ID)
				if e = os.MkdirAll(output, 0700); e != nil {
					t.Fatal(e)
				}
				for _, format := range []string{"UDRO", "UDZO"} {
					current := source
					for _, phase := range []string{"peak", "final"} {
						state, ok := c.States[phase]
						if !ok || state.CheckerStatus != 0 {
							t.Fatal("native state/checker missing")
						}
						changes := editChanges(phase)
						when := time.Unix(manifest.ModificationSeconds, 0).UTC()
						destination := filepath.Join(output, phase+"-"+format+".dmg")
						if _, e = imageedit.Apply(ctx, current, destination, imageedit.Options{Format: format, Time: when}, changes); e != nil {
							t.Fatal(e)
						}
						repeat := filepath.Join(t.TempDir(), "repeat.dmg")
						if _, e = imageedit.Apply(ctx, current, repeat, imageedit.Options{Format: format, Time: when}, changes); e != nil {
							t.Fatal(e)
						}
						if fileDigest(t, repeat) != fileDigest(t, destination) {
							t.Fatal("nonreproducible image edits")
						}
						img, e := diskimage.Open(destination)
						if e != nil {
							t.Fatal(e)
						}
						part, e := img.Partition(0)
						if e != nil {
							t.Fatal(e)
						}
						v, e := hfsplus.Open(part)
						if e != nil {
							t.Fatal(e)
						}
						if v.VolumeID != original.VolumeID || v.Name != original.Name || v.BlockCount != original.BlockCount || v.BlockSize != original.BlockSize {
							t.Fatal("existing volume identity or geometry changed")
						}
						if e = hfsplus.ValidateMutation(ctx, part); e != nil {
							t.Fatal(e)
						}
						want := state.Files
						changed := map[uint64]bool{}
						for _, op := range changes {
							id, e := filesystem.Lookup(ctx, v, op.Path)
							if e != nil {
								t.Fatal(e)
							}
							changed[id] = true
						}
						// Native ctime records the CI clock. Offline edits intentionally
						// use an explicit clock; all other observations remain native.
						want.Entries = append([]nativeFile(nil), want.Entries...)
						for i := range want.Entries {
							if changed[want.Entries[i].Object] {
								want.Entries[i].ChangeNS = when.UnixNano()
							}
						}
						if phase == "final" {
							for i := range want.Entries {
								if strings.HasSuffix(want.Entries[i].Path, "/small") || strings.HasSuffix(want.Entries[i].Path, "/inline-compressed") || strings.HasSuffix(want.Entries[i].Path, "/resource-compressed") {
									want.Entries[i].ChangeNS = when.UnixNano()
								}
							}
						}
						compareFiles(t, v, want)
						compareEditRawAttributes(t, v, want)
						for _, entry := range want.Entries {
							beforeID, e := filesystem.Lookup(ctx, original, entry.Path)
							if e != nil || beforeID != entry.Object {
								t.Fatal("native file identity lost", entry.Path, e)
							}
						}
						verifyEditHeaders(t, part, c.Before.Headers.ExtentsTree.TotalNodes, phase)
						img.Close()
						current = destination
					}
				}
				if fileDigest(t, source) != sourceHash {
					t.Fatal("source changed")
				}
				for _, phase := range []string{"peak", "final"} {
					state := c.States[phase]
					raw := openEditArchive(t, dir, state.Archive)
					img, e := diskimage.Open(raw)
					if e != nil {
						t.Fatal(e)
					}
					part, e := img.Partition(0)
					if e != nil {
						t.Fatal(e)
					}
					v, e := hfsplus.Open(part)
					if e != nil {
						t.Fatal(e)
					}
					compareFiles(t, v, state.Files)
					compareEditRawAttributes(t, v, state.Files)
					img.Close()
				}
			})
		}
	}
	for _, major := range []int{15, 26, 27} {
		if !majors[major] {
			t.Fatal("required native major absent", major)
		}
	}
}

type editPattern struct {
	label string
	size  int64
}

func (p editPattern) Size() int64 { return p.size }
func (p editPattern) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if off >= p.size && len(b) > 0 {
		return 0, io.EOF
	}
	pattern := make([]byte, 256, 300)
	for i := range pattern {
		pattern[i] = byte(i)
	}
	pattern = append(pattern, p.label...)
	pattern = append(pattern, '\n')
	n := min(int64(len(b)), p.size-off)
	for i := int64(0); i < n; i++ {
		b[i] = pattern[(off+i)%int64(len(pattern))]
	}
	if n < int64(len(b)) {
		return int(n), io.EOF
	}
	return int(n), nil
}
func editChanges(phase string) []hfsplus.Change {
	if phase == "peak" {
		return []hfsplus.Change{{Path: "/Fixture/alias", Data: editPattern{"grow", 20 << 20}}, {Path: "/Fixture/small", Data: editPattern{"small", 7000}, Mode: "0755"}, {Path: "/Fixture/inline-compressed", Data: editPattern{"inline", 7000}}, {Path: "/Fixture/resource-compressed", Data: editPattern{"resource", 100000}}}
	}
	return []hfsplus.Change{{Path: "/Fixture/fragmented-data", Data: editPattern{"shrink", 513}}, {Path: "/Fixture/fragmented-resource", ResourceFork: true, Data: editPattern{"fork", 131073}}, {Path: "/Fixture/empty", Data: editPattern{"empty", 0}}, {Path: "/Fixture/independent", Data: editPattern{"independent", 65537}}}
}

func openEditArchive(t *testing.T, dir string, archive hfsGrowthArchive) string {
	t.Helper()
	verifyDigest(t, dir, archive.Image, archive.SHA256)
	if archive.UncompressedBytes != 64<<20 {
		t.Fatal("unbounded edit fixture")
	}
	in, e := os.Open(filepath.Join(dir, archive.Image))
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
	hash := sha256.New()
	n, e := io.Copy(io.MultiWriter(out, hash), io.LimitReader(z, (64<<20)+1))
	closeErr := out.Close()
	if e != nil || closeErr != nil || n != 64<<20 || hex.EncodeToString(hash.Sum(nil)) != archive.UncompressedSHA256 {
		t.Fatal("native edit archive corrupt", n, e, closeErr)
	}
	return path
}

func compareEditRawAttributes(t *testing.T, r filesystem.Reader, want fileObservation) {
	t.Helper()
	seen := map[uint64]bool{}
	for _, entry := range want.RawAttributes {
		if seen[entry.Object] {
			continue
		}
		seen[entry.Object] = true
		listed := map[string]bool{}
		if e := r.ListAttributes(context.Background(), entry.Object, func(name string) error { listed[name] = true; return nil }); e != nil {
			t.Fatal(e)
		}
		expected := map[string]bool{}
		for name, value := range entry.Attributes {
			expected[name] = true
			got, e := r.OpenAttribute(context.Background(), entry.Object, name)
			if e != nil {
				t.Fatal(e)
			}
			compareValue(t, name, got, value)
		}
		if !reflect.DeepEqual(listed, expected) {
			t.Fatal("raw attribute storage diverged", entry.Object, listed, expected)
		}
	}
}

func verifyEditHeaders(t *testing.T, source block.Source, before uint32, phase string) {
	t.Helper()
	primary, alternate := make([]byte, 512), make([]byte, 512)
	if e := block.ReadFull(source, primary, 1024); e != nil {
		t.Fatal(e)
	}
	if e := block.ReadFull(source, alternate, source.Size()-1024); e != nil {
		t.Fatal(e)
	}
	if !reflect.DeepEqual(primary, alternate) {
		t.Fatal("edited volume headers differ")
	}
	if phase == "peak" {
		b := make([]byte, 512)
		off := int64(binary.BigEndian.Uint32(primary[208:])) * int64(binary.BigEndian.Uint32(primary[40:]))
		if e := block.ReadFull(source, b, off); e != nil {
			t.Fatal(e)
		}
		if binary.BigEndian.Uint32(b[36:]) <= before {
			t.Fatal("native fixture did not force overflow-tree fork growth", before, binary.BigEndian.Uint32(b[36:]))
		}
	}
}

// Read native-modified outputs returned from the independent readback gate.
func TestNativeHFSImageEditingContinuation(t *testing.T) {
	root := os.Getenv("APFS_HFS_EDIT_CONTINUATION")
	if root == "" {
		t.Skip("native continuation gate supplies this corpus")
	}
	paths, e := filepath.Glob(filepath.Join(root, "*.raw"))
	if e != nil || len(paths) == 0 {
		t.Fatal("native continuations absent", e)
	}
	for _, path := range paths {
		t.Run(filepath.Base(path), func(t *testing.T) {
			img, e := diskimage.Open(path)
			if e != nil {
				t.Fatal(e)
			}
			defer img.Close()
			p, e := img.Partition(0)
			if e != nil {
				t.Fatal(e)
			}
			if e = hfsplus.ValidateMutation(context.Background(), p); e != nil {
				t.Fatal(e)
			}
			v, e := hfsplus.Open(p)
			if e != nil {
				t.Fatal(e)
			}
			id, e := filesystem.Lookup(context.Background(), v, "/Fixture/alias")
			if e != nil {
				t.Fatal(e)
			}
			value, e := v.OpenData(context.Background(), id)
			if e != nil {
				t.Fatal(e)
			}
			defer value.Close()
			b := make([]byte, value.Size())
			if _, e = value.ReadAt(b, 0); e != nil && !errors.Is(e, io.EOF) {
				t.Fatal(e)
			}
			if !strings.HasSuffix(string(b), "native continuation\n") {
				t.Fatal("native alias continuation not visible")
			}
			out := filepath.Join(os.Getenv("APFS_HFS_EDIT_CONTINUED_OUTPUT"), filepath.Base(path)+".dmg")
			if _, e = imageedit.Apply(context.Background(), path, out, imageedit.Options{Time: time.Unix(1749283750, 0)}, []hfsplus.Change{{Path: "/Fixture/alias", Data: editPattern{"continued-go", 8193}}}); e != nil {
				t.Fatal(e)
			}
		})
	}
}
