package acceptance_test

import (
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
	Journal       *nativeEditJournal
	Headers       struct {
		Primary, Alternate hfsGrowthHeader
		ExtentsTree        struct{ NodeSize, TotalNodes uint32 }
	}
}
type nativeEditManifest struct {
	Schema, Major       int
	Contract            string
	CommandsSHA256      string
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

type nativeEditJournal struct {
	InfoBlock          uint32
	Offset, Size       uint64
	SHA256, InfoSHA256 string
	BackingFiles       map[string]struct {
		Object uint64
		Size   int64
	}
}

func verifyEditJournal(t *testing.T, source block.Source, want *nativeEditJournal) {
	t.Helper()
	if want == nil {
		return
	}
	ctx := context.Background()
	v, e := hfsplus.Open(source)
	if e != nil {
		t.Fatal(e)
	}
	h := make([]byte, 512)
	if e = block.ReadFull(source, h, 1024); e != nil {
		t.Fatal(e)
	}
	if !v.Journaled || !v.Clean || string(h[8:12]) != "HFSJ" || binary.BigEndian.Uint32(h[12:]) != want.InfoBlock {
		t.Fatal("journaled volume state lost")
	}
	for _, region := range []struct {
		offset, size uint64
		digest       string
	}{
		{uint64(want.InfoBlock) * uint64(v.BlockSize), uint64(v.BlockSize), want.InfoSHA256},
		{want.Offset, want.Size, want.SHA256},
	} {
		hash := sha256.New()
		if _, e = io.Copy(hash, io.NewSectionReader(source, int64(region.offset), int64(region.size))); e != nil {
			t.Fatal(e)
		}
		if hex.EncodeToString(hash.Sum(nil)) != region.digest {
			t.Fatal("journal storage changed")
		}
	}
	if len(want.BackingFiles) != 2 {
		t.Fatal("native journal backing observations absent")
	}
	for name, file := range want.BackingFiles {
		id, e := filesystem.Lookup(ctx, v, "/"+name)
		if e != nil || id != file.Object {
			t.Fatal("journal backing identity changed", name, e)
		}
		node, e := v.Stat(ctx, id)
		if e != nil || int64(node.Size) != file.Size {
			t.Fatal("journal backing size changed", name, e)
		}
	}
}

// TestNativeHFSImageEditing modifies Apple-created fragmented volumes. It
// compares original identities and native final contents/metadata/forks, forces
// overflow-tree allocation, verifies both headers, and emits actual images for
// independent Apple fsck, mounted readback and further native/Go editing.
func TestNativeHFSImageEditing(t *testing.T) {
	t.Parallel()
	testNativeHFSImageEditing(t, false)
}

// Journaled references independently prove that journal storage and backing
// identities survive offline edits and subsequent native journaling.
func TestNativeHFSJournaledImageEditing(t *testing.T) {
	t.Parallel()
	testNativeHFSImageEditing(t, true)
}

func testNativeHFSImageEditing(t *testing.T, journaled bool) {
	t.Helper()
	contract, rootEnv, outputEnv, retained := "existing-hfs-file-edits", "APFS_NATIVE_HFS_EDITS", "APFS_HFS_EDIT_OUTPUT", "testdata/hfs-editing"
	if journaled {
		contract, rootEnv, outputEnv, retained = "journaled-hfs-file-edits", "APFS_NATIVE_HFS_JOURNALED_EDITS", "APFS_HFS_JOURNALED_EDIT_OUTPUT", "testdata/hfs-journaled-editing"
	}
	ctx := context.Background()
	root := nativeInput(t, rootEnv, retained)
	paths, err := filepath.Glob(filepath.Join(root, "*", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) == 0 {
		t.Fatal("required HFS editing references absent")
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
		if manifest.Schema != 1 || manifest.Contract != contract || manifest.CapacityBytes != 64<<20 || len(manifest.Cases) != 2 || len(manifest.Producer.Sources) != 10 || majors[manifest.Major] {
			t.Fatal("invalid native HFS edit inventory")
		}
		majors[manifest.Major] = true
		dir := filepath.Dir(manifestPath)
		verifyDigest(t, dir, "commands.json", manifest.CommandsSHA256)
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
				if original.Journaled != journaled || (c.Before.Journal != nil) != journaled {
					t.Fatal("native journal profile differs")
				}
				verifyEditJournal(t, p, c.Before.Journal)
				compareFiles(t, original, c.Before.Files)
				compareEditRawAttributes(t, original, c.Before.Files)
				output := os.Getenv(outputEnv)
				if output == "" {
					output = t.TempDir()
				}
				output = filepath.Join(output, filepath.Base(dir), c.ID)
				if e = os.MkdirAll(output, 0700); e != nil {
					t.Fatal(e)
				}
				for _, format := range []string{"UDRO", "UDZO"} {
					t.Run(format, func(t *testing.T) {
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
							if v.VolumeID != original.VolumeID || v.Name != original.Name || v.BlockCount != original.BlockCount || v.BlockSize != original.BlockSize || v.Journaled != original.Journaled {
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
							verifyEditJournal(t, part, c.Before.Journal)
							verifyEditHeaders(t, part, c.Before.Headers.ExtentsTree.TotalNodes, phase)
							img.Close()
							current = destination
						}
					})
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
	if archive.UncompressedBytes != 64<<20 {
		t.Fatal("unbounded edit fixture")
	}
	return decodedNativeArchive(t, dir, archive, 64<<20)
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
