package hfsplus

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/filecompression"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

var mutationTime = time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)

func mutationFixture(t *testing.T, sensitive bool, policy string) []byte {
	t.Helper()
	ctx := context.Background()
	s, err := session.Create(ctx, filepath.Join(t.TempDir(), "session"), session.Options{Names: filesystem.NameRules{Format: "HFS+", CaseSensitive: sensitive, NormalizationInsensitive: true}, Time: &mutationTime})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	for _, entry := range []struct {
		name string
		data []byte
	}{{"small", bytes.Repeat([]byte("small"), 80)}, {"large", bytes.Repeat([]byte("large"), 30000)}, {"untouched", []byte("retained bytes")}} {
		path := filepath.Join(t.TempDir(), entry.name)
		if err = os.WriteFile(path, entry.data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = s.Copy(ctx, []string{path}, "/"+entry.name, session.CopyOptions{FromHost: true}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err = s.Link(ctx, "/large", "/alias", session.LinkOptions{}); err != nil {
		t.Fatal(err)
	}
	var budget int64
	r, err := filecompression.Prepare(ctx, s, policy, t.TempDir(), &budget)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	p, err := Plan(ctx, r, BuildOptions{Name: "Existing", Time: mutationTime, CaseSensitive: sensitive, Capacity: 16 << 20})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = p.Write(ctx, &out); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestModifyExistingFilesPreservesIdentity(t *testing.T) {
	for _, sensitive := range []bool{false, true} {
		for _, policy := range []string{"preserve", "zlib"} {
			t.Run(fmtMutationCase(sensitive, policy), func(t *testing.T) {
				ctx := context.Background()
				original := mutationFixture(t, sensitive, policy)
				v, err := Open(bytes.NewReader(original))
				if err != nil {
					t.Fatal(err)
				}
				id, err := filesystem.Lookup(ctx, v, "/large")
				if err != nil {
					t.Fatal(err)
				}
				before, err := v.Stat(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				disk, err := block.Stage(ctx, bytes.NewReader(original), t.TempDir())
				if err != nil {
					t.Fatal(err)
				}
				defer disk.Close()
				for _, data := range [][]byte{bytes.Repeat([]byte("replacement"), 40000), []byte("shrink"), {}} {
					report, e := Modify(ctx, disk, []Change{{Path: "/alias", Data: bytes.NewReader(data)}, {Path: "/small", Data: bytes.NewReader([]byte("expanded small file"))}, {Path: "/large", Mode: "u=rwx,go=rx"}}, mutationTime.Add(time.Hour))
					if e != nil {
						t.Fatal(e)
					}
					if report.VolumeID != v.VolumeID {
						t.Fatal("volume identity changed")
					}
					if e = ValidateMutation(ctx, disk); e != nil {
						t.Fatal(e)
					}
					after, e := Open(disk)
					if e != nil {
						t.Fatal(e)
					}
					for _, path := range []string{"/large", "/alias"} {
						gotID, e := filesystem.Lookup(ctx, after, path)
						if e != nil {
							t.Fatal(e)
						}
						node, e := after.Stat(ctx, gotID)
						if e != nil {
							t.Fatal(e)
						}
						if node.Identity != before.Identity || node.Links != before.Links || node.Metadata.Mode.Value != 0100755 || node.Compression.State != filesystem.Absent {
							t.Fatalf("identity/metadata: %+v", node)
						}
						value, e := after.OpenData(ctx, gotID)
						if e != nil {
							t.Fatal(e)
						}
						got, e := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
						value.Close()
						if e != nil || !bytes.Equal(got, data) {
							t.Fatal("alias contents differ", e)
						}
					}
				}
				// Resource fork writes retain ordinary data and support empty forks.
				for _, data := range [][]byte{bytes.Repeat([]byte("fork"), 20000), {}} {
					if _, err = Modify(ctx, disk, []Change{{Path: "/large", ResourceFork: true, Data: bytes.NewReader(data)}}, mutationTime); err != nil {
						t.Fatal(err)
					}
					if err = ValidateMutation(ctx, disk); err != nil {
						t.Fatal(err)
					}
				}
			})
		}
	}
}
func fmtMutationCase(sensitive bool, policy string) string {
	if sensitive {
		return "HFSX/" + policy
	}
	return "HFS+/" + policy
}

type shortMutation struct{ block.Source }

func (shortMutation) WriteAt(p []byte, _ int64) (int, error) { return len(p) - 1, nil }

func TestMutationRejectsUnsafeProfilesAndWriteFailures(t *testing.T) {
	ctx := context.Background()
	original := mutationFixture(t, false, "preserve")
	for _, kind := range []string{"journal", "dirty", "bitmap", "alternate", "crosslink", "catalog-map", "shortwrite", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			b := bytes.Clone(original)
			switch kind {
			case "journal":
				be.PutUint32(b[1028:], be.Uint32(b[1028:])|0x2000)
			case "dirty":
				be.PutUint32(b[1028:], be.Uint32(b[1028:])&^0x100)
			case "alternate":
				b[len(b)-1024+272+16] ^= 1
			case "bitmap":
				off := be.Uint32(b[1024+112+16:])
				b[int(off)*4096] ^= 0x80
			case "catalog-map":
				off := int(be.Uint32(b[1024+272+16:])) * 4096
				h := b[off : off+int(be.Uint16(b[off+32:]))]
				start, _, e := recordBounds(h, 2)
				if e != nil {
					t.Fatal(e)
				}
				root := be.Uint32(h[16:])
				// Keep the map's free count internally consistent, but mark the
				// reachable catalog root free. Admission must reject before writing.
				h[start+int(root/8)] &^= 0x80 >> (root % 8)
				be.PutUint32(h[40:], be.Uint32(h[40:])+1)
			case "crosslink":
				v, e := Open(bytes.NewReader(b))
				if e != nil {
					t.Fatal(e)
				}
				id, e := filesystem.Lookup(ctx, v, "/small")
				if e != nil {
					t.Fatal(e)
				}
				record, e := v.catalogRecord(ctx, id)
				if e != nil {
					t.Fatal(e)
				}
				// Alter only the small file's physical extent, retaining its count.
				large, e := filesystem.Lookup(ctx, v, "/large")
				if e != nil {
					t.Fatal(e)
				}
				other, e := v.catalogRecord(ctx, large)
				if e != nil {
					t.Fatal(e)
				}
				be.PutUint32(record[104:], be.Uint32(other[104:]))
				copyAt := &memoryMutation{b}
				m := &mutation{ctx: ctx, disk: copyAt, v: v}
				if e = m.patchCatalog(uint32(id), record); e != nil {
					t.Fatal(e)
				}
			}
			disk, e := block.Stage(ctx, bytes.NewReader(b), t.TempDir())
			if e != nil {
				t.Fatal(e)
			}
			defer disk.Close()
			var target MutableSource = disk
			testCtx := ctx
			if kind == "shortwrite" {
				target = shortMutation{disk}
			}
			if kind == "cancel" {
				c, stop := context.WithCancel(ctx)
				stop()
				testCtx = c
			}
			_, e = Modify(testCtx, target, []Change{{Path: "/small", Data: bytes.NewReader([]byte("new"))}}, mutationTime)
			if e == nil {
				t.Fatal("unsafe mutation admitted")
			}
			if kind == "shortwrite" && !errors.Is(e, io.ErrShortWrite) {
				t.Fatal(e)
			}
			if kind == "cancel" && !errors.Is(e, context.Canceled) {
				t.Fatal(e)
			}
			if kind == "journal" || kind == "dirty" {
				if !errors.Is(e, filesystem.ErrUnsupported) {
					t.Fatal(e)
				}
			}
			if kind != "shortwrite" {
				got := make([]byte, len(b))
				if e = block.ReadFull(disk, got, 0); e != nil {
					t.Fatal(e)
				}
				if !bytes.Equal(got, b) {
					t.Fatal("failed admission wrote disk")
				}
			}
		})
	}
}

type memoryMutation struct{ data []byte }

func (m *memoryMutation) Size() int64 { return int64(len(m.data)) }
func (m *memoryMutation) ReadAt(p []byte, o int64) (int, error) {
	return bytes.NewReader(m.data).ReadAt(p, o)
}
func (m *memoryMutation) WriteAt(p []byte, o int64) (int, error) {
	if o < 0 || o > int64(len(m.data)) || int64(len(p)) > int64(len(m.data))-o {
		return 0, fs.ErrInvalid
	}
	return copy(m.data[o:], p), nil
}
