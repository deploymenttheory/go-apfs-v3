package workspace

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
	"github.com/deploymenttheory/go-apfs-v3/pack"
)

// stagedTree is a minimal in-memory source for pack. It stages the entries the
// tests look up: a hard-linked file, a name needing host mapping and a symlink.
type stagedTree struct {
	nodes    map[uint64]filesystem.Node
	children map[uint64][]filesystem.DirEntry
	data     map[uint64][]byte
	attrs    map[uint64]map[string][]byte
	targets  map[uint64]string
}

type stagedValue struct{ *bytes.Reader }

func (stagedValue) Close() error { return nil }

func newStagedTree() *stagedTree {
	when := time.Date(2026, 10, 10, 1, 2, 3, 0, time.UTC)
	tree := &stagedTree{nodes: map[uint64]filesystem.Node{}, children: map[uint64][]filesystem.DirEntry{}, data: map[uint64][]byte{}, attrs: map[uint64]map[string][]byte{}, targets: map[uint64]string{}}
	add := func(id uint64, mode uint32, size int) {
		tree.nodes[id] = filesystem.Node{Identity: filesystem.Identity{Object: id}, Size: uint64(size), Links: filesystem.Observed(uint32(1)), Compression: filesystem.Observation[filesystem.Compression]{State: filesystem.Absent}, Metadata: filesystem.Metadata{
			Mode: filesystem.Observed(mode), UID: filesystem.Observed(uint32(501)), GID: filesystem.Observed(uint32(20)), BSDFlags: filesystem.Observed(uint32(0)),
			BirthTime: filesystem.Observed(when), ModifyTime: filesystem.Observed(when), ChangeTime: filesystem.Observed(when), AccessTime: filesystem.Observed(when),
		}}
	}
	add(1, 0040755, 0)
	add(2, 0040755, 0)
	tree.data[3] = []byte("staged payload shared by two names\n")
	add(3, 0100644, len(tree.data[3]))
	tree.nodes[3] = func(n filesystem.Node) filesystem.Node { n.Links = filesystem.Observed(uint32(2)); return n }(tree.nodes[3])
	tree.attrs[3] = map[string][]byte{"org.go-apfs.link": []byte("attribute carried by both names"), filesystem.ResourceFork: bytes.Repeat([]byte("fork"), 300)}
	tree.data[4] = []byte("reserved host name\n")
	add(4, 0100644, len(tree.data[4]))
	add(5, 0120755, 0)
	tree.targets[5] = "alias"
	tree.children[1] = []filesystem.DirEntry{{Name: "Fixture", Object: 2}}
	tree.children[2] = []filesystem.DirEntry{{Name: "alias", Object: 3}, {Name: "second", Object: 3}, {Name: "CON", Object: 4}, {Name: "link", Object: 5}}
	return tree
}

func (tree *stagedTree) Root() uint64 { return 1 }
func (tree *stagedTree) NameRules() filesystem.NameRules {
	return filesystem.NameRules{Format: "APFS", CaseSensitive: true, NormalizationInsensitive: true}
}
func (tree *stagedTree) Stat(_ context.Context, id uint64) (filesystem.Node, error) {
	n, ok := tree.nodes[id]
	if !ok {
		return filesystem.Node{}, fs.ErrNotExist
	}
	return n, nil
}
func (tree *stagedTree) ReadDir(_ context.Context, id uint64, yield func(filesystem.DirEntry) error) error {
	for _, e := range tree.children[id] {
		if err := yield(e); err != nil {
			return err
		}
	}
	return nil
}
func (tree *stagedTree) Lookup(_ context.Context, id uint64, name string) (filesystem.DirEntry, error) {
	for _, e := range tree.children[id] {
		if e.Name == name {
			return e, nil
		}
	}
	return filesystem.DirEntry{}, fs.ErrNotExist
}
func (tree *stagedTree) OpenData(_ context.Context, id uint64) (filesystem.Value, error) {
	b, ok := tree.data[id]
	if !ok {
		return nil, fs.ErrInvalid
	}
	return stagedValue{bytes.NewReader(b)}, nil
}
func (tree *stagedTree) OpenRawData(ctx context.Context, id uint64) (filesystem.Value, error) {
	return tree.OpenData(ctx, id)
}
func (tree *stagedTree) ListAttributes(_ context.Context, id uint64, yield func(string) error) error {
	names := make([]string, 0, len(tree.attrs[id]))
	for name := range tree.attrs[id] {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if err := yield(name); err != nil {
			return err
		}
	}
	return nil
}
func (tree *stagedTree) OpenAttribute(_ context.Context, id uint64, name string) (filesystem.Value, error) {
	b, ok := tree.attrs[id][name]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return stagedValue{bytes.NewReader(b)}, nil
}
func (tree *stagedTree) Readlink(_ context.Context, id uint64) (string, error) {
	target, ok := tree.targets[id]
	if !ok {
		return "", fs.ErrInvalid
	}
	return target, nil
}

// sourceTree packs the staged tree into a case-sensitive APFS image with the
// product and reads it back, so workspace ownership and conflict controls run
// against a real filesystem reader. Native contents belong to acceptance.
func sourceTree(t *testing.T) (filesystem.Reader, uint64) {
	t.Helper()
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "staged.dmg")
	when := time.Date(2026, 10, 10, 1, 2, 3, 0, time.UTC)
	if _, err := pack.Create(ctx, path, newStagedTree(), pack.Options{Format: "UDRO", Volume: pack.VolumeOptions{Name: "Staged", CaseSensitive: true, Time: when, Capacity: 8 << 20}}); err != nil {
		t.Fatal(err)
	}
	image, err := diskimage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := image.Close(); err != nil {
			t.Error(err)
		}
	})
	report, err := inspect.Image(ctx, image)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range report.Partitions {
		if p.APFS != nil {
			r := &p.APFS.Volumes[0]
			id, err := filesystem.Lookup(ctx, r, "Fixture")
			if err != nil {
				t.Fatal(err)
			}
			return r, id
		}
	}
	t.Fatal("missing built filesystem")
	return nil, 0
}

// This checks workspace ownership/conflicts against an existing native source.
// Independent native contents and cross-host extraction belong to acceptance.
func TestWorkspacePreservesReaderAndRejectsExternalChanges(t *testing.T) {
	r, root := sourceTree(t)
	ctx := context.Background()
	dir := filepath.Join(t.TempDir(), "workspace")
	report, err := Extract(ctx, r, root, dir, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Objects == 0 || report.MappedNames == 0 || report.HardLinks+report.HardLinksCopied == 0 {
		t.Fatal("missing preservation outcomes", report)
	}
	w, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	for _, o := range w.document.Objects {
		original, err := r.Stat(ctx, o.Node.Identity.Object)
		if err != nil || !reflect.DeepEqual(original, o.Node) {
			t.Fatal("source metadata changed", err)
		}
	}
	id, err := filesystem.Lookup(ctx, w, "alias")
	if err != nil {
		t.Fatal(err)
	}
	value, err := w.OpenData(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err = w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = value.ReadAt(make([]byte, 1), 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("borrowed value survived owner", err)
	}
	if err = value.Close(); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(dir, "files", "unexpected"), []byte("external"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Open(ctx, dir); !errors.Is(err, filesystem.ErrConflict) {
		t.Fatal("unrecorded host content accepted", err)
	}
	if _, err = Extract(ctx, r, root, dir, Limits{}); !errors.Is(err, fs.ErrExist) {
		t.Fatal("existing destination replaced", err)
	}
}

type badTree struct {
	filesystem.Reader
	root    uint64
	name    string
	failure error
}

func (r badTree) ReadDir(ctx context.Context, id uint64, yield func(filesystem.DirEntry) error) error {
	if id == r.root {
		if r.failure != nil {
			return r.failure
		}
		return yield(filesystem.DirEntry{Name: r.name, Object: r.root})
	}
	return r.Reader.ReadDir(ctx, id, yield)
}

func TestExtractionFailuresDoNotPublish(t *testing.T) {
	r, root := sourceTree(t)
	for _, tc := range []struct {
		name   string
		reader filesystem.Reader
		limits Limits
		want   error
	}{
		{"source-escape", badTree{r, root, "../escape", nil}, Limits{}, filesystem.ErrCorrupt},
		{"directory-cycle", badTree{r, root, "cycle", nil}, Limits{}, filesystem.ErrCorrupt},
		{"source-read-error", badTree{r, root, "", io.ErrUnexpectedEOF}, Limits{}, io.ErrUnexpectedEOF},
		{"object-budget", r, Limits{Objects: 1}, filesystem.ErrLimit},
		{"value-budget", r, Limits{ValueBytes: 1}, filesystem.ErrLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "workspace")
			if _, err := Extract(context.Background(), tc.reader, root, dir, tc.limits); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(dir, "metadata", "manifest.json")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("failure published manifest", err)
			}
			if w, err := Open(context.Background(), dir); err == nil {
				w.Close()
				t.Fatal("incomplete workspace opened")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	dir := filepath.Join(t.TempDir(), "cancelled")
	if _, err := Extract(ctx, r, root, dir, Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("cancelled before start created output")
	}
}

func TestWorkspaceRejectsDamagedBlobAndProjection(t *testing.T) {
	r, root := sourceTree(t)
	for _, damage := range []string{"blob", "projection", "symlink"} {
		t.Run(damage, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "workspace")
			if _, err := Extract(context.Background(), r, root, dir, Limits{}); err != nil {
				t.Fatal(err)
			}
			w, err := Open(context.Background(), dir)
			if err != nil {
				t.Fatal(err)
			}
			id, err := filesystem.Lookup(context.Background(), w, "alias")
			if err != nil {
				t.Fatal(err)
			}
			blob := w.objects[id].Data
			if err = w.Close(); err != nil {
				t.Fatal(err)
			}
			name := filepath.Join(dir, "files", "alias")
			if damage == "blob" {
				name = filepath.Join(dir, "metadata", "blobs", blob.SHA256)
			}
			if damage == "symlink" {
				// A symlink to a real file outside the workspace must not be read.
				outside := filepath.Join(t.TempDir(), "outside")
				if err = os.WriteFile(outside, []byte("decoy"), 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.Remove(name); err != nil {
					t.Fatal(err)
				}
				if err = os.Symlink(outside, name); err != nil {
					t.Fatal("host cannot create symlink for escape control:", err)
				}
			} else {
				f, err := os.OpenFile(name, os.O_WRONLY, 0600)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.WriteAt([]byte("x"), 0)
				if err = errors.Join(err, f.Close()); err != nil {
					t.Fatal(err)
				}
			}
			if reopened, err := Open(context.Background(), dir); err == nil {
				reopened.Close()
				t.Fatal("damaged or substituted workspace accepted")
			}
		})
	}
}

func TestWorkspaceRejectsInvalidManifest(t *testing.T) {
	r, _ := sourceTree(t)
	ctx := context.Background()
	id, err := filesystem.Lookup(ctx, r, "Fixture/alias")
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(t.TempDir(), "workspace")
	if _, err = Extract(ctx, r, id, destination, Limits{}); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(destination, "metadata", "manifest.json")
	original, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*manifest)
	}{
		{"projection escape", func(m *manifest) { m.Entries[0].HostPath = "../outside" }},
		{"missing object", func(m *manifest) { m.Entries[0].Object++ }},
		{"metadata marker in old schema", func(m *manifest) { m.Objects[0].Node.MetadataModified = []string{"mode"} }},
		{"attribute marker in old schema", func(m *manifest) { m.Objects[0].Node.AttributesModified = []string{"org.test"} }},
		{"unknown metadata field", func(m *manifest) { m.Schema = 4; m.Objects[0].Node.MetadataModified = []string{"changeTime"} }},
		{"duplicate metadata field", func(m *manifest) { m.Schema = 4; m.Objects[0].Node.MetadataModified = []string{"mode", "mode"} }},
		{"invalid attribute marker", func(m *manifest) { m.Schema = 4; m.Objects[0].Node.AttributesModified = []string{""} }},
		{"created flag in old schema", func(m *manifest) { m.Objects[0].Node.Created = true }},
		{"changed links in old schema", func(m *manifest) { m.Objects[0].Node.LinksModified = true }},
		{"unknown observation state", func(m *manifest) { m.Objects[0].Node.Metadata.UID.State = 3 }},
		{"invalid blob size", func(m *manifest) { m.Objects[0].Data.Size = -1 }},
		{"unavailable raw data", func(m *manifest) { m.Objects[0].RawData = nil }},
		{"false preservation report", func(m *manifest) { m.Report.HardLinks++ }},
		{"false stored byte count", func(m *manifest) { m.Report.StoredBytes++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var m manifest
			if err := json.Unmarshal(original, &m); err != nil {
				t.Fatal(err)
			}
			tc.edit(&m)
			b, err := json.Marshal(m)
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(name, b, 0600); err != nil {
				t.Fatal(err)
			}
			if opened, err := Open(ctx, destination); err == nil {
				opened.Close()
				t.Fatal("invalid manifest admitted")
			}
		})
	}
}
