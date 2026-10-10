package workspace

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

func sourceTree(t *testing.T) (filesystem.Reader, uint64) {
	t.Helper()
	image, err := diskimage.Open("../acceptance/testdata/semantics/macos-27/apfs-case-sensitive.dmg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := image.Close(); err != nil {
			t.Error(err)
		}
	})
	report, err := inspect.Image(context.Background(), image)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range report.Partitions {
		if p.APFS != nil {
			r := &p.APFS.Volumes[0]
			id, err := filesystem.Lookup(context.Background(), r, "Fixture")
			if err != nil {
				t.Fatal(err)
			}
			return r, id
		}
	}
	t.Fatal("missing native filesystem")
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
