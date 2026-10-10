package workspace

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestEditCreationIsDeterministicAndSurvivesFurtherEdits(t *testing.T) {
	w, id, baseline := replacementBaseline(t)
	ctx := context.Background()
	original, err := w.Stat(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	fileMeta := original.Metadata
	fileMeta.BSDFlags = filesystem.Observed(uint32(0))
	fileMeta.Mode = filesystem.Observed(uint32(0100640))
	dirMeta := fileMeta
	dirMeta.Mode = filesystem.Observed(uint32(0040751))
	changes := []Change{
		{Op: CreateDirectory, Path: "new", Metadata: &dirMeta},
		{Op: CreateFile, Path: "new/file", Metadata: &fileMeta, Data: bytes.NewReader([]byte("new")), Attributes: map[string]block.Source{filesystem.ResourceFork: bytes.NewReader([]byte("independent fork"))}},
		{Op: CreateHardLink, Path: "new/file", To: "new/alias"},
		{Op: RenameEntry, Path: "alias", To: "new/original"},
	}
	first := filepath.Join(t.TempDir(), "first")
	if _, err := w.Edit(ctx, changes, first, Limits{}); err != nil {
		t.Fatal(err)
	}
	a, err := Open(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	second := filepath.Join(t.TempDir(), "same")
	if _, err := w.Edit(ctx, changes, second, Limits{}); err != nil {
		t.Fatal(err)
	}
	b, err := Open(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if a.ManifestSHA256() != b.ManifestSHA256() {
		t.Fatal("same inputs did not produce byte-identical manifests")
	}
	createdID, err := filesystem.Lookup(ctx, a, "new/file")
	if err != nil {
		t.Fatal(err)
	}
	created, err := a.Stat(ctx, createdID)
	if err != nil || !created.Created || !createdIdentity(created.Identity) {
		t.Fatal("creation origin", created, err)
	}
	third := filepath.Join(t.TempDir(), "third")
	if _, err := a.Edit(ctx, []Change{{Op: ReplaceFileData, Path: "new/alias", Data: bytes.NewReader([]byte("replacement"))}, {Op: RemoveEntry, Path: "new/file"}}, third, Limits{}); err != nil {
		t.Fatal(err)
	}
	c, err := Open(ctx, third)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	latest, err := c.Stat(ctx, createdID)
	if err != nil || latest.Identity != created.Identity || !latest.Created || latest.Links.Value != 1 {
		t.Fatal("creation identity not retained", err)
	}
	value, err := c.OpenAttribute(ctx, createdID, filesystem.ResourceFork)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
	value.Close()
	if err != nil || string(data) != "independent fork" {
		t.Fatal("new object's fork lost", err)
	}
	// A newly created directory can contain preserved native objects. Extracting
	// that subtree must keep both origins, including aliases outside the subtree.
	newRoot, err := filesystem.Lookup(ctx, c, "new")
	if err != nil {
		t.Fatal(err)
	}
	subtree := filepath.Join(t.TempDir(), "subtree")
	if _, err := Extract(ctx, c, newRoot, subtree, Limits{}); err != nil {
		t.Fatal(err)
	}
	sub, err := Open(ctx, subtree)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	before, err := sub.Stat(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(t.TempDir(), "linked")
	if _, err := sub.Edit(ctx, []Change{{Op: CreateHardLink, Path: "original", To: "additional"}}, linked, Limits{}); err != nil {
		t.Fatal(err)
	}
	d, err := Open(ctx, linked)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	after, err := d.Stat(ctx, id)
	if err != nil || after.Links.Value != before.Links.Value+1 || after.Identity != original.Identity {
		t.Fatal("lost aliases outside extracted subtree", err)
	}
	unchanged, err := Open(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	defer unchanged.Close()
	if unchanged.ManifestSHA256() != w.ManifestSHA256() {
		t.Fatal("edited baseline")
	}
}

func TestEditPreflightAndStreamingFailuresNeverPublish(t *testing.T) {
	w, id, baseline := replacementBaseline(t)
	ctx := context.Background()
	n, err := w.Stat(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	fileMeta := n.Metadata
	fileMeta.Mode = filesystem.Observed(uint32(0100640))
	fileMeta.BSDFlags = filesystem.Observed(uint32(0))
	dirMeta := fileMeta
	dirMeta.Mode = filesystem.Observed(uint32(0040755))
	symlinkMeta := fileMeta
	symlinkMeta.Mode = filesystem.Observed(uint32(0120777))
	unknown := fileMeta
	unknown.UID.State = filesystem.Uncaptured
	bad := &failedReplacement{size: 10, read: func([]byte, int64) (int, error) { return 0, io.EOF }}
	failure := errors.New("input failure")
	attr := &failedReplacement{size: 1, read: func([]byte, int64) (int, error) { return 0, failure }}
	cancelled, cancel := context.WithCancel(ctx)
	cancelData := &failedReplacement{size: 1, read: func(b []byte, _ int64) (int, error) { b[0] = 1; cancel(); return 1, nil }}
	cases := []struct {
		name    string
		ctx     context.Context
		changes []Change
		limits  Limits
		want    error
	}{
		{"empty", ctx, nil, Limits{}, fs.ErrInvalid},
		{"incomplete metadata", ctx, []Change{{Op: CreateFile, Path: "new", Metadata: &unknown, Data: bytes.NewReader(nil)}}, Limits{}, fs.ErrInvalid},
		{"irrelevant input", ctx, []Change{{Op: RemoveEntry, Path: "alias", Data: bytes.NewReader(nil)}}, Limits{}, fs.ErrInvalid},
		{"symlink traversal", ctx, []Change{{Op: CreateSymlink, Path: "link-dir", Target: ".", Metadata: &symlinkMeta}, {Op: CreateDirectory, Path: "link-dir/escaped", Metadata: &dirMeta}}, Limits{}, fs.ErrInvalid},
		{"cycle after earlier move", ctx, []Change{{Op: CreateDirectory, Path: "a", Metadata: &dirMeta}, {Op: CreateDirectory, Path: "a/b", Metadata: &dirMeta}, {Op: RenameEntry, Path: "a", To: "a/b/a"}}, Limits{}, fs.ErrInvalid},
		{"duplicate alias replacement", ctx, []Change{{Op: CreateHardLink, Path: "alias", To: "another"}, {Op: ReplaceFileData, Path: "alias", Data: bytes.NewReader(nil)}, {Op: ReplaceFileData, Path: "another", Data: bytes.NewReader(nil)}}, Limits{}, filesystem.ErrConflict},
		{"short created data", ctx, []Change{{Op: CreateFile, Path: "created", Metadata: &fileMeta, Data: bad}}, Limits{}, io.ErrUnexpectedEOF},
		{"failed created attribute", ctx, []Change{{Op: CreateDirectory, Path: "created", Metadata: &dirMeta, Attributes: map[string]block.Source{"org.test": attr}}}, Limits{}, failure},
		{"cancel during creation", cancelled, []Change{{Op: CreateFile, Path: "created", Metadata: &fileMeta, Data: cancelData}}, Limits{}, context.Canceled},
		{"value limit", ctx, []Change{{Op: CreateFile, Path: "created", Metadata: &fileMeta, Data: bytes.NewReader([]byte("xx"))}}, Limits{ValueBytes: 1}, filesystem.ErrLimit},
		{"root removal", ctx, []Change{{Op: RemoveEntry, Path: "/"}}, Limits{}, fs.ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "failed")
			if _, err := w.Edit(tc.ctx, tc.changes, dest, tc.limits); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(dest, "metadata/manifest.json")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("failure published manifest", err)
			}
		})
	}
	if bad.closed || attr.closed || cancelData.closed {
		t.Fatal("borrowed source closed")
	}
	if _, err := w.Edit(ctx, []Change{{Op: RemoveEntry, Path: "alias"}}, filepath.Join(baseline, "inside"), Limits{}); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal("baseline containment", err)
	}
	unchanged, err := Open(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	defer unchanged.Close()
	got, err := unchanged.Stat(ctx, id)
	if err != nil || !reflect.DeepEqual(got, n) {
		t.Fatal("failed edit changed original", err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Edit(ctx, []Change{{Op: RemoveEntry, Path: "alias"}}, filepath.Join(t.TempDir(), "closed"), Limits{}); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("closed workspace edited", err)
	}
}

// An uncaptured field is not corruption. Unrelated operations must preserve it;
// adding/removing an alias requires the missing count and must fail explicitly.
func TestEditPreservesUncapturedLinksUntilNeeded(t *testing.T) {
	w, id, _ := replacementBaseline(t)
	ctx := context.Background()
	source := uncapturedLinks{Reader: w, id: id}
	baseline := filepath.Join(t.TempDir(), "uncaptured")
	if _, err := Extract(ctx, source, source.Root(), baseline, Limits{}); err != nil {
		t.Fatal(err)
	}
	unknown, err := Open(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	defer unknown.Close()
	destination := filepath.Join(t.TempDir(), "renamed")
	if _, err := unknown.Edit(ctx, []Change{{Op: RenameEntry, Path: "alias", To: "renamed"}}, destination, Limits{}); err != nil {
		t.Fatal("unrelated rename rejected", err)
	}
	renamed, err := Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer renamed.Close()
	n, err := renamed.Stat(ctx, id)
	if err != nil || n.Links.State != filesystem.Uncaptured {
		t.Fatal("invented missing link count", err)
	}
	for _, change := range []Change{{Op: RemoveEntry, Path: "renamed"}, {Op: CreateHardLink, Path: "renamed", To: "new-link"}} {
		if _, err := renamed.Edit(ctx, []Change{change}, filepath.Join(t.TempDir(), "failed"), Limits{}); !errors.Is(err, filesystem.ErrUnsupported) {
			t.Fatal("guessed missing link count", err)
		}
	}
}

type uncapturedLinks struct {
	filesystem.Reader
	id uint64
}

func (r uncapturedLinks) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	n, err := r.Reader.Stat(ctx, id)
	if id == r.id {
		n.Links = filesystem.Observation[uint32]{}
	}
	return n, err
}
