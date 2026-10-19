package edit

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// countingVolume is a read-only APFS-like volume with one large directory
// beside a small one. It counts the objects and listings read, so a test
// can see what an edit touched.
type countingVolume struct {
	nodes    map[uint64]filesystem.Node
	children map[uint64][]filesystem.DirEntry
	stats    map[uint64]int
	listings map[uint64]int
}

const (
	volumeRoot = 2
	largeDir   = 3
	smallDir   = 4
)

func newCountingVolume(largeFiles int) *countingVolume {
	when := time.Unix(1_700_000_000, 0).UTC()
	meta := func(mode uint32) filesystem.Metadata {
		return filesystem.Metadata{Mode: filesystem.Observed(mode), UID: filesystem.Observed(uint32(501)), GID: filesystem.Observed(uint32(20)), BSDFlags: filesystem.Observed(uint32(0)), BirthTime: filesystem.Observed(when), ModifyTime: filesystem.Observed(when), ChangeTime: filesystem.Observed(when), AccessTime: filesystem.Observed(when)}
	}
	v := &countingVolume{nodes: map[uint64]filesystem.Node{}, children: map[uint64][]filesystem.DirEntry{}, stats: map[uint64]int{}, listings: map[uint64]int{}}
	dir := func(id uint64) {
		v.nodes[id] = filesystem.Node{Identity: filesystem.Identity{Object: id}, Metadata: meta(0o40755), Compression: filesystem.Observation[filesystem.Compression]{State: filesystem.Absent}}
	}
	dir(volumeRoot)
	dir(largeDir)
	dir(smallDir)
	v.children[volumeRoot] = []filesystem.DirEntry{{Name: "Large", Object: largeDir}, {Name: "Small", Object: smallDir}}
	v.children[smallDir] = nil
	for i := range largeFiles {
		id := uint64(100 + i)
		v.nodes[id] = filesystem.Node{Identity: filesystem.Identity{Object: id}, Metadata: meta(0o100644), Links: filesystem.Observed(uint32(1)), Compression: filesystem.Observation[filesystem.Compression]{State: filesystem.Absent}}
		v.children[largeDir] = append(v.children[largeDir], filesystem.DirEntry{Name: fmt.Sprintf("f%06d", i), Object: id})
	}
	return v
}

func (v *countingVolume) Root() uint64 { return volumeRoot }
func (v *countingVolume) NameRules() filesystem.NameRules {
	return filesystem.NameRules{Format: "APFS", NormalizationInsensitive: true}
}
func (v *countingVolume) Stat(_ context.Context, id uint64) (filesystem.Node, error) {
	n, ok := v.nodes[id]
	if !ok {
		return filesystem.Node{}, fs.ErrNotExist
	}
	v.stats[id]++
	return n, nil
}
func (v *countingVolume) ReadDir(_ context.Context, id uint64, yield func(filesystem.DirEntry) error) error {
	v.listings[id]++
	for _, e := range v.children[id] {
		if err := yield(e); err != nil {
			return err
		}
	}
	return nil
}
func (v *countingVolume) Lookup(ctx context.Context, id uint64, name string) (filesystem.DirEntry, error) {
	for _, e := range v.children[id] {
		if e.Name == name {
			return e, nil
		}
	}
	return filesystem.DirEntry{}, fs.ErrNotExist
}
func (v *countingVolume) OpenData(context.Context, uint64) (filesystem.Value, error) {
	return nil, fs.ErrNotExist
}
func (v *countingVolume) OpenRawData(context.Context, uint64) (filesystem.Value, error) {
	return nil, fs.ErrNotExist
}
func (v *countingVolume) ListAttributes(context.Context, uint64, func(string) error) error {
	return nil
}
func (v *countingVolume) OpenAttribute(context.Context, uint64, string) (filesystem.Value, error) {
	return nil, fs.ErrNotExist
}
func (v *countingVolume) Readlink(context.Context, uint64) (string, error) { return "", fs.ErrInvalid }

func createFileChange(path string) Change {
	when := time.Unix(1_750_000_000, 0).UTC()
	return Change{Op: CreateFile, Path: path, Data: bytes.NewReader([]byte("payload\n")), Metadata: &filesystem.Metadata{Mode: filesystem.Observed(uint32(0o100644)), UID: filesystem.Observed(uint32(501)), GID: filesystem.Observed(uint32(20)), BSDFlags: filesystem.Observed(uint32(0)), BirthTime: filesystem.Observed(when), ModifyTime: filesystem.Observed(when), ChangeTime: filesystem.Observed(when), AccessTime: filesystem.Observed(when)}}
}

func TestLazyTreeBoundsWhatAnEditTouchesNotTheVolume(t *testing.T) {
	ctx := context.Background()
	limits := Limits{Objects: 50, Entries: 100}
	volume := newCountingVolume(500)
	if _, err := New(ctx, volume, limits); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatalf("the eager tree models the whole volume and must exceed these limits, got %v", err)
	}
	volume = newCountingVolume(500)
	tree, err := NewLazy(ctx, volume, limits)
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Apply(ctx, createFileChange("Small/new")); err != nil {
		t.Fatalf("an edit beside a large directory must not read it: %v", err)
	}
	if volume.listings[largeDir] != 0 {
		t.Fatalf("the large directory was listed %d times by an edit that never touched it", volume.listings[largeDir])
	}
	for id := uint64(100); id < 600; id++ {
		if volume.stats[id] != 0 {
			t.Fatalf("object %d inside the untouched directory was read", id)
		}
	}
	e, err := tree.Lookup(ctx, smallDir, "new")
	if err != nil {
		t.Fatal(err)
	}
	if e.Object < virtualObjects {
		t.Fatalf("a created object took identity %d, which an unloaded base object could hold", e.Object)
	}
	if err := tree.Apply(ctx, createFileChange("Large/new")); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatalf("listing a directory above the entry bound must still be refused, got %v", err)
	}
}

func TestLazyTreeKeepsHardLinkCountsFromTheRecordedCount(t *testing.T) {
	ctx := context.Background()
	volume := newCountingVolume(2)
	// Two names for object 100: the second alias lives in the small directory.
	n := volume.nodes[100]
	n.Links = filesystem.Observed(uint32(2))
	volume.nodes[100] = n
	volume.children[smallDir] = []filesystem.DirEntry{{Name: "alias", Object: 100}}
	tree, err := NewLazy(ctx, volume, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if err := tree.Apply(ctx, Change{Op: RemoveEntry, Path: "Small/alias"}); err != nil {
		t.Fatal(err)
	}
	node, err := tree.Stat(ctx, 100)
	if err != nil {
		t.Fatalf("removing one of two names must keep the object, which the other directory still names: %v", err)
	}
	if node.Links.Value != 1 {
		t.Fatalf("link count %d after removing one of two names, want 1", node.Links.Value)
	}
	if err := tree.Apply(ctx, Change{Op: RemoveEntry, Path: "Large/f000000"}); err != nil {
		t.Fatal(err)
	}
	if _, err := tree.Stat(ctx, 100); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("an object without names must not be read back from the base, got %v", err)
	}
}
