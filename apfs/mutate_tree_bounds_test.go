package apfs

import (
	"context"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// A checksummed node can still contain malformed typed keys. Admission must
// return a corruption error before suffix sorting or mutation, without panicking.
func TestMutationRejectsTruncatedFilesystemKeysBeforeSorting(t *testing.T) {
	for _, kind := range []uint64{4, 5, 8, 9} {
		key := buildKey(16, kind, 0)
		tree, e := newBuildTree([]buildRecord{{key, []byte{1}}, {key, []byte{2}}}, 14, 0, false)
		if e != nil {
			t.Fatal(e)
		}
		root := tree.nodes[len(tree.nodes)-1]
		root.oid = 100
		b := tree.nodeBytes(root, true)
		sealObject(b, root.oid, 1, 2, 14)
		_, e = loadCOWTree(context.Background(), root.oid, 14, 0, func(uint64) ([]byte, uint64, error) { return b, 10, nil }, (&volumeLayout{}).recordLess, func() (uint64, error) { return 101, nil })
		if !errors.Is(e, filesystem.ErrCorrupt) {
			t.Fatal("truncated typed key admitted", kind, e)
		}
	}
}

func TestMutationRejectsOverlappingLeafRangesWithOrderedSeparators(t *testing.T) {
	var records []buildRecord
	for i := uint64(1); i <= 500; i++ {
		records = append(records, buildRecord{append(buildUint64(i), buildUint64(1)...), make([]byte, 16)})
	}
	tree, err := newBuildTree(records, 11, 0x40000000, true)
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range tree.nodes {
		n.oid = uint64(100 + i)
		n.address = n.oid
	}
	if tree.root().level != 1 {
		t.Fatal("test requires multiple leaves")
	}
	left, right := tree.root().children[0], tree.root().children[1]
	// Parent separators and each individual leaf remain ordered. Only the
	// inter-leaf range is corrupt, so local key-order checks are insufficient.
	le.PutUint64(left.records[len(left.records)-1].key, le.Uint64(right.records[0].key)+1)
	stored := map[uint64][]byte{}
	for _, n := range tree.nodes {
		b := tree.nodeBytes(n, n == tree.root())
		kind := uint32(0x40000003)
		if n == tree.root() {
			kind = 0x40000002
		}
		sealObject(b, n.oid, 1, kind, 11)
		stored[n.oid] = b
	}
	_, err = loadCOWTree(context.Background(), tree.root().oid, 11, 0x40000000, func(id uint64) ([]byte, uint64, error) { return stored[id], id, nil }, orderedPair, func() (uint64, error) { return 1000, nil })
	if !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("cross-leaf overlap admitted", err)
	}
}
