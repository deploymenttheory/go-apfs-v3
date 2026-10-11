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
