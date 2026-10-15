package apfs

import (
	"context"
	"testing"
)

func TestObjectMapPruningKeepsEachHistoricalPredecessorAndDeletion(t *testing.T) {
	var records []buildRecord
	for _, version := range []struct {
		oid, xid uint64
		deleted  bool
	}{{19, 5, false}, {19, 12, true}, {19, 30, false}, {20, 4, false}} {
		value := make([]byte, 16)
		if version.deleted {
			le.PutUint32(value, 1)
		} else {
			le.PutUint32(value[4:], 4096)
			le.PutUint64(value[8:], 100+version.xid)
		}
		records = append(records, buildRecord{append(buildUint64(version.oid), buildUint64(version.xid)...), value})
	}
	built, err := newBuildTree(records, 11, 0x40000000, true)
	if err != nil {
		t.Fatal(err)
	}
	root := built.root()
	root.oid = 50
	root.address = 50
	data := built.nodeBytes(root, true)
	sealObject(data, 50, 40, 0x40000002, 11)
	tree, err := loadCOWTree(context.Background(), 50, 11, 0x40000000, func(uint64) ([]byte, uint64, error) { return data, 50, nil }, orderedPair, func() (uint64, error) { return 51, nil })
	if err != nil {
		t.Fatal(err)
	}
	if err = removeObjectVersions(tree, 19, 10, 20); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		xid, address uint64
		deleted      bool
	}{{10, 105, false}, {20, 0, true}} {
		r, ok := tree.floor(append(buildUint64(19), buildUint64(tc.xid)...))
		if !ok || le.Uint64(r.key) != 19 || le.Uint64(r.value[8:]) != tc.address || (le.Uint32(r.value)&1 != 0) != tc.deleted {
			t.Fatal("historical predecessor changed", tc, r)
		}
	}
	if _, ok := tree.get(append(buildUint64(19), buildUint64(30)...)); ok {
		t.Fatal("unretained version leaked")
	}
	if err = removeObjectVersions(tree, 19); err != nil {
		t.Fatal(err)
	}
	if len(tree.all()) != 1 || le.Uint64(tree.all()[0].key) != 20 {
		t.Fatal("final-reference pruning lost a different object or retained dead versions")
	}
}
