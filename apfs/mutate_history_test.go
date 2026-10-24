package apfs

import (
	"context"
	"math"
	"reflect"
	"testing"
)

func historyRecordTree(t *testing.T, records []buildRecord, subtype uint32, fixed bool) *cowTree {
	t.Helper()
	b, err := newBuildTree(records, subtype, 0x40000000, fixed)
	if err != nil {
		t.Fatal(err)
	}
	id := uint64(10000)
	tree := &cowTree{buildTree: b, rootNode: b.root(), dirty: map[*buildTreeNode]bool{}, less: orderedPair, newOID: func() (uint64, error) { id++; return id, nil }}
	if subtype == 15 {
		tree.less = (&volumeLayout{}).recordLess
	}
	return tree
}

func TestSnapshotExtentDeltasDistinguishKnownZeroRangesAndPreserveOwnerBoundaries(t *testing.T) {
	var current []buildRecord
	for _, r := range [][4]uint64{{10, 1, 11, 3}, {11, 1, 11, 2}, {12, 2, 11, 1}, {17, 1, 77, 1}, {18, 1, 78, 1}} {
		record := buildExtentReference(r[0], r[1], r[2])
		le.PutUint32(record.value[16:], uint32(r[3]))
		current = append(current, record)
	}
	m := &mutation{ctx: context.Background(), extents: historyRecordTree(t, current, 15, false), history: &mutationHistory{
		base: []storageExtent{{10, 12, 2}, {12, 14, 0}, {14, 16, 1}}, owners: []historyExtentOwner{{10, 16, 11}},
	}}
	if err := m.encodeHistoryExtents(); err != nil {
		t.Fatal(err)
	}
	var got [][5]int64
	for _, r := range m.extents.all() {
		got = append(got, [5]int64{int64(prefix(r.key).id), int64(le.Uint64(r.value) & objectMask), int64(le.Uint64(r.value) >> 60), int64(le.Uint64(r.value[8:])), int64(int32(le.Uint32(r.value[16:])))})
	}
	want := [][5]int64{{10, 1, 2, -1, 1}, {12, 2, 2, -1, 1}, {14, 2, 2, -1, -1}, {17, 1, 1, 77, 1}, {18, 1, 1, 78, 1}}
	if !reflect.DeepEqual(got, want) {
		t.Fatal("snapshot boundary/delta encoding changed", got, want)
	}
	changes, err := readExtentChanges(m.extents.all(), 32)
	if err != nil {
		t.Fatal(err)
	}
	refs, err := applyExtentChanges(context.Background(), m.history.base, changes)
	if err != nil {
		t.Fatal(err)
	}
	wantRefs := []storageExtent{{10, 11, 3}, {11, 12, 2}, {12, 14, 1}, {14, 16, 0}, {17, 19, 1}}
	if !reflect.DeepEqual(refs, wantRefs) {
		t.Fatal("encoded delta has different effective references", refs)
	}
}

func TestSnapshotExtentDeltasRejectUnsignedCountsOutsideTheSignedDomain(t *testing.T) {
	record := buildExtentReference(10, 1, 11)
	le.PutUint32(record.value[16:], math.MaxUint32)
	m := &mutation{ctx: context.Background(), extents: historyRecordTree(t, []buildRecord{record}, 15, false), history: &mutationHistory{}}
	if err := m.encodeHistoryExtents(); err == nil {
		t.Fatal("invalid live count wrapped into a negative snapshot delta")
	}
}

func TestSnapshotObjectMapPruningSelectsVersionsAcrossLeafBoundaries(t *testing.T) {
	var records []buildRecord
	for oid := uint64(1); oid <= 800; oid++ {
		for xid := uint64(1); xid <= 8; xid++ {
			value := make([]byte, 16)
			le.PutUint32(value[4:], 4096)
			le.PutUint64(value[8:], oid*10+xid)
			if xid == 4 {
				clear(value)
				le.PutUint32(value, 1)
			}
			records = append(records, buildRecord{append(buildUint64(oid), buildUint64(xid)...), value})
		}
	}
	tree := historyRecordTree(t, records, 11, true)
	if tree.rootNode.level == 0 {
		t.Fatal("control did not cross object-map leaves")
	}
	for _, oid := range []uint64{1, 24, 25, 400, 799, 800} {
		if got := objectVersions(tree, oid); len(got) != 8 {
			t.Fatal("OID versions lost across leaf ranges", oid, len(got))
		}
		if err := removeObjectVersions(tree, oid, 3, 5, 7); err != nil {
			t.Fatal(err)
		}
		got := objectVersions(tree, oid)
		if len(got) != 3 || le.Uint64(got[0].key[8:]) != 3 || le.Uint64(got[1].key[8:]) != 5 || le.Uint64(got[2].key[8:]) != 7 {
			t.Fatal("historical predecessor selection changed", oid, got)
		}
	}
	if got := objectVersions(tree, 399); len(got) != 8 {
		t.Fatal("pruning changed a different object")
	}
}
