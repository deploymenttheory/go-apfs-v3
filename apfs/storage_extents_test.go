package apfs

import (
	"context"
	"errors"
	"math"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestPhysicalExtentHistoryCountsSharedAndFinalOwners(t *testing.T) {
	ctx := context.Background()
	original := []storageExtent{{100, 120, 3}, {200, 210, 1}}
	changes := []extentChange{{storageExtent{105, 115, -2}, false}, {storageExtent{200, 210, -1}, false}, {storageExtent{300, 305, 1}, true}}
	live, err := applyExtentChanges(ctx, original, changes)
	want := []storageExtent{{100, 105, 3}, {105, 115, 1}, {115, 120, 3}, {200, 210, 0}, {300, 305, 1}}
	if err != nil || !reflect.DeepEqual(live, want) {
		t.Fatal("signed updates/splits differ", live, err)
	}
	// Removing the final live reference must not remove an older view's owner.
	var retained []storageExtent
	for _, view := range [][]storageExtent{original, live} {
		for _, r := range view {
			if r.refs > 0 {
				retained = append(retained, r)
			}
		}
	}
	union, err := countStreamExtents(ctx, retained)
	if err != nil || !equalExtentCounts(union, []storageExtent{{100, 120, 2}, {200, 210, 1}, {300, 305, 1}}) {
		t.Fatal("historical ownership disappeared", union, err)
	}
	if original[0].refs != 3 || original[1].refs != 1 {
		t.Fatal("updating live references changed retained history")
	}
}

func TestPhysicalExtentHistoryRejectsUnprovableReferences(t *testing.T) {
	for _, tc := range []struct {
		name    string
		base    []storageExtent
		changes []extentChange
	}{
		{"orphan update", nil, []extentChange{{storageExtent{10, 20, 1}, false}}},
		{"partly unknown update", []storageExtent{{10, 15, 1}}, []extentChange{{storageExtent{10, 20, -1}, false}}},
		{"negative result", []storageExtent{{10, 20, 1}}, []extentChange{{storageExtent{10, 20, -2}, false}}},
		{"overflow", []storageExtent{{10, 20, math.MaxInt32}}, []extentChange{{storageExtent{10, 20, 1}, false}}},
		{"new over retained", []storageExtent{{10, 20, 1}}, []extentChange{{storageExtent{15, 25, 1}, true}}},
		{"new over known zero", []storageExtent{{10, 20, 0}}, []extentChange{{storageExtent{10, 20, 1}, true}}},
		{"overlapping updates", []storageExtent{{10, 20, 3}}, []extentChange{{storageExtent{10, 20, -1}, false}, {storageExtent{15, 20, -1}, false}}},
		{"empty range", nil, []extentChange{{storageExtent{10, 10, 1}, true}}},
		{"negative base", []storageExtent{{10, 20, -1}}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := applyExtentChanges(context.Background(), tc.base, tc.changes); !errors.Is(err, filesystem.ErrCorrupt) {
				t.Fatal("unprovable references admitted", err)
			}
		})
	}
}

func TestPhysicalExtentWorkDependsOnRecordsRatherThanPayload(t *testing.T) {
	const end = uint64(1) << 48
	got, err := applyExtentChanges(context.Background(), []storageExtent{{1, end, 2}}, []extentChange{{storageExtent{4, end - 4, -1}, false}})
	if err != nil || len(got) != 3 || got[1] != (storageExtent{4, end - 4, 1}) {
		t.Fatal("large range was not split by its metadata boundaries", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = applyExtentChanges(ctx, nil, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled extent reconciliation continued", err)
	}
	if _, err = countStreamExtents(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled stream inventory continued", err)
	}
}

func TestPhysicalExtentCountsAreSignedAndStreamAliasesAreSeparate(t *testing.T) {
	r := buildExtentReference(100, 8, 19)
	le.PutUint64(r.value, uint64(2)<<60|8)
	le.PutUint64(r.value[8:], owningObjectIDInvalid)
	negative := int32(-3)
	le.PutUint32(r.value[16:], uint32(negative))
	changes, err := readExtentChanges([]buildRecord{r}, 1000)
	if err != nil || len(changes) != 1 || changes[0].refs != -3 || changes[0].new {
		t.Fatal("physical UPDATE was interpreted as unsigned", changes, err)
	}
	got, err := countStreamExtents(context.Background(), []storageExtent{{100, 108, 1}, {104, 112, 1}})
	want := []storageExtent{{100, 104, 1}, {104, 108, 2}, {108, 112, 1}}
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatal("partially shared fork ranges differ", got, err)
	}
}
