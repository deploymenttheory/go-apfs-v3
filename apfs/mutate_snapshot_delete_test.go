package apfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"reflect"
	"slices"
	"testing"
)

// appendDeleteTestSnapshot extends the explicitly synthetic single-history
// clone fixture. It writes format records directly, never DeleteSnapshot.
func appendDeleteTestSnapshot(t *testing.T, disk *cloneMutationDisk, name string) {
	t.Helper()
	ctx := context.Background()
	m, err := openMutation(ctx, disk)
	if err != nil {
		t.Fatal(err)
	}
	if m.history == nil {
		t.Fatal("append control requires its existing retained history")
	}
	xid := uint64(m.c.XID)
	physical := func(records []buildRecord, subtype uint32, fixed bool) *cowTree {
		t.Helper()
		less := (&volumeLayout{}).recordLess
		if subtype == 19 {
			less = func(a, b []byte) bool { return le.Uint64(a) < le.Uint64(b) }
		}
		slices.SortFunc(records, func(a, b buildRecord) int {
			if less(a.key, b.key) {
				return -1
			}
			if less(b.key, a.key) {
				return 1
			}
			return 0
		})
		b, err := newBuildTree(records, subtype, 0x40000000, fixed)
		if err != nil {
			t.Fatal(err)
		}
		if subtype == 19 {
			b.keySize, b.longestKey = 8, 8
		}
		tree := &cowTree{buildTree: b, rootNode: b.root(), dirty: map[*buildTreeNode]bool{}, less: less, newOID: m.nextOID}
		for _, n := range b.nodes {
			n.oid, err = m.nextOID()
			if err != nil {
				t.Fatal(err)
			}
			tree.dirty[n] = true
		}
		return tree
	}
	oldMeta, err := m.snapshotTree(uint64(m.v.snapMeta), 16)
	if err != nil {
		t.Fatal(err)
	}
	oldMembership, err := m.snapshotTree(le.Uint64(m.volumeMap[56:]), 19)
	if err != nil {
		t.Fatal(err)
	}
	oldExtents, err := m.snapshotTree(le.Uint64(m.super[144:]), 15)
	if err != nil {
		t.Fatal(err)
	}
	// m.extents is normalized in memory. Freeze the ORIGINAL physical delta
	// root and rebase the unchanged live references against this new history.
	var refs []storageExtent
	for _, r := range m.extents.all() {
		start := prefix(r.key).id
		refs = append(refs, storageExtent{start, start + le.Uint64(r.value)&objectMask, int64(le.Uint32(r.value[16:]))})
	}
	m.history.base = refs
	m.history.data, err = countStreamExtents(ctx, append(slices.Clone(m.history.data), refs...))
	if err != nil {
		t.Fatal(err)
	}
	m.history.xids = append(m.history.xids, XID(xid))
	for _, tree := range []*cowTree{m.fs, oldExtents} {
		for _, node := range tree.nodes {
			m.history.metadata[node.address] = true
		}
	}
	address, err := m.allocateMetadata(false)
	if err != nil {
		t.Fatal(err)
	}
	historical := bytes.Clone(m.super)
	sealObject(historical, address, xid, 0x4000000d, 0)
	if err := m.write(historical, address*4096); err != nil {
		t.Fatal(err)
	}
	m.history.metadata[address] = true
	value := make([]byte, 50+len(name)+1)
	le.PutUint64(value, le.Uint64(m.super[144:]))
	le.PutUint64(value[8:], address)
	le.PutUint64(value[16:], uint64(builtClock.UnixNano()))
	le.PutUint64(value[24:], uint64(builtClock.UnixNano()))
	le.PutUint32(value[40:], 0x40000002)
	le.PutUint16(value[48:], uint16(len(name)+1))
	copy(value[50:], name)
	key := buildKey(objectMask, 11, 2+len(name)+1)
	le.PutUint16(key[8:], uint16(len(name)+1))
	copy(key[10:], name)
	metadata := physical(append(oldMeta.all(), buildRecord{buildKey(xid, 1, 0), value}, buildRecord{key, buildUint64(xid)}), 16, false)
	membership := physical(append(oldMembership.all(), buildRecord{buildUint64(xid), make([]byte, 16)}), 19, true)
	for _, tree := range []*cowTree{oldMeta, oldMembership} {
		for _, node := range tree.nodes {
			if err := m.retireMetadata(node.address, true); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := m.writeTree(metadata, true); err != nil {
		t.Fatal(err)
	}
	if err := m.writeTree(membership, true); err != nil {
		t.Fatal(err)
	}
	uuidOID := le.Uint64(m.super[1000:])
	uuidAddress, err := m.allocateMetadata(true)
	if err != nil {
		t.Fatal(err)
	}
	uuid := make([]byte, 4096)
	le.PutUint32(uuid[32:], 1)
	le.PutUint64(uuid[40:], xid)
	le.PutUint64(uuid[48:], xid)
	copy(uuid[56:], "history!")
	sealObject(uuid, uuidOID, xid, 29, 0)
	if err := m.write(uuid, uuidAddress*4096); err != nil {
		t.Fatal(err)
	}
	m.history.metadata[uuidAddress] = true
	mapping := make([]byte, 16)
	le.PutUint32(mapping[4:], 4096)
	le.PutUint64(mapping[8:], uuidAddress)
	if err := m.vmap.put(append(buildUint64(uuidOID), buildUint64(xid)...), mapping); err != nil {
		t.Fatal(err)
	}
	le.PutUint32(m.volumeMap[36:], uint32(len(m.history.xids)))
	le.PutUint64(m.volumeMap[56:], membership.rootNode.address)
	le.PutUint64(m.volumeMap[64:], xid)
	le.PutUint64(m.super[152:], metadata.rootNode.address)
	le.PutUint64(m.super[216:], uint64(len(m.history.xids)))
	if err := m.commit(uint64(builtClock.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectStorage(ctx, disk); err != nil {
		t.Fatal("synthetic multi-history admission", err)
	}
}

func TestSnapshotDeletionInvalidOrMissingIdentityDoesNotWrite(t *testing.T) {
	input := snapshotDeleteInput(t)
	for _, tc := range []struct {
		name     string
		selector SnapshotSelector
		want     error
	}{
		{"empty", SnapshotSelector{}, fs.ErrInvalid},
		{"conflicting", SnapshotSelector{Name: "middle", XID: 1}, fs.ErrInvalid},
		{"invalid name", SnapshotSelector{Name: "bad/name"}, fs.ErrInvalid},
		{"missing name", SnapshotSelector{Name: "missing"}, fs.ErrNotExist},
		{"missing XID", SnapshotSelector{XID: 999999}, fs.ErrNotExist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			disk := newCloneMutationDisk(input)
			before := sha256.Sum256(disk.data)
			if _, err := DeleteSnapshot(context.Background(), disk, "", tc.selector, builtClock); !errors.Is(err, tc.want) || disk.writes != 0 || sha256.Sum256(disk.data) != before {
				t.Fatal("invalid selection wrote or lost its error", tc.name, disk.writes, err)
			}
		})
	}
}

func TestSnapshotDeletionWriteFailureProtectsACompleteCheckpoint(t *testing.T) {
	input := snapshotDeleteInput(t)
	original := newCloneMutationDisk(input)
	c, snapshots := deleteTestSnapshots(t, original)
	wantLive := snapshotStates(t, &c.Volumes[0])
	wantHistory := map[string]map[string]snapshotObjectState{}
	for _, snapshot := range snapshots {
		view, err := c.Volumes[0].OpenSnapshot(context.Background(), snapshot.XID)
		if err != nil {
			t.Fatal(err)
		}
		wantHistory[snapshot.Name] = snapshotStates(t, view)
	}
	completed := newCloneMutationDisk(input)
	if _, err := DeleteSnapshot(context.Background(), completed, c.Volumes[0].UUID, SnapshotSelector{Name: "middle"}, builtClock); err != nil {
		t.Fatal(err)
	}
	// The final write updates block zero AFTER publishing the complete NX
	// descriptor. An error invalidates this disposable copy, but selecting it
	// must still yield either the complete old checkpoint or the complete new
	// checkpoint, with immutable surviving histories in both cases.
	for _, fail := range []int{1, max(1, completed.writes/2), completed.writes} {
		disk := newCloneMutationDisk(input)
		disk.failAt = fail
		if _, err := DeleteSnapshot(context.Background(), disk, c.Volumes[0].UUID, SnapshotSelector{Name: "middle"}, builtClock); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("delete lost original I/O failure", fail, err)
		}
		got, remaining := deleteTestSnapshots(t, disk)
		wantXID, wantSnapshots := c.XID, snapshots
		if fail == completed.writes {
			wantXID++
			wantSnapshots = slices.DeleteFunc(slices.Clone(snapshots), func(s Snapshot) bool { return s.Name == "middle" })
			if _, err := got.Volumes[0].OpenSnapshotName(context.Background(), "middle"); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("published deletion still exposes its removed history", err)
			}
		}
		if got.XID != wantXID || got.UUID != c.UUID || got.Volumes[0].UUID != c.Volumes[0].UUID || !reflect.DeepEqual(remaining, wantSnapshots) {
			t.Fatal("failed deletion did not select the complete expected checkpoint", fail, got.XID, wantXID, remaining, wantSnapshots)
		}
		for path, state := range wantLive {
			state.Node.Identity.View = uint64(wantXID)
			wantLive[path] = state
		}
		if !reflect.DeepEqual(snapshotStates(t, &got.Volumes[0]), wantLive) {
			t.Fatal("failed deletion damaged live bytes or metadata", fail)
		}
		for _, snapshot := range remaining {
			view, err := got.Volumes[0].OpenSnapshotName(context.Background(), snapshot.Name)
			if err != nil || !reflect.DeepEqual(snapshotStates(t, view), wantHistory[snapshot.Name]) {
				t.Fatal("failed deletion damaged a retained view", fail, snapshot.Name, err)
			}
		}
		if _, err := InspectStorage(context.Background(), disk); err != nil {
			t.Fatal("failed deletion storage accounting", fail, err)
		}
	}
}

func TestSnapshotDeletionQueuesOnlyItsExclusiveDataAndContinuesAfterFinalHistory(t *testing.T) {
	ctx := context.Background()
	disk := newCloneMutationDisk(snapshotDeleteInput(t))
	c, snapshots := deleteTestSnapshots(t, disk)
	live := snapshotStates(t, &c.Volumes[0])
	checker, err := newStorageChecker(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := checker.check(); err != nil {
		t.Fatal(err)
	}
	// The declaration gives each snapshot a different /independent data
	// generation. Common clone data/forks/attributes remain live owners.
	ranges := map[string][]storageExtent{}
	id := live["/independent"].Node.Identity.Object
	for i, snapshot := range snapshots {
		view := checker.volumes[0].views[i]
		inode, ok := view.fs.get(buildKey(id, 3, 0))
		if !ok {
			t.Fatal("independent generation inode missing")
		}
		for _, record := range view.fs.records(le.Uint64(inode.value[8:]), 8) {
			start := le.Uint64(record.value[8:])
			count := (le.Uint64(record.value) & ((1 << 56) - 1)) / 4096
			ranges[snapshot.Name] = append(ranges[snapshot.Name], storageExtent{start, start + count, 1})
		}
		if len(ranges[snapshot.Name]) == 0 {
			t.Fatal("exclusive data generation is not allocated", snapshot.Name)
		}
	}
	for _, snapshot := range snapshots {
		if _, err := DeleteSnapshot(ctx, disk, c.Volumes[0].UUID, SnapshotSelector{XID: snapshot.XID}, builtClock); err != nil {
			t.Fatal(err)
		}
		current, _ := deleteTestSnapshots(t, disk)
		state, err := newStorageChecker(ctx, current)
		if err != nil {
			t.Fatal(err)
		}
		if err := state.check(); err != nil {
			t.Fatal(err)
		}
		for _, extent := range ranges[snapshot.Name] {
			for block := extent.start; block < extent.end; block++ {
				queued, allocated := false, false
				for _, record := range state.reader.space.queues[1].all() {
					at := le.Uint64(record.key[8:])
					queued = queued || block >= at && block-at < le.Uint64(record.value)
				}
				for _, chunk := range state.reader.space.chunks {
					if block >= chunk.start && block-chunk.start < uint64(chunk.count) {
						allocated = littleBit(chunk.bitmap, block-chunk.start)
					}
				}
				if !queued || !allocated || littleBit(state.protected, block) {
					t.Fatal("deleted data did not become checkpoint-deferred only", snapshot.Name, block, queued, allocated)
				}
			}
		}
	}
	var stable uint64
	for round := 0; round < 4; round++ {
		payload := bytes.Repeat([]byte("allocation after final snapshot"), 9000)
		if _, err := Modify(ctx, disk, []Change{{Path: "/reuse", Data: bytes.NewReader(payload)}}, builtClock); err != nil {
			t.Fatal("continued write after final snapshot", err)
		}
		if !bytes.Equal(cloneContents(t, disk, "/reuse", ""), payload) {
			t.Fatal("reused allocation readback changed")
		}
		if _, err := Modify(ctx, disk, []Change{{Operation: "rm", Path: "/reuse"}}, builtClock); err != nil {
			t.Fatal(err)
		}
		report, err := InspectStorage(ctx, disk)
		if err != nil || report.Snapshots != 0 {
			t.Fatal("continued allocation accounting", report, err)
		}
		if round == 2 {
			stable = report.FreeBlocks
		} else if round > 2 && stable != report.FreeBlocks {
			t.Fatal("final-history release leaked repeated allocation", stable, report.FreeBlocks)
		}
		current, _ := deleteTestSnapshots(t, disk)
		for path, wanted := range live {
			wanted.Node.Identity.View = uint64(current.XID)
			live[path] = wanted
		}
		if !reflect.DeepEqual(snapshotStates(t, &current.Volumes[0]), live) {
			t.Fatal("allocation reuse changed a surviving clone/data/fork/attribute owner")
		}
	}
}

func snapshotDeleteInput(t *testing.T) []byte {
	t.Helper()
	disk := newCloneMutationDisk(snapshotMutationImage(t))
	for i, name := range []string{"middle", "newest"} {
		payload := bytes.Repeat([]byte{byte('B' + i)}, (4+i)*4096)
		if _, err := Modify(context.Background(), disk, []Change{{Path: "/independent", Data: bytes.NewReader(payload)}}, builtClock); err != nil {
			t.Fatal(err)
		}
		appendDeleteTestSnapshot(t, disk, name)
	}
	if _, err := Modify(context.Background(), disk, []Change{{Path: "/independent", Data: bytes.NewReader(bytes.Repeat([]byte("D"), 6*4096))}}, builtClock); err != nil {
		t.Fatal(err)
	}
	return bytes.Clone(disk.data)
}

func deleteTestSnapshots(t *testing.T, disk *cloneMutationDisk) (*Container, []Snapshot) {
	t.Helper()
	c, err := Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	var result []Snapshot
	if err := c.Volumes[0].ListSnapshots(context.Background(), func(s Snapshot) error { result = append(result, s); return nil }); err != nil {
		t.Fatal(err)
	}
	return c, result
}

func TestSnapshotDeletionPreservesEverySurvivorInDifferentOrders(t *testing.T) {
	input := snapshotDeleteInput(t)
	inputSHA := sha256.Sum256(input)
	for orderIndex, order := range [][]string{{"retained-history", "middle", "newest"}, {"middle", "newest", "retained-history"}, {"newest", "retained-history", "middle"}} {
		t.Run(order[0], func(t *testing.T) {
			disk := newCloneMutationDisk(input)
			c, snapshots := deleteTestSnapshots(t, disk)
			if len(snapshots) != 3 {
				t.Fatal("control must contain three distinct histories", snapshots)
			}
			containerID, volumeID := c.UUID, c.Volumes[0].UUID
			live := snapshotStates(t, &c.Volumes[0])
			wanted := map[string]map[string]snapshotObjectState{}
			inventory := map[string]Snapshot{}
			for _, snapshot := range snapshots {
				view, err := c.Volumes[0].OpenSnapshot(context.Background(), snapshot.XID)
				if err != nil {
					t.Fatal(err)
				}
				wanted[snapshot.Name] = snapshotStates(t, view)
				inventory[snapshot.Name] = snapshot
			}
			previousXID := c.XID
			for index, name := range order {
				selector := SnapshotSelector{Name: name}
				if (index+orderIndex)%2 != 0 {
					for _, snapshot := range snapshots {
						if snapshot.Name == name {
							selector = SnapshotSelector{XID: snapshot.XID}
						}
					}
				}
				report, err := DeleteSnapshot(context.Background(), disk, volumeID, selector, builtClock)
				if err != nil {
					t.Fatal("delete", name, err)
				}
				delete(wanted, name)
				c, remaining := deleteTestSnapshots(t, disk)
				if c.UUID != containerID || c.Volumes[0].UUID != volumeID {
					t.Fatal("deletion changed identity", name, c.UUID, containerID, c.Volumes[0].UUID, volumeID)
				}
				if len(remaining) != len(wanted) {
					t.Fatal("deletion changed inventory", name, remaining, wanted)
				}
				if c.XID != previousXID+1 || report.Transaction != uint64(c.XID) || report.VolumeID != volumeID {
					t.Fatal("deletion transaction/report mismatch", previousXID, c.XID, report)
				}
				previousXID = c.XID
				for path, state := range live {
					state.Node.Identity.View = uint64(c.XID)
					live[path] = state
				}
				if got := snapshotStates(t, &c.Volumes[0]); !reflect.DeepEqual(got, live) {
					for path, before := range live {
						if !reflect.DeepEqual(got[path], before) {
							t.Errorf("live %s node before=%+v after=%+v dataEqual=%t attrsEqual=%t", path, before.Node, got[path].Node, bytes.Equal(before.Data, got[path].Data), reflect.DeepEqual(before.Attrs, got[path].Attrs))
						}
					}
					t.Fatal("deletion changed live state", name)
				}
				for _, snapshot := range remaining {
					if !reflect.DeepEqual(snapshot, inventory[snapshot.Name]) {
						t.Fatal("deletion changed surviving snapshot identity", snapshot, inventory[snapshot.Name])
					}
					view, err := c.Volumes[0].OpenSnapshotName(context.Background(), snapshot.Name)
					if err != nil || !reflect.DeepEqual(snapshotStates(t, view), wanted[snapshot.Name]) {
						t.Fatal("deletion changed surviving history", name, snapshot.Name, err)
					}
				}
				if _, err := c.Volumes[0].OpenSnapshotName(context.Background(), name); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("deleted snapshot still opens", name, err)
				}
				if _, err := c.Volumes[0].OpenSnapshot(context.Background(), inventory[name].XID); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("deleted snapshot XID still opens", name, err)
				}
				if _, err := InspectStorage(context.Background(), disk); err != nil {
					t.Fatal("delete accounting", name, err)
				}
			}
		})
	}
	if sha256.Sum256(input) != inputSHA {
		t.Fatal("immutable regression input changed")
	}
}
