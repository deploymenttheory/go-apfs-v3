package apfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// This explicitly synthetic format fixture retains the already built clone
// tree, physical extent tree and a UUID metadata version. It creates no native
// oracle and calls no snapshot mutation operation: existing Apple histories
// independently qualify admission and continued native allocation.
func snapshotMutationImage(t *testing.T) []byte {
	t.Helper()
	disk := newCloneMutationDisk(cloneMutationImage(t))
	retainSyntheticSnapshot(t, disk, "")
	return bytes.Clone(disk.data)
}

func retainSyntheticSnapshot(t *testing.T, disk MutableSource, volume string) {
	t.Helper()
	m, err := openMutationVolume(context.Background(), disk, volume)
	if err != nil {
		t.Fatal(err)
	}
	xid := uint64(m.c.XID)
	physicalTree := func(records []buildRecord, subtype uint32, fixed bool) *cowTree {
		t.Helper()
		b, err := newBuildTree(records, subtype, 0x40000000, fixed)
		if err != nil {
			t.Fatal(err)
		}
		if subtype == 19 {
			b.keySize, b.longestKey = 8, 8
		}
		tree := &cowTree{buildTree: b, rootNode: b.root(), dirty: map[*buildTreeNode]bool{}, less: (&volumeLayout{}).recordLess, newOID: m.nextOID}
		for _, n := range b.nodes {
			n.oid, err = m.nextOID()
			if err != nil {
				t.Fatal(err)
			}
			tree.dirty[n] = true
		}
		return tree
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
	name := "retained-history"
	value := make([]byte, 50+len(name)+1)
	le.PutUint64(value, m.extents.rootNode.address)
	le.PutUint64(value[8:], address)
	le.PutUint64(value[16:], uint64(builtClock.UnixNano()))
	le.PutUint64(value[24:], uint64(builtClock.UnixNano()))
	le.PutUint32(value[40:], 0x40000002)
	le.PutUint16(value[48:], uint16(len(name)+1))
	copy(value[50:], name)
	nameKey := buildKey(objectMask, 11, 2+len(name)+1)
	le.PutUint16(nameKey[8:], uint16(len(name)+1))
	copy(nameKey[10:], name)
	if err := m.retireMetadata(uint64(m.v.snapMeta), true); err != nil {
		t.Fatal(err)
	}
	metadata := physicalTree([]buildRecord{{buildKey(xid, 1, 0), value}, {nameKey, buildUint64(xid)}}, 16, false)
	if err := m.writeTree(metadata, true); err != nil {
		t.Fatal(err)
	}
	snapshots := physicalTree([]buildRecord{{buildUint64(xid), make([]byte, 16)}}, 19, true)
	if err := m.writeTree(snapshots, true); err != nil {
		t.Fatal(err)
	}
	// Extended metadata is a virtual object selected by snapshot XID through
	// the live object map, not by the snapshot superblock's stale omap pointer.
	uuidOID, err := m.nextOID()
	if err != nil {
		t.Fatal(err)
	}
	uuidAddress, err := m.allocateMetadata(true)
	if err != nil {
		t.Fatal(err)
	}
	uuid := make([]byte, 4096)
	le.PutUint32(uuid[32:], 1)
	le.PutUint64(uuid[40:], xid)
	copy(uuid[48:], []byte("historical UUID!"))
	sealObject(uuid, uuidOID, xid, 29, 0)
	if err := m.write(uuid, uuidAddress*4096); err != nil {
		t.Fatal(err)
	}
	mapping := make([]byte, 16)
	le.PutUint32(mapping[4:], 4096)
	le.PutUint64(mapping[8:], uuidAddress)
	if err := m.vmap.put(append(buildUint64(uuidOID), buildUint64(xid)...), mapping); err != nil {
		t.Fatal(err)
	}
	le.PutUint32(m.volumeMap[36:], 1)
	le.PutUint32(m.volumeMap[44:], 0x40000002)
	le.PutUint64(m.volumeMap[56:], snapshots.rootNode.address)
	le.PutUint64(m.volumeMap[64:], xid)
	le.PutUint32(m.super[124:], 0x40000002)
	le.PutUint64(m.super[152:], metadata.rootNode.address)
	le.PutUint64(m.super[216:], 1)
	le.PutUint64(m.super[1000:], uuidOID)
	m.extents = physicalTree(nil, 15, false)
	if err := m.commit(uint64(builtClock.UnixNano())); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectStorage(context.Background(), disk); err != nil {
		t.Fatalf("synthetic history must reconcile independently before its writer regression (allocated %d freed %d): %v", m.allocated, m.freed, err)
	}
}

type snapshotObjectState struct {
	Node  filesystem.Node
	Data  []byte
	Attrs map[string][]byte
}

func snapshotStates(t *testing.T, reader filesystem.Reader) map[string]snapshotObjectState {
	t.Helper()
	ctx := context.Background()
	result := map[string]snapshotObjectState{}
	read := func(value filesystem.Value, err error) []byte {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		data := make([]byte, value.Size())
		_, readErr := value.ReadAt(data, 0)
		closeErr := value.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil {
			t.Fatal(readErr, closeErr)
		}
		return data
	}
	for _, path := range []string{"/source", "/clone-a", "/clone-alias", "/clone-b", "/independent"} {
		id, err := filesystem.LookupExact(ctx, reader, path)
		if err != nil {
			t.Fatal(path, err)
		}
		node, err := reader.Stat(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		state := snapshotObjectState{Node: node, Data: read(reader.OpenData(ctx, id)), Attrs: map[string][]byte{}}
		if err := reader.ListAttributes(ctx, id, func(name string) error {
			state.Attrs[name] = read(reader.OpenAttribute(ctx, id, name))
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		result[path] = state
	}
	return result
}

func TestSnapshotLiveEditsPreserveHistoricalVersionsStreamsAndUUID(t *testing.T) {
	ctx := context.Background()
	original := snapshotMutationImage(t)
	digest := sha256.Sum256(original)
	disk := newCloneMutationDisk(original)
	container, err := Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	volume := &container.Volumes[0]
	var snapshots []Snapshot
	if err := volume.ListSnapshots(ctx, func(s Snapshot) error { snapshots = append(snapshots, s); return nil }); err != nil || len(snapshots) != 1 || snapshots[0].UUID.State != filesystem.Present {
		t.Fatal(snapshots, err)
	}
	history, err := volume.OpenSnapshot(ctx, snapshots[0].XID)
	if err != nil {
		t.Fatal(err)
	}
	want := snapshotStates(t, history)
	for round := 0; round < 12; round++ {
		payload := bytes.Repeat([]byte(fmt.Sprintf("live round %d\n", round)), 701)
		changes := []Change{{Path: "/clone-a", Data: bytes.NewReader(payload)}, {Path: "/clone-b", ResourceFork: true, Data: bytes.NewReader(payload)}, {Operation: "xattr", Path: "/source", Attribute: "org.go-apfs.large", Data: bytes.NewReader(payload)}}
		if round == 3 {
			changes = append(changes, Change{Operation: "clone", Path: "/clone-b", Destination: "/new-clone", ActorUID: filesystem.Observed(uint32(0))})
		}
		if round == 4 {
			changes = append(changes, Change{Operation: "rm", Path: "/new-clone"})
		}
		if _, err := ModifyVolume(ctx, disk, volume.UUID, changes, builtClock); err != nil {
			t.Fatalf("live edit %d: %v", round, err)
		}
		if _, err := InspectStorage(ctx, disk); err != nil {
			t.Fatalf("live edit %d accounting: %v", round, err)
		}
		container, err = Open(disk)
		if err != nil {
			t.Fatal(err)
		}
		volume = &container.Volumes[0]
		for _, reader := range []struct{ byName bool }{{false}, {true}} {
			if reader.byName {
				history, err = volume.OpenSnapshotName(ctx, snapshots[0].Name)
			} else {
				history, err = volume.OpenSnapshot(ctx, snapshots[0].XID)
			}
			if err != nil {
				t.Fatal(err)
			}
			if got := snapshotStates(t, history); !reflect.DeepEqual(got, want) {
				t.Fatalf("round %d changed historical files or IDs", round)
			}
		}
		var got []Snapshot
		if err := volume.ListSnapshots(ctx, func(s Snapshot) error { got = append(got, s); return nil }); err != nil || !reflect.DeepEqual(got, snapshots) {
			t.Fatal("snapshot identity changed", got, err)
		}
	}
	if sha256.Sum256(original) != digest {
		t.Fatal("immutable source changed")
	}
}

func TestSnapshotFinalLiveOwnerRemovalRetainsHistoryAndReclaimsOnlyNewAllocation(t *testing.T) {
	ctx := context.Background()
	disk := newCloneMutationDisk(snapshotMutationImage(t))
	c, err := Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	history, err := c.Volumes[0].OpenSnapshotName(ctx, "retained-history")
	if err != nil {
		t.Fatal(err)
	}
	want := snapshotStates(t, history)
	var changes []Change
	for path := range want {
		changes = append(changes, Change{Operation: "rm", Path: path})
	}
	if _, err := Modify(ctx, disk, changes, builtClock); err != nil {
		t.Fatal(err)
	}
	var stable uint64
	for round := 0; round < 8; round++ {
		payload := bytes.Repeat([]byte("live allocation only"), 12000)
		if _, err := Modify(ctx, disk, []Change{{Path: "/reuse", Data: bytes.NewReader(payload)}}, builtClock); err != nil {
			t.Fatal(err)
		}
		if got := cloneContents(t, disk, "/reuse", ""); !bytes.Equal(got, payload) {
			t.Fatal("allocation readback")
		}
		if _, err := Modify(ctx, disk, []Change{{Operation: "rm", Path: "/reuse"}}, builtClock); err != nil {
			t.Fatal(err)
		}
		report, err := InspectStorage(ctx, disk)
		if err != nil {
			t.Fatal(err)
		}
		if round == 2 {
			stable = report.FreeBlocks
		} else if round > 2 && report.FreeBlocks != stable {
			t.Fatal("unretained live replacements leaked allocation", round, stable, report.FreeBlocks)
		}
		c, err = Open(disk)
		if err != nil {
			t.Fatal(err)
		}
		history, err = c.Volumes[0].OpenSnapshotName(ctx, "retained-history")
		if err != nil {
			t.Fatal(err)
		}
		if got := snapshotStates(t, history); !reflect.DeepEqual(got, want) {
			t.Fatal("final live unlink or allocation changed snapshot")
		}
		for path := range want {
			if _, err := filesystem.LookupExact(ctx, &c.Volumes[0], path); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("removed live name survives", path, err)
			}
		}
	}
}

func TestSnapshotFailedWritesRetainTheSelectedHistoricalRoots(t *testing.T) {
	ctx := context.Background()
	original := snapshotMutationImage(t)
	c, err := Open(bytes.NewReader(original))
	if err != nil {
		t.Fatal(err)
	}
	history, err := c.Volumes[0].OpenSnapshotName(ctx, "retained-history")
	if err != nil {
		t.Fatal(err)
	}
	want := snapshotStates(t, history)
	change := func() []Change {
		return []Change{{Path: "/clone-a", Data: bytes.NewReader(bytes.Repeat([]byte("new data"), 1027))}, {Path: "/clone-a", ResourceFork: true, Data: bytes.NewReader(bytes.Repeat([]byte("new fork"), 1027))}}
	}
	completed := newCloneMutationDisk(original)
	if _, err := Modify(ctx, completed, change(), builtClock); err != nil {
		t.Fatal(err)
	}
	for fail := 1; fail <= completed.writes; fail++ {
		disk := newCloneMutationDisk(original)
		disk.failAt = fail
		if _, err := Modify(ctx, disk, change(), builtClock); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal("write failure lost", fail, err)
		}
		c, err := Open(disk)
		if err != nil {
			t.Fatal("selected recovery checkpoint lost", fail, err)
		}
		history, err := c.Volumes[0].OpenSnapshotName(ctx, "retained-history")
		if err != nil {
			t.Fatal("historical root lost", fail, err)
		}
		if got := snapshotStates(t, history); !reflect.DeepEqual(got, want) {
			t.Fatal("failed write damaged history", fail)
		}
	}
	full := newCloneMutationDisk(original)
	if _, err := Modify(ctx, full, []Change{{Path: "/clone-a", Data: bytes.NewReader(make([]byte, len(original)))}}, builtClock); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal("full scratch did not refuse", err)
	}
	c, err = Open(full)
	if err != nil {
		t.Fatal(err)
	}
	history, err = c.Volumes[0].OpenSnapshotName(ctx, "retained-history")
	if err != nil {
		t.Fatal(err)
	}
	if got := snapshotStates(t, history); !reflect.DeepEqual(got, want) {
		t.Fatal("allocation pressure changed retained history")
	}
}

type snapshotSparseFile struct {
	*os.File
	size, position int64
}

func (f *snapshotSparseFile) Size() int64 { return f.size }
func (f *snapshotSparseFile) Write(data []byte) (int, error) {
	if bytes.Count(data, []byte{0}) == len(data) {
		if err := f.Truncate(f.position + int64(len(data))); err != nil {
			return 0, err
		}
	} else if n, err := f.WriteAt(data, f.position); err != nil || n != len(data) {
		return n, errors.Join(err, io.ErrShortWrite)
	}
	f.position += int64(len(data))
	return len(data), nil
}

func snapshotVolumeBytes(t *testing.T, disk MutableSource, uuid string) string {
	t.Helper()
	ctx := context.Background()
	c, err := Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	s, err := newStorageChecker(ctx, c)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.check(); err != nil {
		t.Fatal(err)
	}
	var addresses []uint64
	for address, object := range s.metadata {
		if object.volume == uuid {
			addresses = append(addresses, address)
		}
	}
	for _, volume := range s.volumes {
		if volume.v.UUID == uuid {
			addresses = append(addresses, volume.address)
			for _, r := range volume.data {
				for address := r.start; address < r.end; address++ {
					addresses = append(addresses, address)
				}
			}
		}
	}
	slices.Sort(addresses)
	addresses = slices.Compact(addresses)
	h := sha256.New()
	data := make([]byte, 4096)
	for _, address := range addresses {
		if _, err := disk.ReadAt(data, int64(address)*4096); err != nil {
			t.Fatal(err)
		}
		_, _ = h.Write(buildUint64(address))
		_, _ = h.Write(data)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

func TestSnapshotVolumeEditsPreserveAllPeerHistoryAndStorageBytes(t *testing.T) {
	ctx := context.Background()
	seed := newCloneMutationDisk(cloneMutationImage(t))
	source, err := Open(seed)
	if err != nil {
		t.Fatal(err)
	}
	plan, err := PlanContainer(ctx, []VolumeSpec{{Reader: &source.Volumes[0], Name: "First"}, {Reader: &source.Volumes[0], Name: "Second"}}, ContainerBuildOptions{Time: builtClock, Capacity: (512 << 20) + 4096})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "histories.raw"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := f.Close(); err != nil {
			t.Error(err)
		}
	})
	disk := &snapshotSparseFile{File: f, size: plan.Size()}
	if err := plan.Write(ctx, disk); err != nil {
		t.Fatal(err)
	}
	c, err := Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	for _, volume := range c.Volumes {
		retainSyntheticSnapshot(t, disk, volume.UUID)
	}
	for index, volume := range c.Volumes {
		peer := c.Volumes[1-index].UUID
		before := snapshotVolumeBytes(t, disk, peer)
		for round := 0; round < 3; round++ {
			if _, err := ModifyVolume(ctx, disk, volume.UUID, []Change{{Path: "/clone-a", Data: bytes.NewReader([]byte(fmt.Sprintf("selected %d/%d", index, round)))}}, builtClock); err != nil {
				t.Fatal(err)
			}
			if got := snapshotVolumeBytes(t, disk, peer); got != before {
				t.Fatal("editing one volume changed peer metadata/history/data storage")
			}
		}
	}
}

func TestSnapshotMutationRefusesUnknownOrCorruptHistoryBeforeWriting(t *testing.T) {
	for _, fault := range []string{"pending object-map snapshot", "historical extent count", "unsupported UUID version", "snapshot flags"} {
		t.Run(fault, func(t *testing.T) {
			original := snapshotMutationImage(t)
			digest := sha256.Sum256(original)
			disk := &storageFaultSource{Source: bytes.NewReader(original), patches: map[uint64][]byte{}}
			container, err := Open(disk)
			if err != nil {
				t.Fatal(err)
			}
			s, err := newStorageChecker(context.Background(), container)
			if err != nil {
				t.Fatal(err)
			}
			if err := s.check(); err != nil {
				t.Fatal(err)
			}
			volume := s.volumes[0]
			want := filesystem.ErrUnsupported
			switch fault {
			case "pending object-map snapshot":
				tree, err := s.tree(le.Uint64(volume.mapHeader[56:]), 19, volume.v.UUID, func(a, b []byte) bool { return le.Uint64(a) < le.Uint64(b) })
				if err != nil {
					t.Fatal(err)
				}
				patchStorageRecord(t, disk, tree, func(buildRecord) bool { return true }, func(r buildRecord) { le.PutUint32(r.value, 1) })
			case "historical extent count":
				want = filesystem.ErrCorrupt
				patchStorageRecord(t, disk, volume.views[0].extents, func(buildRecord) bool { return true }, func(r buildRecord) { le.PutUint32(r.value[16:], le.Uint32(r.value[16:])+1) })
			case "unsupported UUID version":
				mapping, err := storageMapping(volume.omap, volume.v.snapMetaExt, volume.snapshots[0].XID)
				if err != nil {
					t.Fatal(err)
				}
				address := uint64(mapping.address)
				data := bytes.Clone(original[address*4096 : (address+1)*4096])
				le.PutUint32(data[32:], 2)
				seal(data)
				disk.patches[address] = data
			case "snapshot flags":
				tree, err := s.tree(uint64(volume.v.snapMeta), 16, volume.v.UUID, (&volumeLayout{}).recordLess)
				if err != nil {
					t.Fatal(err)
				}
				patchStorageRecord(t, disk, tree, func(r buildRecord) bool { return prefix(r.key).kind == 1 }, func(r buildRecord) { le.PutUint32(r.value[44:], 1) })
			}
			if err := ValidateMutation(context.Background(), disk); !errors.Is(err, want) {
				t.Fatal("history refusal changed", err)
			}
			_, err = ModifyVolume(context.Background(), disk, volume.v.UUID, []Change{{Path: "/source", Data: bytes.NewReader([]byte("must not write"))}}, builtClock)
			if !errors.Is(err, want) || disk.writes != 0 || sha256.Sum256(original) != digest {
				t.Fatal("unknown/corrupt history reached writes", err, disk.writes)
			}
		})
	}
}
