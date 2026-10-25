package apfs

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"slices"
	"time"
)

// SnapshotSelector identifies exactly one snapshot by its exact name or XID.
type SnapshotSelector struct {
	Name string
	XID  XID
}

// DeleteSnapshot removes one retained view from an exclusively owned,
// unpublished copy. Surviving views retain their identities and contents.
// Retired allocations enter the checkpoint-protected free queue; they are not
// made immediately reusable. Any error invalidates the unpublished copy.
func DeleteSnapshot(ctx context.Context, disk MutableSource, volumeUUID string, selector SnapshotSelector, when time.Time) (ChangeReport, error) {
	var report ChangeReport
	if disk == nil || (selector.Name == "") == (selector.XID == 0) || selector.Name != "" && !validSnapshotName(selector.Name) || when.IsZero() || when.Nanosecond() != 0 {
		return report, fs.ErrInvalid
	}
	stamp, err := buildTime(when)
	if err != nil {
		return report, err
	}
	m, err := openMutationVolume(ctx, disk, volumeUUID)
	if err != nil {
		return report, err
	}
	if volumeUUID == "" && len(m.c.Volumes) > 1 {
		return report, fmt.Errorf("select an APFS volume UUID in a multiple-volume container: %w", fs.ErrInvalid)
	}
	index := slices.IndexFunc(m.ownership.snapshots, func(snapshot snapshotRecord) bool {
		return selector.Name != "" && snapshot.Name == selector.Name || selector.XID != 0 && snapshot.XID == selector.XID
	})
	if index < 0 {
		return report, fs.ErrNotExist
	}
	if err = m.deleteSnapshot(index); err != nil {
		return report, err
	}
	if err = m.commit(stamp); err != nil {
		return report, err
	}
	return ChangeReport{VolumeID: m.v.UUID, FreeBlocks: m.space.free, Transaction: m.xid}, nil
}

func (m *mutation) snapshotTree(root uint64, subtype uint32) (*cowTree, error) {
	less := (&volumeLayout{options: VolumeSpec{CaseSensitive: m.v.CaseSensitive}}).recordLess
	if subtype == 19 {
		less = func(a, b []byte) bool { return le.Uint64(a) < le.Uint64(b) }
	}
	return loadCOWTree(m.ctx, root, subtype, 0x40000000, func(address uint64) ([]byte, uint64, error) {
		b, err := m.readObject(address, 0, 0x40000000)
		return b, address, err
	}, less, m.nextOID)
}

func (m *mutation) deleteSnapshot(deleted int) error {
	state, oldHistory := m.ownership, m.history
	metadata, err := m.snapshotTree(uint64(m.v.snapMeta), 16)
	if err != nil {
		return err
	}
	membership, err := m.snapshotTree(le.Uint64(m.volumeMap[56:]), 19)
	if err != nil {
		return err
	}
	snapshot := state.snapshots[deleted]
	for _, record := range metadata.all() {
		p := prefix(record.key)
		if p.kind == 1 && p.id == uint64(snapshot.XID) || p.kind == 11 && XID(le.Uint64(record.value)) == snapshot.XID {
			if err = metadata.put(record.key, nil); err != nil {
				return err
			}
		}
	}
	if err = membership.put(buildUint64(uint64(snapshot.XID)), nil); err != nil {
		return err
	}
	history := &mutationHistory{metadata: map[uint64]bool{}, owners: oldHistory.owners}
	owned := map[uint64]bool{}
	keepMappings := map[string]bool{}
	var data []storageExtent
	for i, view := range state.views {
		if i == deleted {
			continue
		}
		live := i == len(state.snapshots)
		xid := m.c.XID
		if !live {
			xid = state.snapshots[i].XID
			history.xids = append(history.xids, xid)
			history.metadata[uint64(state.snapshots[i].superblock)] = true
		}
		for _, node := range view.fs.nodes {
			record, ok := m.vmap.floor(append(buildUint64(node.oid), buildUint64(uint64(xid))...))
			if !ok || le.Uint64(record.key) != node.oid || le.Uint32(record.value) != 0 {
				return corrupt("snapshot deletion filesystem mapping", 0)
			}
			keepMappings[string(record.key)] = true
			owned[le.Uint64(record.value[8:])] = true
			if !live {
				history.metadata[le.Uint64(record.value[8:])] = true
			}
		}
		for _, r := range view.refs {
			if r.refs != 0 {
				data = append(data, r)
			}
		}
		if live {
			continue
		}
		if oid := uint64(m.v.snapMetaExt); oid != 0 {
			record, ok := m.vmap.floor(append(buildUint64(oid), buildUint64(uint64(xid))...))
			if !ok || le.Uint64(record.key) != oid || le.Uint32(record.value) != 0 {
				return corrupt("snapshot deletion UUID mapping", 0)
			}
			keepMappings[string(record.key)] = true
			history.metadata[le.Uint64(record.value[8:])] = true
		}
		// Deletion can remove known-zero coverage, so rebase the chain in
		// chronological order using the actual newly encoded predecessor.
		normalized, err := normalizeHistoryExtents(m.ctx, view.refs, oldHistory.owners)
		if err != nil {
			return err
		}
		records, err := encodeHistoryExtentRecords(m.ctx, normalized, history.base)
		if err != nil {
			return err
		}
		if !equalSnapshotExtentRecords(view.extents.all(), records) {
			view.extents.newOID = m.nextOID
			if err = replaceHistoryExtentRecords(m.ctx, view.extents, records); err != nil {
				return err
			}
			// Keep original history protections until all survivor trees have
			// been written; shared old nodes are retired by the final sweep.
			if err = m.writeTree(view.extents, true); err != nil {
				return err
			}
			key := buildKey(uint64(xid), 1, 0)
			record, ok := metadata.get(key)
			if !ok {
				return corrupt("snapshot deletion metadata", 0)
			}
			value := bytes.Clone(record.value)
			le.PutUint64(value, view.extents.rootNode.address)
			if err = metadata.put(key, value); err != nil {
				return err
			}
		}
		for _, node := range view.extents.nodes {
			history.metadata[node.address] = true
		}
		changes, err := readExtentChanges(records, m.c.BlockCount)
		if err != nil {
			return err
		}
		history.base, err = applyExtentChanges(m.ctx, history.base, changes)
		if err != nil {
			return err
		}
	}
	retainedData, err := countStreamExtents(m.ctx, data)
	if err != nil {
		return err
	}
	var historicalData []storageExtent
	for i, view := range state.views[:len(state.snapshots)] {
		if i != deleted {
			for _, r := range view.refs {
				if r.refs != 0 {
					historicalData = append(historicalData, r)
				}
			}
		}
	}
	history.data, err = countStreamExtents(m.ctx, historicalData)
	if err != nil {
		return err
	}
	// Drop versions with no reachable filesystem or snapshot UUID owner.
	// Recovery checkpoints keep their own physical object maps and free-queue
	// protections; removing a current mapping never frees its blocks early.
	candidates := oldHistory.metadata
	for _, record := range m.vmap.all() {
		if keepMappings[string(record.key)] {
			continue
		}
		if le.Uint32(record.value)&1 == 0 {
			candidates[le.Uint64(record.value[8:])] = true
		}
		if err = m.vmap.put(record.key, nil); err != nil {
			return err
		}
	}
	m.history = history
	count := uint64(len(history.xids))
	if count == 0 {
		m.history = nil
		le.PutUint64(m.super[1000:], 0)
	}
	// The live extent tree is retired by commit, including any old nodes it
	// shared with a historical tree. Avoid scheduling the same block twice.
	for _, node := range append(slices.Clone(m.extents.nodes), m.extents.removed...) {
		owned[node.address] = true
	}
	addresses := make([]uint64, 0, len(candidates))
	for address := range candidates {
		addresses = append(addresses, address)
	}
	slices.Sort(addresses)
	for _, address := range addresses {
		if owned[address] || history.metadata[address] || m.retired[address] {
			continue
		}
		if err = m.retireMetadata(address, address != uint64(snapshot.superblock)); err != nil {
			return err
		}
	}
	if err = m.retireSnapshotData(state.data, retainedData); err != nil {
		return err
	}
	if err = m.writeTree(metadata, true); err != nil {
		return err
	}
	if err = m.writeTree(membership, true); err != nil {
		return err
	}
	le.PutUint64(m.super[152:], metadata.rootNode.address)
	le.PutUint64(m.super[216:], count)
	le.PutUint32(m.volumeMap[36:], uint32(count))
	le.PutUint64(m.volumeMap[56:], membership.rootNode.address)
	var newest XID
	if count != 0 {
		newest = history.xids[count-1]
	}
	le.PutUint64(m.volumeMap[64:], uint64(newest))
	return nil
}

func equalSnapshotExtentRecords(a, b []buildRecord) bool {
	return slices.EqualFunc(a, b, func(a, b buildRecord) bool {
		return bytes.Equal(a.key, b.key) && bytes.Equal(a.value, b.value)
	})
}

func (m *mutation) retireSnapshotData(previous, retained []storageExtent) error {
	j := 0
	for _, r := range previous {
		for at := r.start; at < r.end; {
			for j < len(retained) && retained[j].end <= at {
				j++
			}
			if j < len(retained) && retained[j].start <= at {
				at = min(r.end, retained[j].end)
				continue
			}
			end := r.end
			if j < len(retained) {
				end = min(end, retained[j].start)
			}
			if err := m.retireData(at, end-at); err != nil {
				return err
			}
			at = end
		}
	}
	return nil
}
