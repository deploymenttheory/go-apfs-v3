package apfs

import (
	"bytes"
	"context"
	"fmt"
	"math"
	"slices"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type historyExtentOwner struct{ start, end, owner uint64 }

// A snapshot owns its immutable roots and data independently of recovery
// checkpoints. The latter may be retired before reuse; these owners cannot.
// base is the newest snapshot's effective reference state, including known
// zero ranges. The current extent tree is normalized in memory only and encoded
// back to a NEW/UPDATE delta against base before writing its COW nodes.
type mutationHistory struct {
	xids       []XID
	metadata   map[uint64]bool
	data, base []storageExtent
	owners     []historyExtentOwner
}

func (m *mutation) admitHistory(volume *storageVolume, storage *storageChecker) error {
	h := &mutationHistory{metadata: map[uint64]bool{}}
	for _, snapshot := range volume.snapshots {
		h.xids = append(h.xids, snapshot.XID)
		h.metadata[uint64(snapshot.superblock)] = true
		if _, err := volume.v.snapshotUUID(snapshot.XID); err != nil {
			return err
		}
	}
	if len(volume.views) != len(h.xids)+1 || le.Uint64(volume.mapHeader[64:]) < uint64(h.xids[len(h.xids)-1]) || le.Uint64(volume.mapHeader[64:]) > uint64(m.c.XID) {
		return corrupt("mutation snapshot inventory", 0)
	}
	root := le.Uint64(volume.mapHeader[56:])
	snapshots, err := storage.tree(root, 19, volume.v.UUID, func(a, b []byte) bool { return le.Uint64(a) < le.Uint64(b) })
	if err != nil {
		return err
	}
	if int(snapshots.keyCount) != len(h.xids) {
		return fmt.Errorf("pending object-map snapshots: %w", filesystem.ErrUnsupported)
	}
	for i, record := range snapshots.all() {
		if le.Uint64(record.key) != uint64(h.xids[i]) || le.Uint32(record.value) != 0 {
			return fmt.Errorf("pending object-map snapshot: %w", filesystem.ErrUnsupported)
		}
	}
	for _, record := range volume.omap.all() {
		if le.Uint32(record.value)&1 != 0 {
			continue
		}
		address := le.Uint64(record.value[8:])
		object := storage.metadata[address]
		kind := object.kind &^ uint32(0x10000000)
		filesystemNode := object.subtype == 14 && (kind == 2 || kind == 3)
		snapshotMetadata := kind == 29 && object.oid == uint64(volume.v.snapMetaExt)
		if object.volume != volume.v.UUID || object.kind&0xc0000000 != 0 || !filesystemNode && !snapshotMetadata {
			return fmt.Errorf("snapshot object-map mutation profile: %w", filesystem.ErrUnsupported)
		}
	}
	// Peer histories are fully checked but are never normalized or committed
	// by an edit targeting another volume. The container-wide protection map
	// already retains every peer's current and historical allocation.
	if m != storage.reader.space.owner {
		return nil
	}
	// Each retained transaction chooses the predecessor for every virtual OID.
	// Deleted placeholders own no bytes, but must survive pruning as well.
	oids := map[uint64]bool{}
	for _, record := range volume.omap.all() {
		oids[le.Uint64(record.key)] = true
	}
	if len(oids) > maxStorageRecords/len(h.xids) {
		return filesystem.ErrLimit
	}
	for oid := range oids {
		if err := m.ctx.Err(); err != nil {
			return err
		}
		for _, xid := range h.xids {
			record, ok := volume.omap.floor(append(buildUint64(oid), buildUint64(uint64(xid))...))
			if ok && le.Uint64(record.key) == oid && le.Uint32(record.value)&1 == 0 {
				h.metadata[le.Uint64(record.value[8:])] = true
			}
		}
	}
	var data []storageExtent
	for i, view := range volume.views {
		if i < len(h.xids) {
			for _, node := range view.extents.nodes {
				h.metadata[node.address] = true
			}
			for _, r := range view.refs {
				if r.refs != 0 {
					if len(data) == maxStorageRecords {
						return filesystem.ErrLimit
					}
					data = append(data, r)
				}
			}
		}
		for _, record := range view.extents.all() {
			if le.Uint64(record.value)>>60 == 1 {
				if len(h.owners) == maxStorageRecords {
					return filesystem.ErrLimit
				}
				start := prefix(record.key).id
				h.owners = append(h.owners, historyExtentOwner{start, start + (le.Uint64(record.value) & objectMask), le.Uint64(record.value[8:])})
			}
		}
	}
	h.data, err = countStreamExtents(m.ctx, data)
	if err != nil {
		return err
	}
	h.base = volume.views[len(h.xids)-1].refs
	slices.SortFunc(h.owners, func(a, b historyExtentOwner) int {
		if a.start < b.start {
			return -1
		}
		if a.start > b.start {
			return 1
		}
		return 0
	})
	for i, r := range h.owners {
		if i > 0 && h.owners[i-1].end > r.start {
			return corrupt("snapshot extent owner overlap", 0)
		}
	}
	m.history = h
	normalized, err := normalizeHistoryExtents(m.ctx, volume.views[len(h.xids)].refs, h.owners)
	if err != nil {
		return err
	}
	return replaceHistoryExtentRecords(m.ctx, m.extents, normalized)
}

// normalizeHistoryExtents restores the original NEW owner boundaries to an
// effective reference state. Zero-count ranges remain in the reference state,
// but do not own an allocation and therefore have no normalized NEW record.
func normalizeHistoryExtents(ctx context.Context, refs []storageExtent, owners []historyExtentOwner) ([]buildRecord, error) {
	if len(refs) > maxStorageRecords || len(owners) > maxStorageRecords {
		return nil, filesystem.ErrLimit
	}
	var normalized []buildRecord
	ownerAt := 0
	for _, r := range refs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if r.start >= r.end || r.refs < 0 || r.refs > math.MaxInt32 {
			return nil, corrupt("snapshot effective reference bounds/count", 0)
		}
		if r.refs == 0 {
			continue
		}
		for at := r.start; at < r.end; {
			if len(normalized) == maxStorageRecords {
				return nil, filesystem.ErrLimit
			}
			for ownerAt < len(owners) && owners[ownerAt].end <= at {
				ownerAt++
			}
			if ownerAt == len(owners) || owners[ownerAt].start > at {
				return nil, corrupt("snapshot extent owner coverage", 0)
			}
			owner := owners[ownerAt]
			stop := min(r.end, owner.end)
			record := buildExtentReference(at, stop-at, owner.owner)
			le.PutUint32(record.value[16:], uint32(r.refs))
			normalized = append(normalized, record)
			at = stop
		}
	}
	return normalized, ctx.Err()
}

func replaceHistoryExtentRecords(ctx context.Context, tree *cowTree, records []buildRecord) error {
	if len(records) > maxStorageRecords {
		return filesystem.ErrLimit
	}
	for _, old := range tree.all() {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tree.put(old.key, nil); err != nil {
			return err
		}
	}
	for _, record := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tree.put(record.key, record.value); err != nil {
			return err
		}
	}
	return nil
}

func (m *mutation) pruneVolumeObject(oid uint64) error {
	if m.history == nil {
		return removeObjectVersions(m.vmap, oid)
	}
	previous := objectVersions(m.vmap, oid)
	if err := removeObjectVersions(m.vmap, oid, m.history.xids...); err != nil {
		return err
	}
	for _, record := range previous {
		if _, kept := m.vmap.get(record.key); kept || le.Uint32(record.value)&1 != 0 {
			continue
		}
		address := le.Uint64(record.value[8:])
		if !m.retired[address] {
			if err := m.retireMetadata(address, true); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *mutation) retireData(start, count uint64) error {
	retire := func(at, n uint64) error {
		if n == 0 {
			return nil
		}
		if err := m.space.retire(false, at, n); err != nil {
			return err
		}
		m.freed += n
		return nil
	}
	if m.history == nil {
		return retire(start, count)
	}
	end, at := start+count, start
	for _, r := range m.history.data {
		if r.end <= at {
			continue
		}
		if r.start >= end {
			break
		}
		if r.start > at {
			if err := retire(at, r.start-at); err != nil {
				return err
			}
		}
		at = max(at, min(r.end, end))
	}
	return retire(at, end-at)
}

func (m *mutation) encodeHistoryExtents() error {
	if m.history == nil {
		return nil
	}
	records, err := encodeHistoryExtentRecords(m.ctx, m.extents.all(), m.history.base)
	if err != nil {
		return err
	}
	return replaceHistoryExtentRecords(m.ctx, m.extents, records)
}

// encodeHistoryExtentRecords expresses normalized NEW current records as a
// delta against the preceding retained view, including its known-zero ranges.
// A caller rebasing a history chain must materialize the returned records with
// readExtentChanges and applyExtentChanges before encoding the following view.
func encodeHistoryExtentRecords(ctx context.Context, current []buildRecord, base []storageExtent) ([]buildRecord, error) {
	if len(current) > maxStorageRecords || len(base) > maxStorageRecords {
		return nil, filesystem.ErrLimit
	}
	var points []uint64
	for _, r := range base {
		points = append(points, r.start, r.end)
	}
	for _, r := range current {
		start := prefix(r.key).id
		points = append(points, start, start+(le.Uint64(r.value)&objectMask))
	}
	if len(points) > 4*maxStorageRecords {
		return nil, filesystem.ErrLimit
	}
	slices.Sort(points)
	points = slices.Compact(points)
	var records []buildRecord
	i, j := 0, 0
	for index := 0; index+1 < len(points); index++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		at, end := points[index], points[index+1]
		for i < len(base) && base[i].end <= at {
			i++
		}
		for j < len(current) && prefix(current[j].key).id+(le.Uint64(current[j].value)&objectMask) <= at {
			j++
		}
		known := i < len(base) && base[i].start <= at
		var old, now int64
		var owner uint64
		if known {
			old = base[i].refs
		}
		if j < len(current) && prefix(current[j].key).id <= at {
			now = int64(le.Uint32(current[j].value[16:]))
			owner = le.Uint64(current[j].value[8:])
		}
		if now < 0 || now > math.MaxInt32 {
			return nil, corrupt("snapshot live reference count", 0)
		}
		if known && old == now || !known && now == 0 {
			continue
		}
		kind, refs := uint64(1), now
		if known {
			kind, refs = 2, now-old
			// UPDATE changes a retained allocation's count, not its owner.
			// Apple-written snapshot extent trees use INVALID here; fsck
			// rejects an ordinary stream owner even when the delta is sound.
			owner = owningObjectIDInvalid
		}
		if refs < math.MinInt32 || refs > math.MaxInt32 {
			return nil, filesystem.ErrLimit
		}
		record := buildExtentReference(at, end-at, owner)
		le.PutUint64(record.value, kind<<60|(end-at))
		le.PutUint32(record.value[16:], uint32(int32(refs)))
		if n := len(records); n > 0 {
			last := records[n-1]
			if prefix(last.key).id+(le.Uint64(last.value)&objectMask) == at && le.Uint64(last.value)>>60 == kind && bytes.Equal(last.value[8:], record.value[8:]) {
				le.PutUint64(last.value, kind<<60|(end-prefix(last.key).id))
				continue
			}
		}
		if len(records) == maxStorageRecords {
			return nil, filesystem.ErrLimit
		}
		records = append(records, record)
	}
	return records, ctx.Err()
}
