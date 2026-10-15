package apfs

import (
	"context"
	"math"
	"slices"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Physical extent reference counts are signed. UPDATE records change the
// preceding retained tree; they are not standalone allocations. Keep known
// zero-count ranges so an UPDATE cannot manufacture an unknown allocation.
type storageExtent struct {
	start, end uint64
	refs       int64
}

type extentChange struct {
	storageExtent
	new bool
}

type extentEvent struct {
	at                 uint64
	base, fresh, delta int64
	baseN, newN, diffN int
}

const maxStorageRecords = 1 << 20

func readExtentChanges(records []buildRecord, blocks uint64) ([]extentChange, error) {
	if len(records) > maxStorageRecords {
		return nil, filesystem.ErrLimit
	}
	changes := make([]extentChange, 0, len(records))
	var end uint64
	for _, r := range records {
		if len(r.key) != 8 || len(r.value) != 20 || prefix(r.key).kind != 2 {
			return nil, corrupt("physical extent record bounds", 0)
		}
		p := prefix(r.key)
		length, kind := le.Uint64(r.value)&objectMask, le.Uint64(r.value)>>60
		refs := int64(int32(le.Uint32(r.value[16:])))
		if length == 0 || p.id >= blocks || length > blocks-p.id || p.id < end {
			return nil, corrupt("physical extent range or overlap", 0)
		}
		if kind != 1 && kind != 2 {
			return nil, filesystem.ErrUnsupported
		}
		if kind == 1 && (refs <= 0 || le.Uint64(r.value[8:]) == 0 || le.Uint64(r.value[8:]) > objectMask) {
			return nil, corrupt("new physical extent reference", 0)
		}
		end = p.id + length
		changes = append(changes, extentChange{storageExtent{p.id, end, refs}, kind == 1})
	}
	return changes, nil
}

// applyExtentChanges merges sorted interval boundaries. Work and memory depend
// on metadata ranges, never on the number of blocks covered by a data extent.
func applyExtentChanges(ctx context.Context, base []storageExtent, changes []extentChange) ([]storageExtent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(base) > maxStorageRecords || len(changes) > maxStorageRecords || len(base)+len(changes) > maxStorageRecords {
		return nil, filesystem.ErrLimit
	}
	events := make([]extentEvent, 0, 2*(len(base)+len(changes)))
	for _, r := range base {
		if r.start >= r.end || r.refs < 0 || r.refs > math.MaxInt32 {
			return nil, corrupt("retained physical extent bounds/count", 0)
		}
		events = append(events, extentEvent{at: r.start, base: r.refs, baseN: 1}, extentEvent{at: r.end, base: -r.refs, baseN: -1})
	}
	for _, r := range changes {
		if r.start >= r.end || r.refs < math.MinInt32 || r.refs > math.MaxInt32 {
			return nil, corrupt("physical extent change bounds/count", 0)
		}
		if r.new {
			events = append(events, extentEvent{at: r.start, fresh: r.refs, newN: 1}, extentEvent{at: r.end, fresh: -r.refs, newN: -1})
		} else {
			events = append(events, extentEvent{at: r.start, delta: r.refs, diffN: 1}, extentEvent{at: r.end, delta: -r.refs, diffN: -1})
		}
	}
	slices.SortFunc(events, func(a, b extentEvent) int {
		if a.at < b.at {
			return -1
		}
		if a.at > b.at {
			return 1
		}
		return 0
	})
	var active extentEvent
	var result []storageExtent
	for i := 0; i < len(events); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		at := events[i].at
		for i < len(events) && events[i].at == at {
			e := events[i]
			active.base += e.base
			active.fresh += e.fresh
			active.delta += e.delta
			active.baseN += e.baseN
			active.newN += e.newN
			active.diffN += e.diffN
			i++
		}
		if i == len(events) {
			if active.base != 0 || active.fresh != 0 || active.delta != 0 || active.baseN != 0 || active.newN != 0 || active.diffN != 0 {
				return nil, corrupt("unbalanced physical extent references", 0)
			}
			break
		}
		if active.baseN < 0 || active.baseN > 1 || active.newN < 0 || active.diffN < 0 || active.newN+active.diffN > 1 || active.newN != 0 && active.baseN != 0 || active.diffN != 0 && active.baseN == 0 {
			return nil, corrupt("physical extent history coverage", int64(at)*4096)
		}
		if active.baseN+active.newN == 0 {
			continue
		}
		refs := active.base + active.fresh + active.delta
		if refs < 0 || refs > math.MaxInt32 || active.newN != 0 && refs == 0 {
			return nil, corrupt("physical extent reference count", int64(at)*4096)
		}
		result = appendStorageExtent(result, storageExtent{at, events[i].at, refs})
	}
	return result, nil
}

func appendStorageExtent(ranges []storageExtent, r storageExtent) []storageExtent {
	if n := len(ranges); n != 0 && ranges[n-1].end == r.start && ranges[n-1].refs == r.refs {
		ranges[n-1].end = r.end
		return ranges
	}
	return append(ranges, r)
}

// countStreamExtents counts distinct file-extent records, not inode aliases or
// historical views. Several inodes can use one stream; several fork streams
// can instead reference the same physical range.
func countStreamExtents(ctx context.Context, ranges []storageExtent) ([]storageExtent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(ranges) > maxStorageRecords {
		return nil, filesystem.ErrLimit
	}
	events := make([]extentEvent, 0, 2*len(ranges))
	for _, r := range ranges {
		if r.start >= r.end {
			return nil, corrupt("empty stream extent", 0)
		}
		events = append(events, extentEvent{at: r.start, base: 1}, extentEvent{at: r.end, base: -1})
	}
	slices.SortFunc(events, func(a, b extentEvent) int {
		if a.at < b.at {
			return -1
		}
		if a.at > b.at {
			return 1
		}
		return 0
	})
	var count int64
	var result []storageExtent
	for i := 0; i < len(events); {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		at := events[i].at
		for i < len(events) && events[i].at == at {
			count += events[i].base
			i++
		}
		if count < 0 || count > math.MaxInt32 {
			return nil, corrupt("stream extent reference overflow", 0)
		}
		if i < len(events) && count != 0 {
			result = appendStorageExtent(result, storageExtent{at, events[i].at, count})
		}
	}
	if count != 0 {
		return nil, corrupt("unbalanced stream extent references", 0)
	}
	return result, nil
}

func equalExtentCounts(physical, streams []storageExtent) bool {
	i := 0
	for _, r := range physical {
		if r.refs == 0 {
			continue
		}
		if i == len(streams) || r != streams[i] {
			return false
		}
		i++
	}
	return i == len(streams)
}
