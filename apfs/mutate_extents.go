package apfs

import (
	"math"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// releaseExtent releases one stream's reference to a physical interval. A
// clone's independent fork/attribute stream can share all or part of another
// stream's allocation. Preserve every surviving reference and the original
// owning_obj_id hint, including when that original inode no longer exists.
func (m *mutation) releaseExtent(address, blocks uint64) error {
	return m.changeExtentReferences(address, blocks, -1)
}

func (m *mutation) retainExtent(address, blocks uint64) error {
	return m.changeExtentReferences(address, blocks, 1)
}

func (m *mutation) changeExtentReferences(address, blocks uint64, delta int64) error {
	if blocks == 0 || address >= m.c.BlockCount || blocks > m.c.BlockCount-address {
		return corrupt("released extent range", 0)
	}
	end := address + blocks
	for at := address; at < end; {
		r, ok := m.extents.floor(buildKey(at, 2, 0))
		if !ok || prefix(r.key).kind != 2 || len(r.value) != 20 {
			return corrupt("released extent ownership", 0)
		}
		start := prefix(r.key).id
		length := le.Uint64(r.value) & objectMask
		refs := int32(le.Uint32(r.value[16:]))
		if length == 0 || start > at || start >= m.c.BlockCount || length > m.c.BlockCount-start || start+length <= at || le.Uint64(r.value)>>60 != 1 || refs <= 0 {
			return corrupt("released extent coverage", 0)
		}
		stop := min(end, start+length)
		if int64(refs)+delta > math.MaxInt32 {
			return filesystem.ErrLimit
		}
		owner := le.Uint64(r.value[8:])
		if err := m.extents.put(r.key, nil); err != nil {
			return err
		}
		for _, keep := range [][3]uint64{{start, at - start, uint64(refs)}, {at, stop - at, uint64(int64(refs) + delta)}, {stop, start + length - stop, uint64(refs)}} {
			if keep[1] == 0 {
				continue
			}
			if keep[2] == 0 {
				if err := m.space.retire(false, keep[0], keep[1]); err != nil {
					return err
				}
				m.freed += keep[1]
				continue
			}
			record := buildExtentReference(keep[0], keep[1], owner)
			le.PutUint32(record.value[16:], uint32(keep[2]))
			if err := m.extents.put(record.key, record.value); err != nil {
				return err
			}
		}
		at = stop
	}
	return nil
}
