package apfs

// releaseExtent removes only the current stream's physical range. Apple may
// coalesce adjacent data and resource-fork ranges with the same owning_obj_id
// into one physical record; the surviving prefix/suffix must retain that owner.
func (m *mutation) releaseExtent(address, blocks uint64) error {
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
		if length == 0 || start > at || start >= m.c.BlockCount || length > m.c.BlockCount-start || start+length <= at || le.Uint32(r.value[16:]) != 1 {
			return corrupt("released extent coverage", 0)
		}
		stop := min(end, start+length)
		owner := le.Uint64(r.value[8:])
		if err := m.extents.put(r.key, nil); err != nil {
			return err
		}
		for _, keep := range [][2]uint64{{start, at - start}, {stop, start + length - stop}} {
			if keep[1] == 0 {
				continue
			}
			record := buildExtentReference(keep[0], keep[1], owner)
			if err := m.extents.put(record.key, record.value); err != nil {
				return err
			}
		}
		at = stop
	}
	return nil
}
