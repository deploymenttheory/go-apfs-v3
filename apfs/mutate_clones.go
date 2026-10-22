package apfs

import "bytes"

// A private-ID hint can survive on a descriptor-less compressed or empty
// inode, including when another inode owns that ID's data. Only an actual
// INO_EXT_TYPE_DSTREAM descriptor owns a stream reference.
func inodeDataStreamID(inode []byte) (uint64, error) {
	if len(inode) < 92 {
		return 0, corrupt("changed inode stream", 0)
	}
	found := false
	if err := extendedFields(inode[92:], func(kind byte, data []byte) error {
		if kind == 8 {
			if found || len(data) != 40 {
				return corrupt("changed inode stream descriptor", 0)
			}
			found = true
		}
		return nil
	}); err != nil {
		return 0, err
	}
	if !found {
		return 0, nil
	}
	id := le.Uint64(inode[8:])
	if id == 0 || id > objectMask {
		return 0, corrupt("changed inode stream ID", 0)
	}
	return id, nil
}

// Stream references count inode/attribute descriptors, not hard-link names.
// The shared storage checker reconciles them before any mutation. Attributes
// with one owner may omit the reference record entirely.
func (m *mutation) streamReferenceCount(id uint64) (uint32, error) {
	r, present := m.fs.get(buildKey(id, 6, 0))
	if !present {
		return 1, nil
	}
	if len(r.value) != 4 || le.Uint32(r.value) == 0 {
		return 0, corrupt("changed stream reference count", 0)
	}
	return le.Uint32(r.value), nil
}

// A whole-data replacement needs a private stream only when other inodes
// still use its records. Its new storage remains ordinary allocated COW data;
// no untouched sibling's stream or physical mapping is rewritten.
func (m *mutation) privateDataStream(inode []byte) (uint64, error) {
	id, err := inodeDataStreamID(inode)
	if err != nil {
		return 0, err
	}
	if id == 0 {
		return m.nextFileID()
	}
	refs, err := m.streamReferenceCount(id)
	if err != nil || refs == 1 {
		return id, err
	}
	if err = m.releaseStreamReference(id); err != nil {
		return 0, err
	}
	return m.nextFileID()
}

func (m *mutation) releaseStreamReference(id uint64) error {
	if id == 0 {
		return nil
	}
	refs, err := m.streamReferenceCount(id)
	if err != nil {
		return err
	}
	key := buildKey(id, 6, 0)
	if refs > 1 {
		r, _ := m.fs.get(key)
		value := bytes.Clone(r.value)
		le.PutUint32(value, refs-1)
		return m.fs.put(key, value)
	}
	// Distinct stream IDs may themselves reference shared physical intervals.
	// removeStream decrements those interval counts and retires only last use.
	if err = m.removeStream(id); err != nil {
		return err
	}
	return m.fs.put(key, nil)
}
