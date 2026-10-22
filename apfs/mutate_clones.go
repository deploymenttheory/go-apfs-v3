package apfs

import "bytes"

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
func (m *mutation) privateDataStream(id uint64) (uint64, error) {
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
