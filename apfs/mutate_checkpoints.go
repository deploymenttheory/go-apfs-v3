package apfs

// prepareReuse retires older checkpoint descriptors in the unpublished copy
// before the first allocation or write can overwrite their deferred blocks.
// The selected checkpoint's descriptors/data and all of its allocations remain
// protected until publication. No-op commands perform no retirement or writes.
func (m *mutation) prepareReuse() error {
	if m.reusePrepared {
		return m.ctx.Err()
	}
	count, base := le.Uint32(m.nx[104:]), le.Uint64(m.nx[112:])
	start, length := le.Uint32(m.nx[136:]), le.Uint32(m.nx[140:])
	zero := make([]byte, 4096)
	for i := uint32(0); i < count; i++ {
		if (i+count-start)%count < length {
			continue
		}
		if err := m.writeBytes(zero, (base+uint64(i))*4096); err != nil {
			return err
		}
	}
	m.reusePrepared = true
	return m.space.reclaim()
}
