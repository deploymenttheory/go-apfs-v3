package apfs

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func (m *mutation) reservations() (reserved, allocated uint64, err error) {
	volumes := m.volumes
	if len(volumes) == 0 {
		volumes = []*mutation{m}
	}
	for _, volume := range volumes {
		reserve := volume.v.ReserveBlocks
		if reserve > m.c.BlockCount-reserved || volume.v.QuotaBlocks != 0 && reserve > volume.v.QuotaBlocks {
			return 0, 0, corrupt("volume reservation geometry", 0)
		}
		reserved += reserve
		allocated += min(reserve, le.Uint64(volume.super[88:]))
	}
	return reserved, allocated, nil
}

func (m *mutation) updateSpaceLimits(previous uint64) error {
	current := le.Uint64(m.super[88:])
	if quota := m.v.QuotaBlocks; quota != 0 && current > quota && current > previous {
		return fmt.Errorf("APFS volume %s quota exceeded: %w", m.v.UUID, filesystem.ErrLimit)
	}
	reserved, allocated, err := m.reservations()
	if err != nil {
		return err
	}
	if reserved-allocated > m.space.free {
		return fmt.Errorf("APFS remaining volume reservations exceed available allocation: %w", filesystem.ErrLimit)
	}
	le.PutUint64(m.space.data[184:], reserved)
	le.PutUint64(m.space.data[192:], allocated)
	return nil
}
