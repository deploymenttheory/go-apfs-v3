package apfs

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Keybags are container-owned physical allocations, outside volume fs_alloc_count.
// Their full extents must be claimed independently of ordinary metadata and data.
func (s *storageChecker) checkKeybags() error {
	c := s.c
	if c.keylockerStart == 0 && c.keylockerCount == 0 {
		for _, v := range c.Volumes {
			if v.Encrypted {
				return corrupt("encrypted volume has no keylocker", 0)
			}
		}
		return nil
	}
	entries, err := c.keybag(s.ctx, c.keylockerStart, c.keylockerCount, c.id, 0x6b657973)
	if err != nil {
		return err
	}
	s.keybagRanges = append(s.keybagRanges, storageExtent{c.keylockerStart, c.keylockerStart + c.keylockerCount, 1})
	seenKeys, seenRecords := map[[16]byte]bool{}, map[[16]byte]bool{}
	for _, entry := range entries {
		var v *Volume
		for i := range c.Volumes {
			if c.Volumes[i].id == entry.id {
				v = &c.Volumes[i]
				break
			}
		}
		if v == nil || !v.Encrypted {
			return fmt.Errorf("unowned keybag entry: %w", filesystem.ErrUnsupported)
		}
		switch entry.tag {
		case 2:
			if _, err := parseKeyRecord(entry.data, false); err != nil {
				return err
			}
			seenKeys[entry.id] = true
		case 3:
			if len(entry.data) != 16 {
				return corrupt("volume keybag extent record", 0)
			}
			start, count := le.Uint64(entry.data), le.Uint64(entry.data[8:])
			records, err := c.keybag(s.ctx, start, count, entry.id, 0x72656373)
			if err != nil {
				return err
			}
			// The retained native software profile has one Disk crypto user.
			// Other users need independent writer qualification before admission.
			users := 0
			for _, record := range records {
				if record.tag == 4 {
					continue // Inline passphrase hint; no additional allocation.
				}
				if record.tag != 3 || record.id != entry.id {
					return fmt.Errorf("software crypto-user profile: %w", filesystem.ErrUnsupported)
				}
				parsed, err := parseKeyRecord(record.data, true)
				if err != nil {
					return err
				}
				if parsed.id != record.id {
					return corrupt("crypto-user keybag identity", 0)
				}
				users++
			}
			if users != 1 {
				return fmt.Errorf("software crypto-user count: %w", filesystem.ErrUnsupported)
			}
			s.keybagRanges = append(s.keybagRanges, storageExtent{start, start + count, 1})
			seenRecords[entry.id] = true
		default:
			return fmt.Errorf("container keybag tag %d: %w", entry.tag, filesystem.ErrUnsupported)
		}
	}
	for _, v := range c.Volumes {
		if v.Encrypted && (!seenKeys[v.id] || !seenRecords[v.id]) {
			return corrupt("missing encrypted volume key ownership", 0)
		}
	}
	return nil
}
