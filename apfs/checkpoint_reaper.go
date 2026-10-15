package apfs

import (
	"fmt"
	"math"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// An idle native reaper can retain empty list pages. Only the linked occupied
// entries are work; stale bytes in its free entries/state buffer are not roots.
// Active reaping and nonempty lists remain outside the admitted storage profile.
func (m *mutation) emptyReaperLists(reaper []byte, allow bool) (map[uint64]bool, error) {
	head, tail, count := le.Uint64(reaper[48:]), le.Uint64(reaper[56:]), le.Uint32(reaper[68:])
	pages := map[uint64]bool{}
	if head == 0 {
		if tail != 0 || count != 0 {
			return nil, corrupt("empty reaper list inventory", 0)
		}
		return pages, nil
	}
	if !allow {
		return nil, fmt.Errorf("APFS reaper list mutation profile: %w", filesystem.ErrUnsupported)
	}
	var last uint64
	for oid := head; oid != 0; {
		if err := m.ctx.Err(); err != nil {
			return nil, err
		}
		if pages[oid] || len(pages) >= checkpointObjectLimit {
			return nil, corrupt("reaper list cycle or limit", 0)
		}
		page, ok := m.ephemeral[oid]
		if !ok || page.kind != 0x80000012 || page.subtype != 0 || len(page.data) < 64 {
			return nil, corrupt("reaper list checkpoint mapping", 0)
		}
		b := page.data
		maximum := le.Uint32(b[44:])
		free := le.Uint32(b[60:])
		if le.Uint32(b[40:]) != 0 || maximum == 0 || uint64(maximum) > uint64(len(b)-64)/40 {
			return nil, fmt.Errorf("reaper list layout: %w", filesystem.ErrUnsupported)
		}
		if le.Uint32(b[48:]) != 0 {
			return nil, fmt.Errorf("APFS queued reaper work: %w", filesystem.ErrUnsupported)
		}
		if le.Uint32(b[52:]) != math.MaxUint32 || le.Uint32(b[56:]) != math.MaxUint32 || free != math.MaxUint32 && free >= maximum {
			return nil, corrupt("idle reaper list indices", 0)
		}
		pages[oid], last = true, oid
		oid = le.Uint64(b[32:])
	}
	if last != tail || uint64(len(pages)) != uint64(count) {
		return nil, corrupt("reaper list count or tail", 0)
	}
	return pages, nil
}
