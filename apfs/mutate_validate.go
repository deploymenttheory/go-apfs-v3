package apfs

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Allocation and reference reconciliation belongs to the shared storage checker.
// Mutation admission separately restricts the writer to its qualified ordinary
// profile. Accounting shared/history owners must never implicitly enable edits.
func (m *mutation) validateOwnership(storage *storageChecker) error {
	container := make(map[uint64]uint64, len(m.volumes))
	for _, volume := range m.volumes {
		container[uint64(volume.v.OID)] = volume.volumeAddress
	}
	if err := currentMapInventory(m.cmap, container); err != nil {
		return err
	}
	for index, volume := range storage.volumes {
		if len(volume.snapshots) == 0 {
			if le.Uint32(volume.mapHeader[36:]) != 0 || le.Uint64(volume.mapHeader[64:]) != 0 {
				return fmt.Errorf("retained volume versions: %w", filesystem.ErrUnsupported)
			}
			current := make(map[uint64]uint64, len(volume.fs.nodes))
			for _, n := range volume.fs.nodes {
				current[n.oid] = n.address
			}
			if err := currentMapInventory(volume.omap, current); err != nil {
				return err
			}
		} else if err := m.volumes[index].admitHistory(volume, storage); err != nil {
			return err
		}
		streams := volume.views[len(volume.views)-1].streams
		for _, inode := range streams.inodes {
			if _, err := statisticsForInode(inode.value); err != nil {
				return err
			}
		}
		for _, r := range m.volumes[index].extents.all() {
			if len(volume.snapshots) != 0 && m.volumes[index] != m {
				break
			}
			if le.Uint64(r.value)>>60 != 1 || int32(le.Uint32(r.value[16:])) <= 0 {
				return fmt.Errorf("APFS physical extent history: %w", filesystem.ErrUnsupported)
			}
		}
		// The shared checker reconciles counts against all live streams. An
		// original owning_obj_id can outlive its inode even at count one; clone
		// flags are historical hints, not authority to free or overwrite data.
	}
	if le.Uint32(storage.mapHeader[36:]) != 0 || le.Uint64(storage.mapHeader[64:]) != 0 {
		return fmt.Errorf("retained container map versions: %w", filesystem.ErrUnsupported)
	}
	// Preserve only validated idle linked pages, in link order. Their free
	// entries may contain stale work bytes; those bytes do not authorize work.
	reaper := m.ephemeral[le.Uint64(m.nx[168:])].data
	if _, err := m.emptyReaperLists(reaper, true); err != nil {
		return err
	}
	for oid := le.Uint64(reaper[48:]); oid != 0; {
		page := m.ephemeral[oid]
		m.reaperLists = append(m.reaperLists, page)
		oid = le.Uint64(page.data[32:])
	}
	m.space.protected, m.space.protectedPool = storage.protected, storage.pool
	return nil
}

func currentMapInventory(tree *cowTree, current map[uint64]uint64) error {
	records := tree.all()
	if len(records) != len(current) {
		return fmt.Errorf("retained object-map inventory: %w", filesystem.ErrUnsupported)
	}
	for _, r := range records {
		if le.Uint32(r.value) != 0 || le.Uint32(r.value[4:]) != 4096 || current[le.Uint64(r.key)] != le.Uint64(r.value[8:]) {
			return corrupt("current object-map ownership", 0)
		}
		delete(current, le.Uint64(r.key))
	}
	if len(current) != 0 {
		return corrupt("missing object-map ownership", 0)
	}
	return nil
}
