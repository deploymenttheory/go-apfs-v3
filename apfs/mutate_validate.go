package apfs

import (
	"fmt"
	"slices"

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
	for _, volume := range storage.volumes {
		if len(volume.views) != 1 || le.Uint32(volume.mapHeader[36:]) != 0 || le.Uint64(volume.mapHeader[64:]) != 0 {
			return fmt.Errorf("retained volume versions: %w", filesystem.ErrUnsupported)
		}
		current := make(map[uint64]uint64, len(volume.fs.nodes))
		for _, n := range volume.fs.nodes {
			current[n.oid] = n.address
		}
		if err := currentMapInventory(volume.omap, current); err != nil {
			return err
		}
		streams := volume.views[0].streams
		if streams.cloned {
			return fmt.Errorf("APFS clone history: %w", filesystem.ErrUnsupported)
		}
		for _, stream := range streams.streams {
			if stream.owners != 1 {
				return fmt.Errorf("APFS shared stream: %w", filesystem.ErrUnsupported)
			}
		}
		for _, inode := range streams.inodes {
			if _, err := statisticsForInode(inode.value); err != nil {
				return err
			}
		}
		var owners []ownedRange
		for _, r := range volume.extents.all() {
			if le.Uint64(r.value)>>60 != 1 || le.Uint32(r.value[16:]) != 1 {
				return fmt.Errorf("APFS shared physical extent: %w", filesystem.ErrUnsupported)
			}
			start := prefix(r.key).id
			owners = append(owners, ownedRange{start, start + (le.Uint64(r.value) & objectMask), le.Uint64(r.value[8:])})
		}
		if err := validateExtentOwners(owners, slices.Clone(streams.owners)); err != nil {
			return err
		}
	}
	if le.Uint32(storage.mapHeader[36:]) != 0 || le.Uint64(storage.mapHeader[64:]) != 0 {
		return fmt.Errorf("retained container map versions: %w", filesystem.ErrUnsupported)
	}
	// Empty reaper-list pages are understood by inspection. Carrying them into
	// a new checkpoint remains outside the current writer's admission profile.
	if _, err := m.emptyReaperLists(m.ephemeral[le.Uint64(m.nx[168:])].data, false); err != nil {
		return err
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
