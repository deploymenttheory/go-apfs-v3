package apfs

import (
	"context"
	"fmt"
	"io/fs"
	"slices"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// StorageReport describes reconciled allocation for the admitted plaintext
// profile. Checkpoint protection is conservative; descriptor completeness does
// not establish the health of an older filesystem. File-content/application
// verification is separate.
type StorageReport struct {
	ContainerUUID string `json:"containerUUID"`
	Transaction   XID    `json:"transaction"`
	BlockSize     uint32 `json:"blockSize"`
	Blocks        uint64 `json:"blocks"`
	FreeBlocks    uint64 `json:"freeBlocks"`
	// PendingFreeBlocks remain allocated in the main-device free queue.
	PendingFreeBlocks         uint64 `json:"pendingFreeBlocks"`
	ProtectedBlocks           uint64 `json:"protectedBlocks"`
	CheckpointProtectedBlocks uint64 `json:"checkpointProtectedBlocks"`
	RetainedCheckpoints       int    `json:"retainedCheckpoints"`
	Snapshots                 uint64 `json:"snapshots"`
	Volumes                   int    `json:"volumes"`
}

// InspectStorage checks current and retained filesystem roots, object-map
// versions, data/attribute references and both allocation maps without writing.
// Unsupported encryption, geometry or metadata fails explicitly. Snapshot/clone
// writer admission is separate; successful accounting never enables a writer.
func InspectStorage(ctx context.Context, source block.Source) (StorageReport, error) {
	var report StorageReport
	if source == nil {
		return report, fs.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	c, err := Open(source)
	if err != nil {
		return report, err
	}
	checker, err := newStorageChecker(ctx, c)
	if err != nil {
		return report, err
	}
	if err = checker.check(); err != nil {
		return report, err
	}
	return checker.report, nil
}

type storageObject struct {
	volume        string
	oid, xid      uint64
	kind, subtype uint32
}

type storageVolume struct {
	v                 *Volume
	super             []byte
	address           uint64
	omap, fs, extents *cowTree
	mapHeader         []byte
	views             []*storageView
	data              []storageExtent
	snapshots         []snapshotRecord
}

type storageView struct {
	fs      *cowTree
	streams *streamInventory
	refs    []storageExtent
	extents *cowTree
}

type storageChecker struct {
	ctx              context.Context
	c                *Container
	nx               []byte
	reader           *mutation
	volumes          []*storageVolume
	metadata         map[uint64]storageObject
	objects, records int
	protected, pool  []byte
	report           StorageReport
	mapHeader        []byte
	cmap             *cowTree
}

func newStorageChecker(ctx context.Context, c *Container) (*storageChecker, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if c.BlockSize != 4096 || c.Checkpoint == 0 || len(c.Volumes) == 0 {
		return nil, filesystem.ErrUnsupported
	}
	if (c.BlockCount+7)/8 > maxMutationBitmapBytes {
		return nil, filesystem.ErrLimit
	}
	nx, err := c.object(c.Checkpoint, 1)
	if err != nil {
		return nil, err
	}
	// Fusion, key lockers, EFI state, pinned mappings and pending container
	// operations need their own ownership interpretation.
	for _, off := range []int{48, 56, 1240, 1248, 1256, 1272, 1296, 1304, 1352, 1360, 1368, 1376, 1392, 1400} {
		if le.Uint64(nx[off:]) != 0 {
			return nil, fmt.Errorf("container storage feature at %d: %w", off, filesystem.ErrUnsupported)
		}
	}
	r := &mutation{ctx: ctx, c: c, disk: readOnlyMutation{c.source}, nx: nx, ephemeral: map[uint64]ephemeral{}}
	if err = r.loadEphemeralObjects(true); err != nil {
		return nil, err
	}
	s := &storageChecker{ctx: ctx, c: c, nx: nx, reader: r, metadata: map[uint64]storageObject{}}
	s.report = StorageReport{ContainerUUID: c.UUID, Transaction: c.XID, BlockSize: c.BlockSize, Blocks: c.BlockCount, Volumes: len(c.Volumes)}
	return s, nil
}

func (s *storageChecker) physical(address uint64, volume string, kind uint32) ([]byte, uint64, error) {
	if err := s.ctx.Err(); err != nil {
		return nil, 0, err
	}
	if s.objects >= 16000 {
		return nil, 0, filesystem.ErrLimit
	}
	s.objects++
	b, err := s.reader.readObject(address, kind, 0x40000000)
	if err != nil {
		return nil, 0, err
	}
	if err = s.remember(address, volume, b); err != nil {
		return nil, 0, err
	}
	return b, address, nil
}

func (s *storageChecker) remember(address uint64, volume string, b []byte) error {
	object := storageObject{volume, le.Uint64(b[8:]), le.Uint64(b[16:]), le.Uint32(b[24:]), le.Uint32(b[28:])}
	if previous, exists := s.metadata[address]; exists && previous != object {
		return corrupt("cross-linked storage metadata", int64(address)*4096)
	}
	s.metadata[address] = object
	return nil
}

func (s *storageChecker) tree(root uint64, subtype uint32, volume string, less func([]byte, []byte) bool) (*cowTree, error) {
	t, err := loadCOWTree(s.ctx, root, subtype, 0x40000000, func(id uint64) ([]byte, uint64, error) {
		return s.physical(id, volume, 0)
	}, less, func() (uint64, error) { return 0, fs.ErrPermission })
	if err != nil {
		return nil, fmt.Errorf("storage tree %d root %d: %w", subtype, root, err)
	}
	if err = s.consumeRecords(t.keyCount); err != nil {
		return nil, err
	}
	return t, nil
}

func (s *storageChecker) consumeRecords(n uint64) error {
	if n > uint64(maxStorageRecords-s.records) {
		return filesystem.ErrLimit
	}
	s.records += int(n)
	return nil
}

func (s *storageChecker) objectMap(address uint64, volume string) ([]byte, *cowTree, error) {
	b, _, err := s.physical(address, volume, 11)
	if err != nil {
		return nil, nil, err
	}
	if le.Uint32(b[32:])&^uint32(1) != 0 || le.Uint32(b[40:]) != 0x40000002 || le.Uint64(b[72:]) != 0 || le.Uint64(b[80:]) != 0 {
		return nil, nil, fmt.Errorf("object-map storage profile: %w", filesystem.ErrUnsupported)
	}
	t, err := s.tree(le.Uint64(b[48:]), 11, volume, orderedPair)
	if err != nil {
		return nil, nil, err
	}
	if t.keySize != 16 || t.valueSize != 16 {
		return nil, nil, corrupt("object-map record sizes", 0)
	}
	for _, r := range t.all() {
		id, xid := le.Uint64(r.key), le.Uint64(r.key[8:])
		flags, size, address := le.Uint32(r.value), le.Uint32(r.value[4:]), le.Uint64(r.value[8:])
		if id == 0 || xid == 0 || xid > uint64(s.c.XID) {
			return nil, nil, corrupt("object-map storage identity", 0)
		}
		if flags&^uint32(1) != 0 {
			return nil, nil, filesystem.ErrUnsupported
		}
		if flags&1 != 0 {
			continue // A deleted placeholder does not own a stored object.
		}
		if size != 4096 || address == 0 || address >= s.c.BlockCount {
			return nil, nil, corrupt("object-map stored range", 0)
		}
		if s.objects >= 16000 {
			return nil, nil, filesystem.ErrLimit
		}
		s.objects++
		object := make([]byte, 4096)
		if err = block.ReadFull(s.c.source, object, int64(address)*4096); err != nil {
			return nil, nil, err
		}
		if !validChecksum(object) || le.Uint64(object[8:]) != id || le.Uint64(object[16:]) > xid || le.Uint32(object[24:])&0xc0000000 != 0 {
			return nil, nil, corrupt("mapped storage object", int64(address)*4096)
		}
		if err = s.remember(address, volume, object); err != nil {
			return nil, nil, err
		}
	}
	if root := le.Uint64(b[56:]); root != 0 {
		if le.Uint32(b[44:]) != 0x40000002 {
			return nil, nil, filesystem.ErrUnsupported
		}
		snaps, err := s.tree(root, 19, volume, func(a, b []byte) bool { return le.Uint64(a) < le.Uint64(b) })
		if err != nil {
			return nil, nil, err
		}
		if snaps.keySize != 8 || snaps.valueSize != 16 || snaps.keyCount != uint64(le.Uint32(b[36:])) {
			return nil, nil, corrupt("object-map snapshot inventory", 0)
		}
		for _, record := range snaps.all() {
			if le.Uint64(record.key) == 0 || le.Uint64(record.key) > uint64(s.c.XID) || le.Uint32(record.value)&^uint32(3) != 0 {
				return nil, nil, corrupt("object-map snapshot record", 0)
			}
			// oms_pad and oms_oid are reserved, not physical references.
		}
	} else if le.Uint32(b[36:]) != 0 {
		return nil, nil, corrupt("missing object-map snapshot tree", 0)
	}
	return b, t, nil
}

func storageMapping(t *cowTree, oid OID, xid XID) (objectMapping, error) {
	r, ok := t.floor(append(buildUint64(uint64(oid)), buildUint64(uint64(xid))...))
	if !ok || OID(le.Uint64(r.key)) != oid || le.Uint32(r.value) != 0 || le.Uint32(r.value[4:]) != 4096 {
		return objectMapping{}, corrupt("unmapped storage version", 0)
	}
	return objectMapping{address: PhysicalAddress(le.Uint64(r.value[8:]))}, nil
}

func (s *storageChecker) filesystem(v *Volume, omap *cowTree) (*cowTree, error) {
	less := (&volumeLayout{options: VolumeSpec{CaseSensitive: v.CaseSensitive}}).recordLess
	t, err := loadCOWTree(s.ctx, uint64(v.root), 14, 0, func(id uint64) ([]byte, uint64, error) {
		if s.objects >= 16000 {
			return nil, 0, filesystem.ErrLimit
		}
		s.objects++
		mapping, err := storageMapping(omap, OID(id), v.xid)
		if err != nil {
			return nil, 0, err
		}
		b := make([]byte, 4096)
		if err := block.ReadFull(s.c.source, b, int64(mapping.address)*4096); err != nil {
			return nil, 0, err
		}
		if XID(le.Uint64(b[16:])) > v.xid {
			return nil, 0, corrupt("filesystem storage transaction", 0)
		}
		return b, uint64(mapping.address), s.remember(uint64(mapping.address), v.UUID, b)
	}, less, func() (uint64, error) { return 0, fs.ErrPermission })
	if err != nil {
		return nil, err
	}
	return t, s.consumeRecords(t.keyCount)
}

func (s *storageChecker) check() error {
	mapHeader, cmap, err := s.objectMap(le.Uint64(s.nx[160:]), "")
	if err != nil {
		return fmt.Errorf("container map: %w", err)
	}
	s.mapHeader, s.cmap = mapHeader, cmap
	for i := range s.c.Volumes {
		v := &s.c.Volumes[i]
		if v.Encrypted || v.EncryptionRollingStateOID != 0 || v.Sealed || v.Role != 0 || v.ReadOnlyCompatibleFeatures != 0 || v.IncompatibleFeatures&^uint64(0xf) != 0 || v.CompatibleFeatures&^uint64(2) != 0 || v.rootType != 2 {
			return fmt.Errorf("volume %s storage profile: %w", v.UUID, filesystem.ErrUnsupported)
		}
		mapping, err := storageMapping(cmap, v.OID, s.c.XID)
		if err != nil {
			return err
		}
		super, err := s.c.object(mapping.address, 13)
		if err != nil {
			return err
		}
		if le.Uint64(super[160:]) != 0 || le.Uint64(super[168:]) != 0 || le.Uint32(super[120:]) != 0x40000002 {
			return filesystem.ErrUnsupported
		}
		mapHeader, omap, err := s.objectMap(uint64(v.omap), v.UUID)
		if err != nil {
			return fmt.Errorf("volume map: %w", err)
		}
		volume := &storageVolume{v: v, super: super, address: uint64(mapping.address), omap: omap, mapHeader: mapHeader}
		s.volumes = append(s.volumes, volume)
		if err = s.checkVolume(volume); err != nil {
			return fmt.Errorf("volume %s: %w", v.UUID, err)
		}
		s.reader.volumes = append(s.reader.volumes, &mutation{v: v, super: super})
	}
	if err = s.reader.loadSpace(); err != nil {
		return fmt.Errorf("storage allocation maps: %w", err)
	}
	if err = s.checkpointLifetimes(); err != nil {
		return err
	}
	return s.checkAllocation()
}

func (s *storageChecker) checkVolume(volume *storageVolume) error {
	v := volume.v
	if v.snapMeta != 0 {
		if v.snapMetaType != 0x40000002 {
			return filesystem.ErrUnsupported
		}
		if _, err := s.tree(uint64(v.snapMeta), 16, v.UUID, (&volumeLayout{options: VolumeSpec{CaseSensitive: v.CaseSensitive}}).recordLess); err != nil {
			return err
		}
	}
	history, err := v.snapshots(s.ctx)
	if err != nil {
		return err
	}
	volume.snapshots = history
	s.report.Snapshots += uint64(len(history))
	var previous []storageExtent
	for _, snapshot := range history {
		if snapshot.Flags != 0 || snapshot.extentType != 0x40000002 || snapshot.extents == 0 {
			return fmt.Errorf("snapshot storage profile: %w", filesystem.ErrUnsupported)
		}
		view, err := v.snapshotVolume(snapshot)
		if err != nil {
			return err
		}
		super, _, err := s.physical(uint64(snapshot.superblock), v.UUID, 13)
		if err != nil {
			return err
		}
		state, err := s.checkView(view, super, volume.omap, uint64(snapshot.extents), previous)
		if err != nil {
			return err
		}
		previous = state.refs
		volume.views = append(volume.views, state)
	}
	state, err := s.checkView(v, volume.super, volume.omap, le.Uint64(volume.super[144:]), previous)
	if err != nil {
		return fmt.Errorf("live transaction %d: %w", v.xid, err)
	}
	volume.fs, volume.extents = state.fs, state.extents
	volume.views = append(volume.views, state)
	var ranges []storageExtent
	for _, view := range volume.views {
		for _, r := range view.refs {
			if r.refs != 0 {
				ranges = append(ranges, r)
			}
		}
	}
	volume.data, err = countStreamExtents(s.ctx, ranges)
	if err != nil {
		return err
	}
	var allocated uint64
	for _, object := range s.metadata {
		// Volume superblocks are container-owned, including retained snapshot
		// superblocks. apfs_fs_alloc_count excludes them on all native controls.
		if object.volume == v.UUID && object.kind&0xffff != 13 {
			allocated++
		}
	}
	for _, r := range volume.data {
		allocated += r.end - r.start
	}
	if allocated != le.Uint64(volume.super[88:]) {
		return fmt.Errorf("volume allocation: referenced=%d recorded=%d: %w", allocated, le.Uint64(volume.super[88:]), filesystem.ErrCorrupt)
	}
	return nil
}

func (s *storageChecker) checkView(v *Volume, super []byte, omap *cowTree, extentRoot uint64, previous []storageExtent) (*storageView, error) {
	t, err := s.filesystem(v, omap)
	if err != nil {
		return nil, err
	}
	streams, err := scanStorageStreams(s.ctx, t.all(), s.c.BlockCount, super)
	if err != nil {
		return nil, err
	}
	extents, err := s.tree(extentRoot, 15, v.UUID, (&volumeLayout{}).recordLess)
	if err != nil {
		return nil, err
	}
	changes, err := readExtentChanges(extents.all(), s.c.BlockCount)
	if err != nil {
		return nil, err
	}
	refs, err := applyExtentChanges(s.ctx, previous, changes)
	if err != nil {
		return nil, err
	}
	actual, err := countStreamExtents(s.ctx, streams.extents)
	if err != nil {
		return nil, err
	}
	if !equalExtentCounts(refs, actual) {
		return nil, corrupt("file/physical extent reference counts", 0)
	}
	return &storageView{fs: t, streams: streams, refs: refs, extents: extents}, nil
}

func (s *storageChecker) checkAllocation() error {
	space := s.reader.space
	s.protected = make([]byte, (s.c.BlockCount+7)/8)
	s.pool = make([]byte, (space.poolCount+7)/8)
	main := make([]byte, len(s.protected))
	pool := make([]byte, len(s.pool))
	claim := func(start, count uint64, protect bool) error {
		if count == 0 || start >= s.c.BlockCount || count > s.c.BlockCount-start {
			return corrupt("owned storage range", 0)
		}
		for at := start; at < start+count; {
			if err := s.ctx.Err(); err != nil {
				return err
			}
			chunk := space.chunks[at/32768]
			take := min(start+count-at, chunk.start+uint64(chunk.count)-at)
			if offset, ok := claimBits(chunk.bitmap, main, at-chunk.start, at, take); !ok {
				return corrupt("unallocated or cross-linked storage", int64(at+offset)*4096)
			}
			if protect {
				if _, ok := claimBits(chunk.bitmap, s.protected, at-chunk.start, at, take); !ok {
					return corrupt("protected storage conflict", 0)
				}
				s.report.ProtectedBlocks += take
			}
			at += take
		}
		return nil
	}
	claimPool := func(start, count uint64, protect bool) error {
		if count == 0 || start < space.pool || start >= space.pool+space.poolCount || count > space.pool+space.poolCount-start {
			return corrupt("internal-pool storage range", 0)
		}
		if _, ok := claimBits(space.poolBits, pool, start-space.pool, start-space.pool, count); !ok {
			return corrupt("internal-pool storage conflict", 0)
		}
		if protect {
			if _, ok := claimBits(space.poolBits, s.pool, start-space.pool, start-space.pool, count); !ok {
				return corrupt("internal-pool protection conflict", 0)
			}
		}
		return nil
	}
	for _, r := range [][2]uint64{{0, 1}, {le.Uint64(s.nx[112:]), uint64(le.Uint32(s.nx[104:]))}, {le.Uint64(s.nx[120:]), uint64(le.Uint32(s.nx[108:]))}, {space.bitmapBase, 16}, {space.pool, space.poolCount}} {
		if err := claim(r[0], r[1], true); err != nil {
			return err
		}
	}
	addresses := make([]uint64, 0, len(s.metadata))
	for address := range s.metadata {
		addresses = append(addresses, address)
	}
	slices.Sort(addresses)
	for _, address := range addresses {
		if err := claim(address, 1, true); err != nil {
			return err
		}
	}
	for _, volume := range s.volumes {
		for _, r := range volume.data {
			if err := claim(r.start, r.end-r.start, true); err != nil {
				return err
			}
		}
	}
	for _, cib := range space.cibs {
		if err := claimPool(cib.address, 1, true); err != nil {
			return err
		}
		for _, chunk := range cib.chunks {
			if chunk.bitmapAddress != 0 {
				if err := claimPool(chunk.bitmapAddress, 1, true); err != nil {
					return err
				}
			}
		}
	}
	for i, queue := range space.queues {
		for _, r := range queue.all() {
			var err error
			if i == 0 {
				err = claimPool(le.Uint64(r.key[8:]), le.Uint64(r.value), false)
			} else {
				err = claim(le.Uint64(r.key[8:]), le.Uint64(r.value), false)
			}
			if err != nil {
				return err
			}
			if i == 1 {
				s.report.PendingFreeBlocks += le.Uint64(r.value)
				if le.Uint64(r.key) >= uint64(space.checkpointFloor) {
					s.report.CheckpointProtectedBlocks += le.Uint64(r.value)
				}
			}
		}
	}
	for _, chunk := range space.chunks {
		if !equalBitmap(chunk.bitmap, main[chunk.start/8:], uint64(chunk.count)) {
			return fmt.Errorf("storage chunk %d has unaccounted allocation: %w", chunk.start, filesystem.ErrUnsupported)
		}
	}
	if !equalBitmap(space.poolBits, pool, space.poolCount) {
		return corrupt("unaccounted internal-pool storage", 0)
	}
	s.report.FreeBlocks = space.free
	s.report.ProtectedBlocks += s.report.CheckpointProtectedBlocks
	return s.ctx.Err()
}
