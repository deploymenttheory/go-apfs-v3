package apfs

import (
	"fmt"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// validateOwnership accounts the admitted container's current objects, streams,
// deferred frees and reserved regions against both allocation maps. Historical
// object-map versions are not live ownership; their blocks belong to free queues.
func (m *mutation) validateOwnership() error {
	main := make([]byte, (m.c.BlockCount+7)/8)
	pool := make([]byte, (m.space.poolCount+7)/8)
	claim := func(start, count uint64) error {
		if start >= m.c.BlockCount || count > m.c.BlockCount-start {
			return corrupt("owned extent range", 0)
		}
		for at := start; at < start+count; {
			if err := m.ctx.Err(); err != nil {
				return err
			}
			chunk := m.space.chunks[at/32768]
			take := min(start+count-at, chunk.start+uint64(chunk.count)-at)
			if offset, ok := claimBits(chunk.bitmap, main, at-chunk.start, at, take); !ok {
				return corrupt("unallocated or cross-linked APFS block", int64(at+offset)*4096)
			}
			at += take
		}
		return nil
	}
	claimPool := func(start, count uint64) error {
		if start < m.space.pool || start >= m.space.pool+m.space.poolCount || count > m.space.pool+m.space.poolCount-start {
			return corrupt("pool ownership range", 0)
		}
		if _, ok := claimBits(m.space.poolBits, pool, start-m.space.pool, start-m.space.pool, count); !ok {
			return corrupt("pool ownership conflict", 0)
		}
		return nil
	}
	for _, range_ := range [][2]uint64{{0, 1}, {le.Uint64(m.nx[112:]), uint64(le.Uint32(m.nx[104:]))}, {le.Uint64(m.nx[120:]), uint64(le.Uint32(m.nx[108:]))}, {m.space.bitmapBase, 16}, {m.space.pool, m.space.poolCount}} {
		if e := claim(range_[0], range_[1]); e != nil {
			return e
		}
	}
	for _, cib := range m.space.cibs {
		if e := claimPool(cib.address, 1); e != nil {
			return e
		}
		for _, ch := range cib.chunks {
			if ch.bitmapAddress != 0 {
				if e := claimPool(ch.bitmapAddress, 1); e != nil {
					return e
				}
			}
		}
	}
	for _, r := range m.space.queues[0].all() {
		if e := claimPool(le.Uint64(r.key[8:]), le.Uint64(r.value)); e != nil {
			return e
		}
	}
	for _, r := range m.space.queues[1].all() {
		if e := claim(le.Uint64(r.key[8:]), le.Uint64(r.value)); e != nil {
			return e
		}
	}
	if err := claim(le.Uint64(m.nx[160:]), 1); err != nil {
		return err
	}
	for _, node := range m.cmap.nodes {
		if err := claim(node.address, 1); err != nil {
			return err
		}
	}
	volumes := m.volumes
	if len(volumes) == 0 {
		volumes = []*mutation{m}
	}
	current := make(map[uint64]uint64, len(volumes))
	for _, volume := range volumes {
		current[uint64(volume.v.OID)] = volume.volumeAddress
	}
	if len(m.cmap.all()) != len(current) {
		return fmt.Errorf("container map inventory: %w", filesystem.ErrUnsupported)
	}
	for _, record := range m.cmap.all() {
		id, xid := le.Uint64(record.key), le.Uint64(record.key[8:])
		if le.Uint32(record.value) != 0 || le.Uint32(record.value[4:]) != 4096 || xid > uint64(m.c.XID) || current[id] != le.Uint64(record.value[8:]) {
			return corrupt("container object map ownership", 0)
		}
		delete(current, id)
	}
	if len(current) != 0 {
		return corrupt("missing container map ownership", 0)
	}
	for _, volume := range volumes {
		if err := volume.validateVolumeOwnership(claim); err != nil {
			return err
		}
	}
	for _, chunk := range m.space.chunks {
		if err := m.ctx.Err(); err != nil {
			return err
		}
		if !equalBitmap(chunk.bitmap, main[chunk.start/8:], uint64(chunk.count)) {
			return fmt.Errorf("APFS chunk at %d has unaccounted ownership: %w", chunk.start, filesystem.ErrUnsupported)
		}
	}
	if !equalBitmap(m.space.poolBits, pool, m.space.poolCount) {
		return corrupt("unaccounted pool ownership", 0)
	}
	return m.ctx.Err()
}

func (m *mutation) validateVolumeOwnership(claim func(uint64, uint64) error) error {
	for _, address := range []uint64{m.volumeAddress, uint64(m.v.omap)} {
		if err := claim(address, 1); err != nil {
			return err
		}
	}
	// Snapshot-free maps describe each current virtual object exactly once.
	current := map[uint64]uint64{}
	for _, n := range m.fs.nodes {
		current[n.oid] = n.address
	}
	if len(m.vmap.all()) != len(current) {
		return fmt.Errorf("volume map inventory: %w", filesystem.ErrUnsupported)
	}
	for _, r := range m.vmap.all() {
		id, xid := le.Uint64(r.key), le.Uint64(r.key[8:])
		if le.Uint32(r.value) != 0 || le.Uint32(r.value[4:]) != 4096 || xid > uint64(m.c.XID) || current[id] != le.Uint64(r.value[8:]) {
			return corrupt("current object map ownership", 0)
		}
		delete(current, id)
	}
	if len(current) != 0 {
		return corrupt("missing object map ownership", 0)
	}

	var volumeBlocks uint64 = 1
	for _, t := range []*cowTree{m.fs, m.extents, m.vmap} {
		for _, n := range t.nodes {
			if e := claim(n.address, 1); e != nil {
				return e
			}
			volumeBlocks++
		}
	}
	if root := le.Uint64(m.super[152:]); root != 0 {
		t, e := loadCOWTree(m.ctx, root, 16, 0x40000000, func(id uint64) ([]byte, uint64, error) { b, e := m.readObject(id, 0, 0x40000000); return b, id, e }, (&volumeLayout{options: VolumeSpec{CaseSensitive: m.v.CaseSensitive}}).recordLess, m.nextOID)
		if e != nil {
			return e
		}
		if t.keyCount != 0 {
			return filesystem.ErrUnsupported
		}
		for _, n := range t.nodes {
			if e := claim(n.address, 1); e != nil {
				return e
			}
			volumeBlocks++
		}
	}
	// Every physical extent must have one current stream owner. Clones are a
	// distinct profile; hard links share an inode/stream and retain refcnt == 1.
	streams := map[uint64]bool{}
	owners := map[uint64]uint64{}
	streamBlocks := map[uint64]uint64{}
	references := map[uint64]uint32{}
	inodes := map[uint64]buildRecord{}
	links := map[uint64]uint32{}
	var files, dirs, symlinks, others uint64
	for _, r := range m.fs.all() {
		p := prefix(r.key)
		switch p.kind {
		case 3:
			if len(r.key) != 8 || len(r.value) < 92 {
				return corrupt("mutation inode bounds", 0)
			}
			if _, ok := inodes[p.id]; ok {
				return corrupt("duplicate mutation inode", 0)
			}
			inodes[p.id] = r
			flags := le.Uint64(r.value[48:])
			if _, err := statisticsForInode(r.value); err != nil {
				return err
			}
			if flags&(0x10|0x400) != 0 {
				return fmt.Errorf("APFS clone history: %w", filesystem.ErrUnsupported)
			}
			kind := le.Uint16(r.value[80:]) & 0170000
			switch kind {
			case 0100000:
				files++
			case 0040000:
				if p.id != 2 && p.id != 3 {
					dirs++
				}
			case 0120000:
				symlinks++
			default:
				others++
			}
			stream := le.Uint64(r.value[8:])
			has := false
			if e := extendedFields(r.value[92:], func(kind byte, data []byte) error {
				if kind == 8 {
					if len(data) != 40 {
						return corrupt("mutation data stream field", 0)
					}
					has = true
					streamBlocks[stream] = le.Uint64(data[8:]) / 4096
					if le.Uint64(data[8:])%4096 != 0 {
						return corrupt("stream allocation size", 0)
					}
				}
				return nil
			}); e != nil {
				return e
			}
			if has {
				if stream == 0 || streams[stream] {
					return filesystem.ErrUnsupported
				}
				streams[stream] = true
				owners[stream] = stream // inode private_id; attribute owners use their record ID below
			}
		case 4:
			if len(r.key) < 11 || len(r.value) < 4 || int(le.Uint16(r.value[2:])) != len(r.value)-4 {
				return corrupt("mutation attribute bounds", 0)
			}
			// Independently captured ordinary attribute streams carry 0x10 on
			// macOS 15/26/27. Its meaning is unpublished; the documented stream
			// layout, complete extent ownership and contents are still validated.
			flags := le.Uint16(r.value)
			if flags&^uint16(0x1f) != 0 || flags&3 != 1 && flags&3 != 2 || flags&0x10 != 0 && flags&3 != 1 {
				return fmt.Errorf("APFS attribute %q flags %#x: %w", string(r.key[10:len(r.key)-1]), flags, filesystem.ErrUnsupported)
			}
			if string(r.key[10:len(r.key)-1]) == filesystem.ResourceFork && flags&3 != 1 {
				return corrupt("resource fork is not stream based", 0)
			}
			if flags&1 != 0 {
				if len(r.value) != 52 {
					return corrupt("attribute stream bounds", 0)
				}
				id := le.Uint64(r.value[4:])
				if id == 0 || streams[id] {
					return fmt.Errorf("APFS attribute %q shared stream %d: %w", string(r.key[10:len(r.key)-1]), id, filesystem.ErrUnsupported)
				}
				streams[id] = true
				owners[id] = attributeExtentOwner(p.id, id, flags)
				size := le.Uint64(r.value[20:])
				if size%4096 != 0 {
					return corrupt("attribute stream allocation", 0)
				}
				streamBlocks[id] = size / 4096
			}
		case 6:
			if len(r.key) != 8 || len(r.value) != 4 || le.Uint32(r.value) != 1 {
				return fmt.Errorf("APFS shared stream: %w", filesystem.ErrUnsupported)
			}
			references[p.id] = 1
		case 9:
			if len(r.value) < 18 {
				return corrupt("mutation directory record", 0)
			}
			links[le.Uint64(r.value)]++
		case 10:
			if len(r.key) != 8 || len(r.value) != 32 {
				return corrupt("directory statistics record bounds", 0)
			}
		case 5, 7, 8, 11, 12: // Siblings are validated with their directory graph.
		default:
			return fmt.Errorf("APFS mutation record type %d: %w", p.kind, filesystem.ErrUnsupported)
		}
	}
	var physicalOwners, streamOwners []ownedRange
	for _, r := range m.extents.all() {
		p := prefix(r.key)
		if p.kind != 2 || len(r.key) != 8 || len(r.value) != 20 || le.Uint64(r.value)>>60 != 1 || le.Uint32(r.value[16:]) != 1 {
			return fmt.Errorf("APFS extent ownership profile: %w", filesystem.ErrUnsupported)
		}
		length := le.Uint64(r.value) & objectMask
		owner := le.Uint64(r.value[8:])
		if length == 0 || p.id >= m.c.BlockCount || length > m.c.BlockCount-p.id || owner == 0 {
			return corrupt("physical extent range", 0)
		}
		physicalOwners = append(physicalOwners, ownedRange{p.id, p.id + length, owner})
	}
	allocated := map[uint64]uint64{}
	for _, r := range m.fs.all() {
		p := prefix(r.key)
		if p.kind != 8 {
			continue
		}
		if len(r.key) != 16 || len(r.value) != 24 {
			return corrupt("mutation file extent bounds", 0)
		}
		length := le.Uint64(r.value) & ((1 << 56) - 1)
		address := le.Uint64(r.value[8:])
		if !streams[p.id] || length == 0 || length%4096 != 0 || le.Uint64(r.value)>>56 != 0 || le.Uint64(r.value[16:]) != 0 {
			return filesystem.ErrUnsupported
		}
		if address == 0 {
			continue
		}
		blocks := length / 4096
		if address >= m.c.BlockCount || blocks > m.c.BlockCount-address {
			return corrupt("file extent range", 0)
		}
		streamOwners = append(streamOwners, ownedRange{address, address + blocks, owners[p.id]})
		if e := claim(address, blocks); e != nil {
			return e
		}
		allocated[p.id] += blocks
		volumeBlocks += blocks
	}
	if err := validateExtentOwners(physicalOwners, streamOwners); err != nil {
		return err
	}
	for id, blocks := range streamBlocks {
		if blocks != allocated[id] {
			return corrupt("stream allocated-block accounting", 0)
		}
	}
	for id := range references {
		if !streams[id] {
			return corrupt("orphan data-stream reference", 0)
		}
	}
	for id, r := range inodes {
		kind := le.Uint16(r.value[80:]) & 0170000
		if kind != 0040000 && links[id] != le.Uint32(r.value[56:]) {
			return corrupt("inode hard-link count", 0)
		}
	}
	if files != le.Uint64(m.super[184:]) || dirs != le.Uint64(m.super[192:]) || symlinks != le.Uint64(m.super[200:]) || others != le.Uint64(m.super[208:]) || volumeBlocks != le.Uint64(m.super[88:]) {
		return fmt.Errorf("APFS volume counters: computed files=%d directories=%d symlinks=%d other=%d blocks=%d; recorded=%d/%d/%d/%d/%d: %w", files, dirs, symlinks, others, volumeBlocks, le.Uint64(m.super[184:]), le.Uint64(m.super[192:]), le.Uint64(m.super[200:]), le.Uint64(m.super[208:]), le.Uint64(m.super[88:]), filesystem.ErrCorrupt)
	}
	return m.ctx.Err()
}
