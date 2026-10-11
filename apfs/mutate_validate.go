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
		for i := uint64(0); i < count; i++ {
			a := start + i
			if !m.space.used(a) || littleBit(main, a) {
				return corrupt("unallocated or cross-linked APFS block", int64(a)*4096)
			}
			setLittleBit(main, a, true)
		}
		return nil
	}
	claimPool := func(start, count uint64) error {
		if start < m.space.pool || start >= m.space.pool+m.space.poolCount || count > m.space.pool+m.space.poolCount-start {
			return corrupt("pool ownership range", 0)
		}
		for i := uint64(0); i < count; i++ {
			p := start + i - m.space.pool
			if !littleBit(m.space.poolBits, p) || littleBit(pool, p) {
				return corrupt("pool ownership conflict", 0)
			}
			setLittleBit(pool, p, true)
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
	for _, a := range []uint64{le.Uint64(m.nx[160:]), m.volumeAddress, uint64(m.v.omap)} {
		if e := claim(a, 1); e != nil {
			return e
		}
	}
	var volumeBlocks uint64 = 1
	for _, t := range []*cowTree{m.fs, m.extents, m.vmap, m.cmap} {
		for _, n := range t.nodes {
			if e := claim(n.address, 1); e != nil {
				return e
			}
			if t != m.cmap {
				volumeBlocks++
			}
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
				owners[stream] = p.id
			}
		case 4:
			if len(r.key) < 11 || len(r.value) < 4 || int(le.Uint16(r.value[2:])) != len(r.value)-4 {
				return corrupt("mutation attribute bounds", 0)
			}
			flags := le.Uint16(r.value)
			if flags&^uint16(7) != 0 || flags&3 != 1 && flags&3 != 2 {
				return filesystem.ErrUnsupported
			}
			if flags&1 != 0 {
				if len(r.value) != 52 {
					return corrupt("attribute stream bounds", 0)
				}
				id := le.Uint64(r.value[4:])
				if id == 0 || streams[id] {
					return filesystem.ErrUnsupported
				}
				streams[id] = true
				owners[id] = p.id
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
		case 5, 7, 8, 10, 11, 12: // Preserved sibling, protection and directory-stat records.
		default:
			return fmt.Errorf("APFS mutation record type %d: %w", p.kind, filesystem.ErrUnsupported)
		}
	}
	extents := map[uint64]buildRecord{}
	for _, r := range m.extents.all() {
		p := prefix(r.key)
		if p.kind != 2 || len(r.key) != 8 || len(r.value) != 20 || le.Uint64(r.value)>>60 != 1 || le.Uint32(r.value[16:]) != 1 {
			return fmt.Errorf("APFS extent ownership profile: %w", filesystem.ErrUnsupported)
		}
		extents[p.id] = r
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
		ref, ok := extents[address]
		if !ok || le.Uint64(ref.value)&objectMask != blocks || le.Uint64(ref.value[8:]) != owners[p.id] {
			return fmt.Errorf("file/physical extent at %d: stream=%d blocks=%d physical=%x: %w", address, p.id, blocks, ref.value, filesystem.ErrCorrupt)
		}
		delete(extents, address)
		if e := claim(address, blocks); e != nil {
			return e
		}
		allocated[p.id] += blocks
		volumeBlocks += blocks
	}
	if len(extents) != 0 {
		return corrupt("unowned physical extent", 0)
	}
	for id, blocks := range streamBlocks {
		if blocks != allocated[id] {
			return corrupt("stream allocated-block accounting", 0)
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
	for a := uint64(0); a < m.c.BlockCount; a++ {
		if m.space.used(a) != littleBit(main, a) {
			return fmt.Errorf("APFS block %d has unaccounted ownership: %w", a, filesystem.ErrUnsupported)
		}
	}
	for a := uint64(0); a < m.space.poolCount; a++ {
		if littleBit(m.space.poolBits, a) != littleBit(pool, a) {
			return corrupt("unaccounted pool ownership", 0)
		}
	}
	return m.ctx.Err()
}
