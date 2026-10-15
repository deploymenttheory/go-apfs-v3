package apfs

import (
	"bytes"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type mutableChunk struct {
	xid, start    uint64
	count, free   uint32
	bitmapAddress uint64
	bitmap        []byte
	dirty         bool
}
type mutableCIB struct {
	address uint64
	data    []byte
	chunks  []*mutableChunk
}
type mutationSpace struct {
	owner                       *mutation
	data                        []byte
	cibs                        []*mutableCIB
	chunks                      []*mutableChunk
	pool, poolCount, bitmapBase uint64
	poolBits                    []byte
	free                        uint64
	queues                      [2]*cowTree
	protected, protectedPool    []byte
	checkpointFloor             XID
}

func littleBit(b []byte, i uint64) bool { return b[i/8]&(1<<uint(i%8)) != 0 }
func setLittleBit(b []byte, i uint64, value bool) {
	if value {
		b[i/8] |= 1 << uint(i%8)
	} else {
		b[i/8] &^= 1 << uint(i%8)
	}
}
func orderedPair(a, b []byte) bool {
	x, y := le.Uint64(a), le.Uint64(b)
	return x < y || x == y && le.Uint64(a[8:]) < le.Uint64(b[8:])
}
func (m *mutation) loadSpace() error {
	ep, ok := m.ephemeral[le.Uint64(m.nx[152:])]
	if !ok || ep.kind != 0x80000005 || len(ep.data) < 0x160 {
		return corrupt("mutation space manager mapping", 0)
	}
	s := &mutationSpace{owner: m, data: bytes.Clone(ep.data)}
	m.space = s
	b := s.data
	if le.Uint32(b[32:]) != 4096 || le.Uint32(b[36:]) != 32768 || le.Uint32(b[40:]) != 126 || le.Uint32(b[44:]) != 507 || le.Uint64(b[48:]) != m.c.BlockCount || le.Uint32(b[68:]) != 0 || le.Uint64(b[88:]) != 0 || le.Uint32(b[144:])&^uint32(1) != 0 {
		return fmt.Errorf("space manager geometry/reservations: %w", filesystem.ErrUnsupported)
	}
	reserved, allocated, err := m.reservations()
	if err != nil {
		return err
	}
	if reserved != le.Uint64(b[184:]) || allocated != le.Uint64(b[192:]) {
		return corrupt("space manager volume reservations", 0)
	}
	s.pool, s.poolCount, s.bitmapBase = le.Uint64(b[176:]), le.Uint64(b[152:]), le.Uint64(b[168:])
	s.free = le.Uint64(b[72:])
	// The first profile has a single internal-pool bitmap and inline CIB addresses.
	if le.Uint32(b[160:]) != 1 || le.Uint32(b[164:]) != 16 || s.poolCount == 0 || s.poolCount > 32768 || s.pool > m.c.BlockCount || s.poolCount > m.c.BlockCount-s.pool || s.bitmapBase+16 > m.c.BlockCount {
		return filesystem.ErrUnsupported
	}
	for _, off := range []uint32{le.Uint32(b[324:]), le.Uint32(b[328:]), le.Uint32(b[332:]), le.Uint32(b[80:])} {
		if off < 0x150 || uint64(off) >= uint64(len(b)) {
			return corrupt("space manager offsets", 0)
		}
	}
	// 0x144/148/14c contain offsets into the variable tail, not physical addresses.
	indexOff, freeOff := le.Uint32(b[328:]), le.Uint32(b[332:])
	if uint64(indexOff)+2 > uint64(len(b)) || uint64(freeOff)+32 > uint64(len(b)) {
		return corrupt("pool bitmap arrays", 0)
	}
	index := le.Uint16(b[indexOff:])
	if index >= 16 {
		return corrupt("pool bitmap ring index", 0)
	}
	s.poolBits = make([]byte, 4096)
	if e := block.ReadFull(m.disk, s.poolBits, int64(s.bitmapBase+uint64(index))*4096); e != nil {
		return e
	}
	cibCount := le.Uint32(b[64:])
	addressOff := le.Uint32(b[80:])
	if cibCount == 0 || cibCount > 128 || uint64(addressOff)+uint64(cibCount)*8 > uint64(len(b)) {
		return filesystem.ErrUnsupported
	}
	for i := uint32(0); i < cibCount; i++ {
		address := le.Uint64(b[uint64(addressOff)+uint64(i)*8:])
		data, e := m.readObject(address, 7, 0x40000000)
		if e != nil {
			return e
		}
		if le.Uint32(data[32:]) != i {
			return corrupt("CIB index", 0)
		}
		cib := &mutableCIB{address: address, data: bytes.Clone(data)}
		count := le.Uint32(data[36:])
		if count == 0 || count > 126 {
			return corrupt("CIB count", 0)
		}
		for j := uint32(0); j < count; j++ {
			r := data[40+j*32:]
			ch := &mutableChunk{xid: le.Uint64(r), start: le.Uint64(r[8:]), count: le.Uint32(r[16:]), free: le.Uint32(r[20:]), bitmapAddress: le.Uint64(r[24:]), bitmap: make([]byte, 4096)}
			if ch.start != uint64(len(s.chunks))*32768 || ch.start >= m.c.BlockCount || ch.count != uint32(min(uint64(32768), m.c.BlockCount-ch.start)) || ch.free > ch.count || ch.xid > uint64(m.c.XID) {
				return corrupt("chunk geometry", 0)
			}
			if ch.bitmapAddress != 0 {
				if ch.bitmapAddress < s.pool || ch.bitmapAddress >= s.pool+s.poolCount || !littleBit(s.poolBits, ch.bitmapAddress-s.pool) {
					return corrupt("chunk bitmap pool ownership", 0)
				}
				if e := block.ReadFull(m.disk, ch.bitmap, int64(ch.bitmapAddress)*4096); e != nil {
					return e
				}
			} else if ch.free != ch.count {
				return corrupt("missing allocated chunk bitmap", 0)
			}
			var free uint32
			for k := uint64(0); k < uint64(ch.count); k++ {
				if !littleBit(ch.bitmap, k) {
					free++
				}
			}
			if free != ch.free {
				return corrupt("chunk free accounting", 0)
			}
			cib.chunks = append(cib.chunks, ch)
			s.chunks = append(s.chunks, ch)
		}
		s.cibs = append(s.cibs, cib)
	}
	var blocks, free uint64
	for _, ch := range s.chunks {
		blocks += uint64(ch.count)
		free += uint64(ch.free)
	}
	if blocks != m.c.BlockCount || free != s.free || uint64(len(s.chunks)) != le.Uint64(b[56:]) {
		return corrupt("space manager free accounting", 0)
	}
	for i := range 2 {
		oid := le.Uint64(b[208+i*40:])
		q, e := loadCOWTree(m.ctx, oid, 9, 0x80000000, func(id uint64) ([]byte, uint64, error) {
			ep, ok := m.ephemeral[id]
			if !ok || ep.kind&0xffff != 2 && ep.kind&0xffff != 3 || ep.subtype != 9 {
				return nil, 0, corrupt("free queue mapping", 0)
			}
			return ep.data, ep.address, nil
		}, orderedPair, m.nextOID)
		if e != nil {
			return e
		}
		s.queues[i] = q
		var count uint64
		for _, r := range q.all() {
			xid, address, n := le.Uint64(r.key), le.Uint64(r.key[8:]), le.Uint64(r.value)
			if xid == 0 || xid > uint64(m.c.XID) || n == 0 {
				return corrupt("free queue entry", 0)
			}
			if i == 0 {
				if address < s.pool || address >= s.pool+s.poolCount || n > s.pool+s.poolCount-address {
					return corrupt("pool free queue range", 0)
				}
				for j := uint64(0); j < n; j++ {
					if !littleBit(s.poolBits, address+j-s.pool) {
						return corrupt("pool pending-free allocation", 0)
					}
				}
			} else {
				if address >= m.c.BlockCount || n > m.c.BlockCount-address {
					return corrupt("main free queue range", 0)
				}
				for j := uint64(0); j < n; j++ {
					if !s.used(address + j) {
						return corrupt("main pending-free allocation", 0)
					}
				}
			}
			count += n
		}
		if count != le.Uint64(b[200+i*40:]) {
			return corrupt("free queue accounting", 0)
		}
	}
	return nil
}
func (s *mutationSpace) used(address uint64) bool {
	return littleBit(s.chunks[address/32768].bitmap, address%32768)
}
func (s *mutationSpace) mark(address uint64, used bool) error {
	if address >= s.owner.c.BlockCount {
		return corrupt("allocation range", 0)
	}
	if littleBit(s.protected, address) {
		return corrupt("allocation changes a retained storage root", int64(address)*4096)
	}
	ch := s.chunks[address/32768]
	if s.used(address) == used {
		return corrupt("allocation state", 0)
	}
	setLittleBit(ch.bitmap, address%32768, used)
	ch.dirty = true
	if used {
		ch.free--
		s.free--
	} else {
		ch.free++
		s.free++
	}
	return nil
}
func (s *mutationSpace) reclaim() error {
	// Queue age alone is insufficient: retained checkpoint descriptors must be
	// disabled before their deferred allocations can be reused. Current roots
	// remain protected even after that checkpoint retirement.
	for i, q := range s.queues {
		for _, r := range q.all() {
			if le.Uint64(r.key) >= uint64(s.owner.c.XID) {
				continue
			}
			if !s.owner.reusePrepared && s.checkpointFloor != 0 && le.Uint64(r.key) >= uint64(s.checkpointFloor) {
				continue
			}
			start, count := le.Uint64(r.key[8:]), le.Uint64(r.value)
			for n := uint64(0); n < count; n++ {
				if n%32768 == 0 {
					if err := s.owner.ctx.Err(); err != nil {
						return err
					}
				}
				if i == 0 {
					if littleBit(s.protectedPool, start+n-s.pool) {
						return corrupt("retained internal-pool reference in free queue", 0)
					}
					setLittleBit(s.poolBits, start+n-s.pool, false)
				} else {
					if littleBit(s.protected, start+n) {
						return corrupt("retained storage reference in free queue", 0)
					}
					if e := s.mark(start+n, false); e != nil {
						return e
					}
				}
			}
			if e := q.put(r.key, nil); e != nil {
				return e
			}
		}
	}
	return nil
}
func (s *mutationSpace) allocate(count uint64) (uint64, uint64, error) {
	if e := s.owner.prepareReuse(); e != nil {
		return 0, 0, e
	}
	if e := s.owner.ctx.Err(); e != nil {
		return 0, 0, e
	}
	if count == 0 {
		return 0, 0, filesystem.ErrCorrupt
	}
	for _, ch := range s.chunks {
		if ch.free == 0 {
			continue
		}
		for at := ch.start; at < ch.start+uint64(ch.count); at++ {
			if s.used(at) {
				continue
			}
			n := uint64(1)
			for n < count && at+n < ch.start+uint64(ch.count) && !s.used(at+n) {
				n++
			}
			for j := uint64(0); j < n; j++ {
				if e := s.mark(at+j, true); e != nil {
					return 0, 0, e
				}
			}
			return at, n, nil
		}
	}
	return 0, 0, fmt.Errorf("APFS free allocation exhausted: %w", filesystem.ErrLimit)
}
func (s *mutationSpace) allocatePool() (uint64, error) {
	if e := s.owner.prepareReuse(); e != nil {
		return 0, e
	}
	for i := uint64(0); i < s.poolCount; i++ {
		if !littleBit(s.poolBits, i) {
			if littleBit(s.protectedPool, i) {
				return 0, corrupt("internal-pool allocation changes a retained root", 0)
			}
			setLittleBit(s.poolBits, i, true)
			return s.pool + i, nil
		}
	}
	return 0, fmt.Errorf("APFS internal pool exhausted: %w", filesystem.ErrLimit)
}
func (s *mutationSpace) retire(pool bool, address, count uint64) error {
	if count == 0 {
		return nil
	}
	i := 1
	if pool {
		i = 0
	}
	if address >= s.owner.c.BlockCount || count > s.owner.c.BlockCount-address {
		return corrupt("retired extent bounds", 0)
	}
	// Free-queue values describe ranges, not individual release events. Join
	// adjacent ranges only within this transaction and this allocation domain;
	// selected-checkpoint lifetimes remain unchanged. Namespace removal otherwise
	// consumes a queue node for every small file despite contiguous allocations.
	q := s.queues[i]
	end := address + count
	for _, r := range q.all() {
		if le.Uint64(r.key) != s.owner.xid {
			continue
		}
		start, stop := le.Uint64(r.key[8:]), le.Uint64(r.key[8:])+le.Uint64(r.value)
		if start < end && address < stop {
			return corrupt("overlapping retired extent", 0)
		}
		if stop == address || end == start {
			address, end = min(address, start), max(end, stop)
			if e := q.put(r.key, nil); e != nil {
				return e
			}
		}
	}
	key := append(buildUint64(s.owner.xid), buildUint64(address)...)
	return q.put(key, buildUint64(end-address))
}
func (s *mutationSpace) prepare() error {
	// Allocate each changed CIB and bitmap from the internal pool; their old
	// versions remain allocated in its free queue for the retained checkpoint.
	for i, cib := range s.cibs {
		dirty := false
		for _, ch := range cib.chunks {
			dirty = dirty || ch.dirty
		}
		if !dirty {
			continue
		}
		address, e := s.allocatePool()
		if e != nil {
			return e
		}
		if e = s.retire(true, cib.address, 1); e != nil {
			return e
		}
		for j, ch := range cib.chunks {
			if !ch.dirty {
				continue
			}
			ba, e := s.allocatePool()
			if e != nil {
				return e
			}
			if ch.bitmapAddress != 0 {
				if e = s.retire(true, ch.bitmapAddress, 1); e != nil {
					return e
				}
			}
			if e = s.owner.write(ch.bitmap, ba*4096); e != nil {
				return e
			}
			ch.bitmapAddress = ba
			ch.xid = s.owner.xid
			r := cib.data[40+j*32:]
			le.PutUint64(r, ch.xid)
			le.PutUint32(r[20:], ch.free)
			le.PutUint64(r[24:], ba)
		}
		sealMutationObject(cib.data, address, s.owner.xid, 0x40000007, 0)
		if e = s.owner.write(cib.data, address*4096); e != nil {
			return e
		}
		le.PutUint64(s.data[uint64(le.Uint32(s.data[80:]))+uint64(i)*8:], address)
		cib.address = address
	}
	b := s.data
	indexOff, freeOff := le.Uint32(b[328:]), le.Uint32(b[332:])
	head, tail := le.Uint16(b[320:]), le.Uint16(b[322:])
	oldIndex := le.Uint16(b[indexOff:])
	if head >= 16 || tail >= 16 || head == oldIndex {
		return corrupt("pool bitmap free ring", 0)
	}
	next := le.Uint16(b[freeOff+uint32(head)*2:])
	if next >= 16 {
		return corrupt("pool bitmap free ring exhausted", 0)
	}
	le.PutUint16(b[320:], next)
	le.PutUint16(b[freeOff+uint32(head)*2:], 0xffff)
	le.PutUint16(b[freeOff+uint32(tail)*2:], oldIndex)
	le.PutUint16(b[freeOff+uint32(oldIndex)*2:], 0xffff)
	le.PutUint16(b[322:], oldIndex)
	le.PutUint16(b[indexOff:], head)
	le.PutUint64(b[le.Uint32(b[324:]):], s.owner.xid)
	if e := s.owner.write(s.poolBits, (s.bitmapBase+uint64(head))*4096); e != nil {
		return e
	}
	le.PutUint64(b[72:], s.free)
	for i, q := range s.queues {
		var count, oldest uint64
		for _, r := range q.all() {
			count += le.Uint64(r.value)
			xid := le.Uint64(r.key)
			if oldest == 0 || xid < oldest {
				oldest = xid
			}
		}
		le.PutUint64(b[200+i*40:], count)
		le.PutUint64(b[216+i*40:], oldest)
		if len(q.reachable()) > int(le.Uint16(b[224+i*40:])) {
			return fmt.Errorf("APFS free queue node limit: %w", filesystem.ErrLimit)
		}
	}
	return nil
}
