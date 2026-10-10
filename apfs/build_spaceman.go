package apfs

// Fresh space-manager layout follows Apple's spaceman_phys_t, chunk_info_block
// and internal-pool bitmap ring. The pool is reserved in the device bitmap, and
// its own bitmap accounts only for allocated CIBs and device bitmaps inside it.
// Free-queue sizing is a native admission rule observed by the v2 formatter;
// native creation and subsequent allocation qualify it independently in v3.
func buildMainQueueLimit(blocks uint64) uint16 {
	var n uint16
	switch {
	case blocks < 0x40000:
		n = uint16(1 + (blocks-1)/4544)
	case blocks < 0x100000:
		n = uint16(116 + (blocks-261281)/2272)
	default:
		n = 512
	}
	if n == 2 {
		n = 3
	}
	return n
}
func markBuildBits(b []byte, start, end uint64) {
	for i := start; i < end; i++ {
		b[i/8] |= 1 << uint(i%8)
	}
}

func (p *Layout) addSpaceManager(g buildGeometry, reserved, reserveAllocated uint64) error {
	usedChunks := (g.usedEnd + 32767) / 32768
	firstCIB := g.poolBase + usedChunks
	sm := make([]byte, g.spacemanBlocks*4096)
	for i, v := range []uint32{4096, 32768, 126, 507} {
		le.PutUint32(sm[32+i*4:], v)
	}
	le.PutUint64(sm[0x30:], g.blocks)
	le.PutUint64(sm[0x38:], g.chunks)
	le.PutUint32(sm[0x40:], uint32(g.cibs))
	le.PutUint64(sm[0x48:], g.blocks-g.usedEnd)
	le.PutUint32(sm[0x50:], g.deviceAddressOffset)
	le.PutUint32(sm[0x80:], g.deviceAddressOffset+uint32(g.cibs*8))
	le.PutUint32(sm[0x94:], 16)
	le.PutUint64(sm[0x98:], g.poolBlocks)
	le.PutUint32(sm[0xa0:], uint32(g.poolBitmapBlocks))
	le.PutUint32(sm[0xa4:], uint32(16*g.poolBitmapBlocks))
	le.PutUint64(sm[0xa8:], g.bitmapBase)
	le.PutUint64(sm[0xb0:], g.poolBase)
	le.PutUint64(sm[0xb8:], reserved)
	le.PutUint64(sm[0xc0:], reserveAllocated)
	le.PutUint16(sm[0x140:], uint16(g.poolBitmapBlocks))
	le.PutUint16(sm[0x142:], uint16(16*g.poolBitmapBlocks-1))
	le.PutUint32(sm[0x144:], 0x150)
	le.PutUint32(sm[0x148:], g.bitmapAddressOffset)
	le.PutUint32(sm[0x14c:], g.bitmapFreeOffset)
	for i := uint64(0); i < g.poolBitmapBlocks; i++ {
		le.PutUint64(sm[0x150+i*8:], 1)
		le.PutUint16(sm[uint64(g.bitmapAddressOffset)+2*i:], uint16(i))
	}
	for i := uint64(0); i < 16*g.poolBitmapBlocks; i++ {
		next := uint16(i + 1)
		if i < g.poolBitmapBlocks || i == 16*g.poolBitmapBlocks-1 {
			next = 0xffff
		}
		le.PutUint16(sm[uint64(g.bitmapFreeOffset)+2*i:], next)
	}
	ipLimit := uint16(3*(g.chunks+751)/1127 - 1)
	if ipLimit == 2 {
		ipLimit = 3
	}
	for i, q := range [][2]uint64{{buildIPQueueOID, uint64(ipLimit)}, {buildMainQueueOID, uint64(buildMainQueueLimit(g.blocks))}} {
		fq := sm[0xc8+i*40:]
		le.PutUint64(fq[8:], q[0])
		le.PutUint16(fq[24:], uint16(q[1]))
		t, err := newBuildTree(nil, 9, 0x80000000, true)
		if err != nil {
			return err
		}
		t.place(g.dataBase+1+g.spacemanBlocks+uint64(i), q[0])
		p.parts = append(p.parts, t.blocks()...)
	}
	for ci := uint64(0); ci < g.cibs; ci++ {
		b := make([]byte, 4096)
		le.PutUint32(b[32:], uint32(ci))
		count := min(uint64(126), g.chunks-ci*126)
		le.PutUint32(b[36:], uint32(count))
		for j := uint64(0); j < count; j++ {
			index := ci*126 + j
			start := index * 32768
			count := min(uint64(32768), g.blocks-start)
			used := uint64(0)
			if start < g.usedEnd {
				used = min(count, g.usedEnd-start)
			}
			record := b[40+j*32:]
			le.PutUint64(record, 1)
			le.PutUint64(record[8:], start)
			le.PutUint32(record[16:], uint32(count))
			le.PutUint32(record[20:], uint32(count-used))
			if used != 0 {
				le.PutUint64(record[24:], g.poolBase+index)
			}
		}
		address := firstCIB + ci
		le.PutUint64(sm[uint64(g.deviceAddressOffset)+ci*8:], address)
		p.addBlock(address, b, address, 0x40000007, 0)
	}
	ip := make([]byte, g.poolBitmapBlocks*4096)
	markBuildBits(ip, 0, usedChunks+g.cibs)
	p.parts = append(p.parts, buildPart{offset: int64(g.bitmapBase) * 4096, data: ip})
	for i := uint64(0); i < usedChunks; i++ {
		b := make([]byte, 4096)
		start := i * 32768
		markBuildBits(b, 0, min(uint64(32768), g.usedEnd-start))
		p.parts = append(p.parts, buildPart{offset: int64(g.poolBase+i) * 4096, data: b})
	}
	p.addBlock(g.dataBase+1, sm, buildSpacemanOID, 0x80000005, 0)
	return nil
}
