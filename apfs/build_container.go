package apfs

import (
	"context"
	"fmt"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const (
	buildSpacemanOID  = 1024
	buildReaperOID    = 1025
	buildIPQueueOID   = 1026
	buildMainQueueOID = 1027
	buildVolumeOID    = 1028
)

type buildGeometry struct {
	blocks, chunks, cibs, poolBlocks, poolBitmapBlocks, spacemanBlocks             uint64
	bitmapAddressOffset, bitmapFreeOffset, deviceAddressOffset                     uint32
	dataBase, dataBlocks, containerMap, bitmapBase, poolBase, payloadBase, usedEnd uint64
}

func buildGeometryFor(blocks uint64) buildGeometry {
	g := buildGeometry{blocks: blocks, chunks: (blocks + 32767) / 32768, dataBase: 9}
	g.cibs = (g.chunks + 125) / 126
	g.poolBlocks = 3 * (g.chunks + g.cibs)
	g.poolBitmapBlocks = (g.poolBlocks + 32767) / 32768
	g.bitmapAddressOffset = 0x150 + uint32(8*g.poolBitmapBlocks)
	g.bitmapFreeOffset = g.bitmapAddressOffset + uint32((2*g.poolBitmapBlocks+7)/8*8)
	g.deviceAddressOffset = g.bitmapFreeOffset + uint32(16*g.poolBitmapBlocks*2)
	g.spacemanBlocks = (uint64(g.deviceAddressOffset) + 8*g.cibs + 4095) / 4096
	g.dataBlocks = max(uint64(8), g.spacemanBlocks+3)
	g.containerMap = g.dataBase + g.dataBlocks
	return g
}

func buildObjectMap(records []buildRecord) (*buildTree, error) {
	return newBuildTree(records, 11, 0x40000000, true)
}
func buildMapping(oid, address uint64) buildRecord {
	key := buildUint64(oid)
	key = append(key, buildUint64(1)...)
	val := make([]byte, 16)
	le.PutUint32(val[4:], 4096)
	le.PutUint64(val[8:], address)
	return buildRecord{key, val}
}

type volumeTrees struct {
	volume                        *volumeLayout
	fst, extents, snapshots, omap *buildTree
	oid, address, mapAddress      uint64
}

func fillBuildTree(t *buildTree, records []buildRecord) {
	at := 0
	for _, n := range t.nodes {
		if n.level == 0 {
			copy(n.records, records[at:at+len(n.records)])
			at += len(n.records)
		}
	}
	for _, n := range t.nodes {
		for i, c := range n.children {
			n.records[i].key = c.records[0].key
		}
	}
}

func (p *Layout) arrange(ctx context.Context) error {
	var payload, nodes, reserved, reserveAllocated uint64
	var trees []volumeTrees
	for _, v := range p.volumes {
		records, extents, _ := v.records()
		fst, err := newBuildTree(records, 14, 0, false)
		if err != nil {
			return err
		}
		ert, err := newBuildTree(extents, 15, 0x40000000, false)
		if err != nil {
			return err
		}
		snap, err := newBuildTree(nil, 16, 0x40000000, false)
		if err != nil {
			return err
		}
		mappings := make([]buildRecord, len(fst.nodes))
		for i := range mappings {
			mappings[i] = buildMapping(uint64(i), 0)
		}
		omap, err := buildObjectMap(mappings)
		if err != nil {
			return err
		}
		count := uint64(len(fst.nodes) + len(ert.nodes) + len(snap.nodes) + len(omap.nodes))
		used := uint64(0)
		for _, stream := range v.streams {
			used += stream.blocks
		}
		v.allocated = count + 1 + used
		quota := uint64(v.options.Quota+4095) / 4096
		if quota != 0 && v.allocated > quota {
			return fmt.Errorf("volume %q exceeds its quota: %w", v.options.Name, filesystem.ErrLimit)
		}
		reserve := uint64(v.options.Reserve+4095) / 4096
		reserved += reserve
		reserveAllocated += min(reserve, v.allocated)
		nodes += count + 2
		payload += used
		trees = append(trees, volumeTrees{volume: v, fst: fst, extents: ert, snapshots: snap, omap: omap})
	}
	mappings := make([]buildRecord, len(trees))
	for i := range mappings {
		mappings[i] = buildMapping(uint64(i), 0)
	}
	cmap, err := buildObjectMap(mappings)
	if err != nil {
		return err
	}
	minimum := max(uint64(2048), uint64(len(trees)-1)*131072+1)
	blocks := uint64(p.options.Capacity+4095) / 4096
	if blocks == 0 {
		blocks = max(minimum, payload+nodes+reserved-reserveAllocated+(payload+nodes)/8+128)
	}
	var g buildGeometry
	var oid uint64
	for {
		if blocks < minimum || blocks > 1<<28 {
			return fmt.Errorf("APFS capacity cannot hold %d volumes: %w", len(trees), filesystem.ErrLimit)
		}
		g = buildGeometryFor(blocks)
		at := cmap.place(g.containerMap+1, 0)
		oid = buildVolumeOID
		for i := range trees {
			v := &trees[i]
			v.oid, v.address, v.mapAddress = oid, at, at+1
			at = v.fst.place(at+2, oid+1)
			oid += 1 + uint64(len(v.fst.nodes))
			at = v.extents.place(at, 0)
			at = v.snapshots.place(at, 0)
			at = v.omap.place(at, 0)
		}
		g.bitmapBase = at
		g.poolBase = at + 16*g.poolBitmapBlocks
		g.payloadBase = g.poolBase + g.poolBlocks
		g.usedEnd = g.payloadBase + payload
		required := g.usedEnd + reserved - reserveAllocated
		if required <= blocks {
			break
		}
		if p.options.Capacity != 0 {
			return fmt.Errorf("APFS container capacity, including reservations: %w", filesystem.ErrLimit)
		}
		// Space-manager overhead itself grows with capacity. Recompute until
		// automatic sizing covers both that overhead and unused reservations.
		blocks = required + 128
	}
	if err = p.volumes[0].reserve(int64(nodes+uint64(len(cmap.nodes))+g.cibs+g.spacemanBlocks+g.poolBitmapBlocks+(g.usedEnd+32767)/32768+8) * 4096); err != nil {
		return err
	}
	p.size = int64(blocks * 4096)
	at := g.payloadBase
	for i, t := range trees {
		v := t.volume
		for _, stream := range v.streams {
			stream.start = at
			at += stream.blocks
			if stream.blocks != 0 {
				p.parts = append(p.parts, buildPart{offset: int64(stream.start) * 4096, stream: stream})
			}
		}
		records, extents, nextDoc := v.records()
		fillBuildTree(t.fst, records)
		fillBuildTree(t.extents, extents)
		vm := make([]buildRecord, len(t.fst.nodes))
		for j, n := range t.fst.nodes {
			vm[j] = buildMapping(n.oid, n.address)
		}
		fillBuildTree(t.omap, vm)
		for _, tree := range []*buildTree{t.fst, t.extents, t.snapshots, t.omap} {
			p.parts = append(p.parts, tree.blocks()...)
		}
		p.addMap(t.mapAddress, t.omap.root().address, false)
		p.addVolume(t, uint32(i), nextDoc)
		mappings[i] = buildMapping(t.oid, t.address)
	}
	fillBuildTree(cmap, mappings)
	p.parts = append(p.parts, cmap.blocks()...)
	p.addMap(g.containerMap, cmap.root().address, true)
	if err = p.addSpaceManager(g, reserved, reserveAllocated); err != nil {
		return err
	}
	p.addCheckpoint(g, oid, trees)
	sort.Slice(p.parts, func(i, j int) bool { return p.parts[i].offset < p.parts[j].offset })
	end := int64(0)
	for _, part := range p.parts {
		if part.offset < end {
			return filesystem.ErrCorrupt
		}
		end = part.offset + int64(len(part.data))
		if part.stream != nil {
			end = part.offset + int64(part.stream.blocks)*4096
		}
	}
	if end > p.size {
		return filesystem.ErrCorrupt
	}
	return ctx.Err()
}
func (p *Layout) addBlock(address uint64, b []byte, oid uint64, kind, subtype uint32) {
	sealBuildObject(b, oid, kind, subtype)
	p.parts = append(p.parts, buildPart{offset: int64(address) * 4096, data: b})
}
func (p *Layout) addMap(address, root uint64, manual bool) {
	b := make([]byte, 4096)
	if manual {
		le.PutUint32(b[32:], 1)
	}
	le.PutUint32(b[40:], 0x40000002)
	le.PutUint32(b[44:], 0x40000002)
	le.PutUint64(b[48:], root)
	p.addBlock(address, b, address, 0x4000000b, 0)
}
func (p *Layout) addVolume(t volumeTrees, index, nextDoc uint32) {
	v := t.volume
	b := make([]byte, 4096)
	copy(b[32:], "APSB")
	le.PutUint32(b[36:], index)
	features := uint64(2) // APFS_FEATURE_HARDLINK_MAP_RECORDS
	if v.grouped {
		features |= volumeGroupInodeSpace
	}
	le.PutUint64(b[40:], features)
	incompat := uint64(1)
	if v.options.CaseSensitive {
		incompat = 8
	}
	le.PutUint64(b[56:], incompat)

	le.PutUint64(b[72:], uint64(v.options.Reserve+4095)/4096)
	le.PutUint64(b[80:], uint64(v.options.Quota+4095)/4096)
	le.PutUint64(b[88:], v.allocated) // volume map, its tree, the three other trees, data
	le.PutUint16(b[96:], 5)
	le.PutUint32(b[104:], 6)
	le.PutUint16(b[112:], 1)
	le.PutUint32(b[116:], 2)
	le.PutUint32(b[120:], 0x40000002)
	le.PutUint32(b[124:], 0x40000002)
	le.PutUint64(b[128:], t.mapAddress)
	le.PutUint64(b[136:], t.fst.root().oid)
	le.PutUint64(b[144:], t.extents.root().address)
	le.PutUint64(b[152:], t.snapshots.root().address)
	le.PutUint64(b[176:], v.nextID)
	for _, o := range v.objects {
		if o.id == 2 {
			continue
		}
		off := 184
		switch o.node.Metadata.Mode.Value & 0170000 {
		case 0040000:
			off = 192
		case 0120000:
			off = 200
		}
		le.PutUint64(b[off:], le.Uint64(b[off:])+1)
	}
	le.PutUint64(b[224:], v.allocated)
	copy(b[240:], v.options.UUID[:])
	le.PutUint64(b[264:], 1)
	copy(b[272:], "go-apfs-v3")
	stamp, _ := buildTime(p.options.Time)
	le.PutUint64(b[304:], stamp)
	le.PutUint64(b[312:], 1)
	copy(b[704:], v.options.Name)
	le.PutUint32(b[960:], nextDoc)
	le.PutUint16(b[964:], v.options.Role)
	v.superblock = b
	p.addBlock(t.address, b, t.oid, 13, 0)
}
func (p *Layout) addCheckpoint(g buildGeometry, nextOID uint64, volumes []volumeTrees) {
	reaper := make([]byte, 4096)
	le.PutUint64(reaper[32:], 1)
	le.PutUint32(reaper[64:], 1)
	le.PutUint32(reaper[108:], 4096-112)
	p.addBlock(g.dataBase, reaper, buildReaperOID, 0x80000011, 0)
	mapBlock := make([]byte, 4096)
	le.PutUint32(mapBlock[32:], 1)
	le.PutUint32(mapBlock[36:], 4)
	for i, m := range [][5]uint64{
		{0x80000011, 0, 4096, buildReaperOID, g.dataBase},
		{0x80000005, 0, g.spacemanBlocks * 4096, buildSpacemanOID, g.dataBase + 1},
		{0x80000002, 9, 4096, buildIPQueueOID, g.dataBase + 1 + g.spacemanBlocks},
		{0x80000002, 9, 4096, buildMainQueueOID, g.dataBase + 2 + g.spacemanBlocks},
	} {
		at := 40 + i*40
		le.PutUint32(mapBlock[at:], uint32(m[0]))
		le.PutUint32(mapBlock[at+4:], uint32(m[1]))
		le.PutUint32(mapBlock[at+8:], uint32(m[2]))
		le.PutUint64(mapBlock[at+24:], m[3])
		le.PutUint64(mapBlock[at+32:], m[4])
	}
	p.addBlock(1, mapBlock, 1, 0x4000000c, 0)
	b := make([]byte, 4096)
	copy(b[32:], "NXSB")
	le.PutUint32(b[36:], 4096)
	le.PutUint64(b[40:], g.blocks)
	le.PutUint64(b[64:], 2)
	copy(b[72:], p.options.UUID[:])
	le.PutUint64(b[88:], nextOID)
	le.PutUint64(b[96:], 2)
	le.PutUint32(b[104:], 8)
	le.PutUint32(b[108:], uint32(g.dataBlocks))
	le.PutUint64(b[112:], 1)
	le.PutUint64(b[120:], g.dataBase)
	le.PutUint32(b[128:], 2)
	le.PutUint32(b[132:], uint32(g.spacemanBlocks+3))
	le.PutUint32(b[140:], 2)
	le.PutUint32(b[148:], uint32(g.spacemanBlocks+3))
	le.PutUint64(b[152:], buildSpacemanOID)
	le.PutUint64(b[160:], g.containerMap)
	le.PutUint64(b[168:], buildReaperOID)
	le.PutUint32(b[180:], uint32(min(uint64(100), (g.blocks+131071)/131072)))
	for i, v := range volumes {
		le.PutUint64(b[184+i*8:], v.oid)
	}
	minimum := uint64(8)
	if g.blocks < 32768 {
		minimum = uint64(buildMainQueueLimit(g.blocks))
	}
	le.PutUint64(b[1312:], minimum<<32|4<<16|1)
	p.addBlock(0, b, 1, 0x80000001, 0)
	cp := append([]byte(nil), b...)
	p.addBlock(2, cp, 1, 0x80000001, 0)
}
