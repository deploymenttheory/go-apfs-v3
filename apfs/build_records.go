package apfs

import (
	"hash/crc32"
	"sort"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/names"
)

func buildKey(id uint64, kind uint64, extra int) []byte {
	b := make([]byte, 8+extra)
	le.PutUint64(b, id|kind<<60)
	return b
}
func buildUint64(v uint64) []byte { b := make([]byte, 8); le.PutUint64(b, v); return b }
func buildStreamValue(s *buildStream) []byte {
	b := make([]byte, 40)
	le.PutUint64(b, uint64(s.size))
	le.PutUint64(b[8:], s.blocks*4096)
	le.PutUint64(b[24:], uint64(s.size))
	return b
}
func buildXFields(types, flags []byte, values [][]byte) []byte {
	used := 0
	for _, v := range values {
		used += (len(v) + 7) / 8 * 8
	}
	b := make([]byte, 4+4*len(values)+used)
	le.PutUint16(b, uint16(len(values)))
	le.PutUint16(b[2:], uint16(used))
	at := 4 + 4*len(values)
	for i, v := range values {
		b[4+4*i] = types[i]
		b[5+4*i] = flags[i]
		le.PutUint16(b[6+4*i:], uint16(len(v)))
		copy(b[at:], v)
		at += (len(v) + 7) / 8 * 8
	}
	return b
}
func buildInode(o *buildObject, documentID uint32) buildRecord {
	m := o.node.Metadata
	b := make([]byte, 92)
	a := o.aliases[0]
	le.PutUint64(b, a.parent)
	le.PutUint64(b[8:], o.id)
	for i, t := range []time.Time{m.BirthTime.Value, m.ModifyTime.Value, m.ChangeTime.Value, m.AccessTime.Value} {
		ns, _ := buildTime(t)
		le.PutUint64(b[16+8*i:], ns)
	}
	internal := uint64(0x8000)
	if o.node.Compression.State == filesystem.Present {
		internal |= 0x40000 // INODE_HAS_UNCOMPRESSED_SIZE
		le.PutUint64(b[84:], o.node.Size)
	}
	for _, a := range o.attrs {
		switch a.name {
		case filesystem.FinderInfo:
			internal |= 0x100
		case filesystem.ResourceFork:
			internal = internal&^0x8000 | 0x4000
		case "com.apple.system.Security":
			internal |= 0x40
		}
	}
	le.PutUint64(b[48:], internal)
	count := uint32(len(o.aliases))
	if m.Mode.Value&0170000 == 0040000 {
		count = o.children
	}
	le.PutUint32(b[56:], count)
	le.PutUint32(b[68:], m.BSDFlags.Value)
	le.PutUint32(b[72:], m.UID.Value)
	le.PutUint32(b[76:], m.GID.Value)
	le.PutUint16(b[80:], uint16(m.Mode.Value))
	types, flags := []byte{4}, []byte{2}
	values := [][]byte{append([]byte(a.name), 0)}
	if o.data != nil {
		types = append(types, 8)
		flags = append(flags, 0x20)
		values = append(values, buildStreamValue(o.data))
	}
	if documentID != 0 {
		v := make([]byte, 4)
		le.PutUint32(v, documentID)
		types = append(types, 3)
		flags = append(flags, 0x22)
		values = append(values, v)
	}
	return buildRecord{buildKey(o.id, 3, 0), append(b, buildXFields(types, flags, values)...)}
}

var buildNameCRC = crc32.MakeTable(crc32.Castagnoli)

func (p *Layout) directoryRecord(a buildAlias, id uint64, kind uint16) buildRecord {
	key := buildKey(a.parent, 9, 4+len(a.name)+1)
	h := uint32(0xffffffff)
	for _, r := range names.APFS(a.name, p.options.CaseSensitive, true) {
		v := uint32(r)
		for range 4 {
			h = buildNameCRC[byte(h^v)] ^ (h >> 8)
			v >>= 8
		}
	}
	le.PutUint32(key[8:], (h&0x3fffff)<<10|uint32(len(a.name)+1))
	copy(key[12:], a.name)
	b := make([]byte, 18)
	le.PutUint64(b, id)
	ns, _ := buildTime(p.options.Time)
	le.PutUint64(b[8:], ns)
	le.PutUint16(b[16:], kind)
	if a.id != 0 {
		b = append(b, buildXFields([]byte{1}, []byte{2}, [][]byte{buildUint64(a.id)})...)
	}
	return buildRecord{key, b}
}
func buildXattr(id uint64, name string, value []byte, flags uint16) buildRecord {
	key := buildKey(id, 4, 2+len(name)+1)
	le.PutUint16(key[8:], uint16(len(name)+1))
	copy(key[10:], name)
	b := make([]byte, 4+len(value))
	le.PutUint16(b, flags)
	le.PutUint16(b[2:], uint16(len(value)))
	copy(b[4:], value)
	return buildRecord{key, b}
}

func (p *Layout) records() ([]buildRecord, []buildRecord, uint32) {
	root := p.objects[0]
	priv := &buildObject{id: 3, node: root.node, aliases: []buildAlias{{parent: 1, name: "private-dir"}}}
	priv.node.Metadata.Mode = filesystem.Observed(uint32(0040700))
	priv.node.Metadata.BSDFlags = filesystem.Observed(uint32(0))
	records := []buildRecord{p.directoryRecord(root.aliases[0], 2, 4), p.directoryRecord(priv.aliases[0], 3, 4), buildInode(priv, 0)}
	documentID := uint32(3)
	for _, o := range p.objects {
		doc := uint32(0)
		if o.node.Metadata.BSDFlags.Value&0x40 != 0 {
			doc = documentID
			documentID++
		}
		records = append(records, buildInode(o, doc))
		if o.id != 2 {
			for _, a := range o.aliases {
				records = append(records, p.directoryRecord(a, o.id, uint16(o.node.Metadata.Mode.Value>>12)))
				if a.id != 0 {
					key := buildKey(o.id, 5, 8)
					le.PutUint64(key[8:], a.id)
					v := make([]byte, 10+len(a.name)+1)
					le.PutUint64(v, a.parent)
					le.PutUint16(v[8:], uint16(len(a.name)+1))
					copy(v[10:], a.name)
					records = append(records, buildRecord{key, v}, buildRecord{buildKey(a.id, 12, 0), buildUint64(o.id)})
				}
			}
		}
		if o.target != "" {
			records = append(records, buildXattr(o.id, "com.apple.fs.symlink", append([]byte(o.target), 0), 6))
		}
		for _, a := range o.attrs {
			v := a.inline
			flags := uint16(2)
			if a.stream != nil {
				flags = 1
				v = append(buildUint64(a.stream.id), buildStreamValue(a.stream)...)
			}
			records = append(records, buildXattr(o.id, a.name, v, flags))
		}
	}
	var extents []buildRecord
	for _, s := range p.streams {
		if s.attribute == "" {
			v := make([]byte, 4)
			le.PutUint32(v, 1)
			records = append(records, buildRecord{buildKey(s.id, 6, 0), v})
		}
		if s.blocks == 0 {
			continue
		}
		value := make([]byte, 24)
		le.PutUint64(value, s.blocks*4096)
		le.PutUint64(value[8:], s.start)
		records = append(records, buildRecord{buildKey(s.id, 8, 8), value})
		value = make([]byte, 20)
		le.PutUint64(value, 1<<60|s.blocks)
		le.PutUint64(value[8:], s.id)
		le.PutUint32(value[16:], 1)
		extents = append(extents, buildRecord{buildKey(s.start, 2, 0), value})
	}
	sort.Slice(records, func(i, j int) bool { return p.recordLess(records[i].key, records[j].key) })
	return records, extents, documentID
}
func (p *Layout) recordLess(a, b []byte) bool {
	x, y := le.Uint64(a), le.Uint64(b)
	if x&0x0fffffffffffffff != y&0x0fffffffffffffff {
		return x&0x0fffffffffffffff < y&0x0fffffffffffffff
	}
	if x>>60 != y>>60 {
		return x>>60 < y>>60
	}
	switch x >> 60 {
	case 4:
		return string(a[10:]) < string(b[10:])
	case 5, 8:
		return le.Uint64(a[8:]) < le.Uint64(b[8:])
	case 9:
		h, k := le.Uint32(a[8:])>>10, le.Uint32(b[8:])>>10
		if h != k {
			return h < k
		}
		return names.APFS(string(a[12:len(a)-1]), p.options.CaseSensitive, true) < names.APFS(string(b[12:len(b)-1]), p.options.CaseSensitive, true)
	}
	return false
}
