package apfs

import (
	"bytes"
	"fmt"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v3/internal/filesec"
)

func (m *mutation) modifyFile(c Change, id, stamp uint64) (uint64, error) {
	var e error
	r, ok := m.fs.get(buildKey(id, 3, 0))
	if !ok {
		return 0, corrupt("change inode", 0)
	}
	value := bytes.Clone(r.value)
	kind := le.Uint16(value[80:]) & 0170000
	if (kind != 0100000 && (kind != 0040000 || c.Data != nil)) || le.Uint32(value[68:])&0x60006 != 0 || le.Uint64(value[48:])&(1|0x80|0x200000|0x400000) != 0 {
		return 0, fmt.Errorf("APFS change requires an ordinary mutable file or directory: %w", filesystem.ErrUnsupported)
	}
	if c.Data == nil {
		return 0, fs.ErrInvalid
	}

	permission, e := filesec.WriteMode(uint32(le.Uint16(value[80:])), c.ActorUID)
	if e != nil {
		return 0, e
	}
	le.PutUint16(value[80:], uint16(permission))
	if c.Operation == "chmod" || c.Mode != "" || c.Data.Size() < 0 {
		return 0, fs.ErrInvalid
	}
	if c.ResourceFork {
		if e = m.changeAttribute(Change{Attribute: filesystem.ResourceFork, Data: c.Data}, id, value); e != nil {
			return 0, e
		}
	} else {
		statistics, err := statisticsForInode(value)
		if err != nil {
			return 0, err
		}
		var delta uint64
		if statistics.allocated != 0 {
			delta += 2
		}
		if c.Data.Size() != 0 {
			delta += 2
		}
		if e = m.bumpStatistics(statistics.key, delta); e != nil {
			return 0, e
		}
		if le.Uint32(value[68:])&0x20 != 0 {
			compression, e := decmpfs.Inspect(func(name string) (filesystem.Value, error) { return m.v.OpenAttribute(m.ctx, id, name) })
			if e != nil {
				return 0, e
			}
			ownsFork, e := decmpfs.UsesResourceFork(compression.Type)
			if e != nil {
				return 0, e
			}
			remove := []string{filesystem.Decmpfs}
			if ownsFork {
				remove = append(remove, filesystem.ResourceFork)
			}
			for _, name := range remove {
				key := buildXattr(id, name, nil, 2).key
				if attr, ok := m.fs.get(key); ok {
					if e = m.removeAttributeStream(attr); e != nil {
						return 0, e
					}
					if e = m.fs.put(key, nil); e != nil {
						return 0, e
					}
				}
			}
			le.PutUint32(value[68:], le.Uint32(value[68:])&^uint32(0x20))
			le.PutUint64(value[48:], le.Uint64(value[48:])&^uint64(0x40000))
			if ownsFork {
				le.PutUint64(value[48:], le.Uint64(value[48:])&^uint64(0x4000)|0x8000)
			}
			le.PutUint64(value[84:], 0)
		}
		stream := le.Uint64(value[8:])
		if stream == 0 {
			stream = id
			le.PutUint64(value[8:], stream)
		}
		blocks, e := m.replaceStream(stream, stream, c.Data)
		if e != nil {
			return 0, e
		}
		sv := make([]byte, 40)
		le.PutUint64(sv, uint64(c.Data.Size()))
		le.PutUint64(sv[8:], blocks*4096)
		le.PutUint64(sv[24:], uint64(c.Data.Size()))
		value, e = replaceInodeField(value, 8, 0x20, sv)
		if e != nil {
			return 0, e
		}
		rc := make([]byte, 4)
		le.PutUint32(rc, 1)
		if e = m.fs.put(buildKey(stream, 6, 0), rc); e != nil {
			return 0, e
		}
		le.PutUint64(value[24:], stamp)
	}
	le.PutUint64(value[24:], stamp)

	le.PutUint64(value[32:], stamp)
	if e = m.fs.put(r.key, value); e != nil {
		return 0, e
	}
	return id, nil
}
func (m *mutation) nextFileID() (uint64, error) {
	id := le.Uint64(m.super[176:])
	if id < 16 || id >= objectMask {
		return 0, filesystem.ErrLimit
	}
	le.PutUint64(m.super[176:], id+1)
	return id, nil
}
func replaceInodeField(inode []byte, kind, flag byte, data []byte) ([]byte, error) {
	return updateInodeField(inode, kind, flag, data, false)
}
func removeInodeField(inode []byte, kind byte) ([]byte, error) {
	return updateInodeField(inode, kind, 0, nil, true)
}
func updateInodeField(inode []byte, kind, flag byte, data []byte, remove bool) ([]byte, error) {
	var types, flags []byte
	var values [][]byte
	found := false
	b := inode[92:]
	if len(b) > 0 {
		n := int(le.Uint16(b))
		at := 4 + n*4
		if at > len(b) {
			return nil, corrupt("change extended fields", 0)
		}
		for i := 0; i < n; i++ {
			size := int(le.Uint16(b[6+i*4:]))
			if at+size > len(b) {
				return nil, corrupt("change extended field bounds", 0)
			}
			k, f := b[4+i*4], b[5+i*4]
			v := bytes.Clone(b[at : at+size])
			if k == kind {
				if remove {
					at += (size + 7) / 8 * 8
					continue
				}
				v = data
				// Flags include reserved bits that Apple's format requires us to
				// retain. The supplied flag applies only when adding a new field.
				found = true
			}
			types = append(types, k)
			flags = append(flags, f)
			values = append(values, v)
			at += (size + 7) / 8 * 8
		}
	}
	if !found && !remove {
		types = append(types, kind)
		flags = append(flags, flag)
		values = append(values, data)
	}
	return append(bytes.Clone(inode[:92]), buildXFields(types, flags, values)...), nil
}
func (m *mutation) removeAttributeStream(attr buildRecord) error {
	if le.Uint16(attr.value)&1 == 0 {
		return nil
	}
	if len(attr.value) != 52 {
		return corrupt("changed attribute stream", 0)
	}
	return m.removeStream(le.Uint64(attr.value[4:]))
}
func (m *mutation) removeStream(id uint64) error {
	for _, r := range m.fs.records(id, 8) {
		address := le.Uint64(r.value[8:])
		blocks := (le.Uint64(r.value) & ((1 << 56) - 1)) / 4096
		if address != 0 {
			if e := m.releaseExtent(address, blocks); e != nil {
				return e
			}
			if e := m.space.retire(false, address, blocks); e != nil {
				return e
			}
			m.freed += blocks
		}
		if e := m.fs.put(r.key, nil); e != nil {
			return e
		}
	}
	return nil
}
func (m *mutation) replaceStream(id, owner uint64, data block.Source) (uint64, error) {
	if e := m.removeStream(id); e != nil {
		return 0, e
	}
	size := uint64(data.Size())
	var logical, total uint64
	buf := make([]byte, 128<<10)
	for logical < size {
		need := (size - logical + 4095) / 4096
		address, count, e := m.space.allocate(need)
		if e != nil {
			return 0, e
		}
		for off := uint64(0); off < count*4096; {
			if e = m.ctx.Err(); e != nil {
				return 0, e
			}
			n := min(uint64(len(buf)), count*4096-off)
			clear(buf[:n])
			take := min(n, size-logical-off)
			if logical+off >= size {
				take = 0
			}
			if take > 0 {
				if e = block.ReadFull(data, buf[:take], int64(logical+off)); e != nil {
					return 0, e
				}
			}
			if e = m.write(buf[:n], address*4096+off); e != nil {
				return 0, e
			}
			off += n
		}
		key := buildKey(id, 8, 8)
		le.PutUint64(key[8:], logical)
		value := make([]byte, 24)
		le.PutUint64(value, count*4096)
		le.PutUint64(value[8:], address)
		if e = m.fs.put(key, value); e != nil {
			return 0, e
		}
		ref := buildExtentReference(address, count, owner)
		if e = m.extents.put(ref.key, ref.value); e != nil {
			return 0, e
		}
		logical += count * 4096
		total += count
		m.allocated += count
	}
	return total, nil
}
