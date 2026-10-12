package apfs

import (
	"bytes"
	"errors"
	"io/fs"
	"math"
	"sort"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/metadata"
	"github.com/deploymenttheory/go-apfs-v3/internal/mode"
)

func (m *mutation) editMetadata(c Change, stamp uint64) (uint64, error) {
	if err := metadata.ValidateChange(c); err != nil {
		return 0, err
	}
	entry, err := m.lookupEntry(c.Path)
	if errors.Is(err, fs.ErrNotExist) && c.Operation == "touch" {
		if c.NoCreate || c.NoFollow {
			return 0, nil
		}
		parent, name, e := m.destination(c.Path)
		if e != nil {
			return 0, e
		}
		entry, err = m.createEntry(parent, name, false, "", stamp)
	}
	if err != nil {
		return 0, err
	}
	if c.Recursive {
		var targets []*mutationEntry
		seen := map[uint64]bool{}
		var walk func(*mutationEntry, int) error
		walk = func(e *mutationEntry, depth int) error {
			if depth > 256 {
				return filesystem.ErrLimit
			}
			if seen[e.id] {
				return nil
			}
			inode, err := m.inodeRecord(e.id)
			if err != nil {
				return err
			}
			if le.Uint16(inode.value[80:])&0170000 == 0120000 && c.Operation != "chown" && !c.NoFollow {
				return nil
			}
			seen[e.id] = true
			targets = append(targets, e)
			keys := make([]string, 0, len(m.entries[e.id]))
			for k := range m.entries[e.id] {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if err := walk(m.entries[e.id][k], depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		if err = walk(entry, 0); err != nil {
			return 0, err
		}
		c.Recursive = false
		c.NoFollow = true
		for _, e := range targets {
			if err = m.metadataObject(c, e, stamp); err != nil {
				return 0, err
			}
		}
	} else {
		err = m.metadataObject(c, entry, stamp)
	}
	return entry.id, err
}

func (m *mutation) metadataObject(c Change, e *mutationEntry, stamp uint64) error {
	if err := m.ctx.Err(); err != nil {
		return err
	}
	if err := m.protectMetadataEntry(e, true, c.Operation == "chflags"); err != nil {
		return err
	}
	r, err := m.inodeRecord(e.id)
	if err != nil {
		return err
	}
	value := bytes.Clone(r.value)
	kind := le.Uint16(value[80:]) & 0170000
	if kind != 0100000 && kind != 0040000 && kind != 0120000 {
		return filesystem.ErrUnsupported
	}
	if kind == 0120000 && !c.NoFollow {
		return filesystem.ErrUnsupported
	}
	switch c.Operation {
	case "chmod":
		if le.Uint64(value[48:])&0x40 != 0 {
			return filesystem.ErrUnsupported
		}
		program, err := mode.Parse(c.Mode, 0)
		if err != nil {
			return err
		}
		le.PutUint16(value[80:], uint16(program.Apply(uint32(le.Uint16(value[80:])))))
	case "chown":
		if le.Uint16(value[80:])&06000 != 0 {
			return filesystem.ErrUnsupported
		}
		if c.Metadata.UID.State == filesystem.Present {
			le.PutUint32(value[72:], c.Metadata.UID.Value)
		}
		if c.Metadata.GID.State == filesystem.Present {
			le.PutUint32(value[76:], c.Metadata.GID.Value)
		}
	case "chflags":
		flags, err := metadata.Flags(le.Uint32(value[68:]), c.Flags)
		if err != nil {
			return err
		}
		le.PutUint32(value[68:], flags)
	case "touch":
		var reference *filesystem.Metadata
		if c.Reference != "" {
			ref, err := m.lookupEntry(c.Reference)
			if err != nil {
				return err
			}
			rr, err := m.inodeRecord(ref.id)
			if err != nil {
				return err
			}
			reference = &filesystem.Metadata{ModifyTime: filesystem.Observed(time.Unix(0, int64(le.Uint64(rr.value[24:])))), AccessTime: filesystem.Observed(time.Unix(0, int64(le.Uint64(rr.value[40:]))))}
		}
		patch := metadata.Touch(c, time.Unix(0, int64(stamp)), reference)
		for _, field := range []struct {
			v      filesystem.Observation[time.Time]
			offset int
		}{{patch.ModifyTime, 24}, {patch.AccessTime, 40}} {
			if field.v.State != filesystem.Present {
				continue
			}
			ns, err := buildTime(field.v.Value)
			if err != nil {
				return err
			}
			le.PutUint64(value[field.offset:], ns)
			if field.offset == 24 && ns < le.Uint64(value[16:]) {
				le.PutUint64(value[16:], ns)
			}
		}

	case "xattr":
		if err = m.changeAttribute(c, e.id, value); err != nil {
			return err
		}
		if c.Attribute == filesystem.ResourceFork {
			le.PutUint64(value[24:], stamp)
		}
	}
	le.PutUint64(value[32:], stamp)
	return m.fs.put(r.key, value)
}

// setAttribute owns both inline storage and an independently allocated stream.
// Legacy attributes use inode ownership; native 0x10 streams use their own IDs.
func (m *mutation) setAttribute(id uint64, name string, data block.Source) error {
	key := buildXattr(id, name, nil, 2).key
	extra := uint16(0)
	if old, ok := m.fs.get(key); ok {
		extra = le.Uint16(old.value) &^ uint16(3)
		if err := m.removeAttributeStream(old); err != nil {
			return err
		}
	}
	if data.Size() <= 3500 {
		b := make([]byte, data.Size())
		if err := readAttribute(data, b); err != nil {
			return err
		}
		return m.fs.put(key, buildXattr(id, name, b, 2|extra&^uint16(0x10)).value)
	}
	stream, err := m.nextFileID()
	if err != nil {
		return err
	}
	blocks, err := m.replaceStream(stream, attributeExtentOwner(id, stream, 1|extra), data)
	if err != nil {
		return err
	}
	sv := make([]byte, 48)
	le.PutUint64(sv, stream)
	le.PutUint64(sv[8:], uint64(data.Size()))
	le.PutUint64(sv[16:], blocks*4096)
	le.PutUint64(sv[32:], uint64(data.Size()))
	return m.fs.put(key, buildXattr(id, name, sv, 1|extra).value)
}

func (m *mutation) changeAttribute(c Change, id uint64, value []byte) error {
	key := buildXattr(id, c.Attribute, nil, 2).key
	old, exists := m.fs.get(key)
	if exists && le.Uint16(old.value)&4 != 0 {
		return filesystem.ErrUnsupported
	}
	if (c.DeleteAttribute || c.AttributeMode == "replace") && !exists {
		return fs.ErrNotExist
	}
	if c.AttributeMode == "create" && exists {
		return fs.ErrExist
	}
	if c.Attribute == filesystem.ResourceFork {
		if le.Uint16(value[80:])&0170000 != 0100000 || le.Uint32(value[68:])&0x20 != 0 {
			return filesystem.ErrUnsupported
		}
	}
	remove := c.DeleteAttribute || c.Attribute == filesystem.ResourceFork && c.Data.Size() == 0
	if remove {
		if exists {
			if err := m.removeAttributeStream(old); err != nil {
				return err
			}
			if err := m.fs.put(key, nil); err != nil {
				return err
			}
		}
	} else {
		if c.Data.Size() > math.MaxInt32 {
			return filesystem.ErrLimit
		}
		if c.Attribute == filesystem.FinderInfo && c.Data.Size() != 32 {
			return fs.ErrInvalid
		}
		if err := m.setAttribute(id, c.Attribute, c.Data); err != nil {
			return err
		}
	}
	flags := le.Uint64(value[48:])
	switch c.Attribute {
	case filesystem.FinderInfo:
		if remove {
			flags &^= 0x100
		} else {
			flags |= 0x100
			var data [32]byte
			if err := block.ReadFull(c.Data, data[:], 0); err != nil {
				return err
			}
			bsd := le.Uint32(value[68:]) &^ uint32(0x8000)
			if data[8]&0x40 != 0 {
				bsd |= 0x8000
			}
			le.PutUint32(value[68:], bsd)
		}
	case filesystem.ResourceFork:
		if remove {
			flags = flags&^0x4000 | 0x8000
		} else {
			flags = flags&^0x8000 | 0x4000
		}
	}
	le.PutUint64(value[48:], flags)
	return nil
}

func readAttribute(source block.Source, b []byte) error {
	if len(b) == 0 {
		return nil
	}
	return block.ReadFull(source, b, 0)
}
