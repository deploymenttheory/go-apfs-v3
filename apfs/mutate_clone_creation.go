package apfs

import (
	"bytes"
	"io/fs"
	"math"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/filesec"
)

// cloneFile is clonefile's absent-destination primitive. Ordinary cp -c policy
// (including replacement and fallback) lives in the shared copy implementation.
func (m *mutation) cloneFile(c Change, stamp uint64) (uint64, error) {
	if c.Path == "" || c.Destination == "" || c.Name != "" || c.Parents || c.Recursive || c.Force || c.NoClobber || c.Data != nil || c.ResourceFork || c.Symbolic || c.Mode != "" || c.Metadata != nil || c.Attributes != nil || len(c.RemoveAttributes) != 0 || c.Flags != "" || c.Attribute != "" || c.AttributeMode != "" || c.DeleteAttribute || c.NoCreate || c.NoFollow || c.Reference != "" || c.Access || c.Modify {
		return 0, fs.ErrInvalid
	}
	source, err := m.lookupEntry(c.Path)
	if err != nil {
		return 0, err
	}
	if err := m.protectEntry(source, true); err != nil {
		return 0, err
	}
	sr, err := m.inodeRecord(source.id)
	if err != nil {
		return 0, err
	}
	if le.Uint16(sr.value[80:])&0170000 != 0100000 {
		return 0, fs.ErrInvalid
	}
	parent, name, err := m.destination(c.Destination)
	if err != nil {
		return 0, err
	}
	if m.entries[parent][m.nameKey(name)] != nil {
		return 0, fs.ErrExist
	}
	stream, err := inodeDataStreamID(sr.value)
	if err != nil {
		return 0, err
	}
	if stream != 0 {
		refs, err := m.streamReferenceCount(stream)
		if err != nil {
			return 0, err
		}
		if refs == math.MaxUint32 {
			return 0, filesystem.ErrLimit
		}
	}
	entry, err := m.createEntryKind(parent, name, 0100000, "", stamp)
	if err != nil {
		return 0, err
	}
	fresh, err := m.inodeRecord(entry.id)
	if err != nil {
		return 0, err
	}
	value := bytes.Clone(sr.value)
	le.PutUint64(value, parent)
	if stream == 0 {
		le.PutUint64(value[8:], entry.id)
	}
	le.PutUint64(value[32:], stamp)
	le.PutUint32(value[56:], 1)
	le.PutUint16(value[80:], le.Uint16(value[80:])&^06000)
	if c.ActorUID.State != filesystem.Present || c.ActorUID.Value != 0 {
		copy(value[72:80], fresh.value[72:80])
	}
	flags := le.Uint64(value[48:])&^uint64(2|4|0x40) | 0x10 | 0x400
	if _, ok := m.fs.get(buildXattr(entry.id, filesec.Attribute, nil, 2).key); ok {
		flags |= 0x40
	}
	le.PutUint64(value[48:], flags)
	value, err = replaceInodeField(value, 4, 2, append([]byte(name), 0))
	if err != nil {
		return 0, err
	}
	value, err = removeInodeField(value, 10)
	if err != nil {
		return 0, err
	}
	if stream != 0 {
		refs, err := m.streamReferenceCount(stream)
		if err != nil {
			return 0, err
		}
		count := make([]byte, 4)
		le.PutUint32(count, refs+1)
		if err := m.fs.put(buildKey(stream, 6, 0), count); err != nil {
			return 0, err
		}
	}
	for _, attribute := range m.fs.records(source.id, 4) {
		name := string(attribute.key[10 : len(attribute.key)-1])
		if name == filesec.Attribute {
			continue
		}
		cloned := bytes.Clone(attribute.value)
		if le.Uint16(cloned)&1 != 0 {
			if len(cloned) != 52 {
				return 0, corrupt("cloned attribute stream", 0)
			}
			old := le.Uint64(cloned[4:])
			id, err := m.nextFileID()
			if err != nil {
				return 0, err
			}
			le.PutUint64(cloned[4:], id)
			le.PutUint16(cloned, le.Uint16(cloned)|0x10)
			for _, extent := range m.fs.records(old, 8) {
				address := le.Uint64(extent.value[8:])
				blocks := (le.Uint64(extent.value) & ((1 << 56) - 1)) / 4096
				if address != 0 {
					if err := m.retainExtent(address, blocks); err != nil {
						return 0, err
					}
				}
				key := bytes.Clone(extent.key)
				le.PutUint64(key, id|uint64(8)<<60)
				if err := m.fs.put(key, extent.value); err != nil {
					return 0, err
				}
			}
		}
		if err := m.fs.put(buildXattr(entry.id, name, nil, 2).key, cloned); err != nil {
			return 0, err
		}
	}
	if err := m.fs.put(fresh.key, value); err != nil {
		return 0, err
	}
	statistics, err := statisticsForInode(fresh.value)
	if err != nil {
		return 0, err
	}
	if err := m.setStatisticsReference(entry.id, statistics.key, false); err != nil {
		return 0, err
	}
	sourceValue := bytes.Clone(sr.value)
	le.PutUint64(sourceValue[48:], le.Uint64(sourceValue[48:])|0x400)
	if err := m.fs.put(sr.key, sourceValue); err != nil {
		return 0, err
	}
	return entry.id, nil
}
