package apfs

import (
	"bytes"
	"io/fs"
	"slices"
	"sort"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/copyfile"
)

func (m *mutation) copyMetadata(c Change, stamp uint64) (uint64, error) {
	if err := copyfile.ValidateMetadata(c); err != nil {
		return 0, err
	}
	e, err := m.lookupEntry(c.Path)
	if err != nil {
		return 0, err
	}
	if err = m.protectMetadataEntry(e, true, false); err != nil {
		return 0, err
	}
	r, err := m.inodeRecord(e.id)
	if err != nil {
		return 0, err
	}
	value := bytes.Clone(r.value)
	kind := le.Uint16(value[80:]) & 0170000
	if uint32(kind) != c.Metadata.Mode.Value&0170000 || kind != 0100000 && kind != 0040000 && kind != 0120000 {
		return 0, fs.ErrInvalid
	}
	if kind == 0120000 && !c.NoFollow {
		return 0, filesystem.ErrUnsupported
	}
	if le.Uint64(value[48:])&0x40 != 0 {
		if _, err := m.security(e.id); err != nil {
			return 0, err
		}
	}
	names := make([]string, 0, len(c.Attributes)+len(c.RemoveAttributes))
	for name := range c.Attributes {
		names = append(names, name)
	}
	names = append(names, c.RemoveAttributes...)
	sort.Strings(names)
	for _, name := range names {
		change := Change{Operation: "copy-metadata", Attribute: name, Data: c.Attributes[name], DeleteAttribute: slices.Contains(c.RemoveAttributes, name)}
		if err = m.changeAttribute(change, e.id, value); err != nil {
			return 0, err
		}
	}
	le.PutUint16(value[80:], uint16(c.Metadata.Mode.Value))
	le.PutUint32(value[72:], c.Metadata.UID.Value)
	le.PutUint32(value[76:], c.Metadata.GID.Value)
	flags := le.Uint32(value[68:])
	le.PutUint32(value[68:], flags&^uint32(0x800f)|c.Metadata.BSDFlags.Value)
	for _, field := range []struct {
		offset int
		value  filesystem.Observation[time.Time]
	}{{16, c.Metadata.BirthTime}, {24, c.Metadata.ModifyTime}, {40, c.Metadata.AccessTime}} {
		ns, err := buildTime(field.value.Value)
		if err != nil {
			return 0, err
		}
		le.PutUint64(value[field.offset:], ns)
	}
	le.PutUint64(value[32:], stamp)
	return e.id, m.fs.put(r.key, value)
}
