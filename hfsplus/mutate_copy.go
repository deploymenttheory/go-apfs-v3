package hfsplus

import (
	"bytes"
	"io/fs"
	"slices"
	"sort"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/copyfile"
)

func (m *mutation) copyMetadata(c Change, stamp uint32) (uint32, error) {
	if err := copyfile.ValidateMetadata(c); err != nil {
		return 0, err
	}
	entry, err := m.lookup(c.Path)
	if err != nil {
		return 0, err
	}
	if err = m.protectedMetadata(entry, true, false); err != nil {
		return 0, err
	}
	inode, err := m.logical(entry)
	if err != nil {
		return 0, err
	}
	value := bytes.Clone(inode.value)
	kind := be.Uint16(value[42:]) & 0170000
	if uint32(kind) != c.Metadata.Mode.Value&0170000 || kind != 0100000 && kind != 0040000 && kind != 0120000 {
		return 0, fs.ErrInvalid
	}
	if kind == 0120000 && !c.NoFollow {
		return 0, filesystem.ErrUnsupported
	}
	if be.Uint16(value[2:])&8 != 0 {
		if _, err := m.security(inode.id()); err != nil {
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
		if err = m.changeAttribute(change, inode.id(), value); err != nil {
			return 0, err
		}
	}
	be.PutUint16(value[42:], uint16(c.Metadata.Mode.Value))
	be.PutUint32(value[32:], c.Metadata.UID.Value)
	be.PutUint32(value[36:], c.Metadata.GID.Value)
	setCatalogBSDFlags(value, catalogBSDFlags(value)&^uint32(0x800f)|c.Metadata.BSDFlags.Value)
	for _, field := range []struct {
		offset int
		value  filesystem.Observation[time.Time]
	}{{12, c.Metadata.BirthTime}, {16, c.Metadata.ModifyTime}, {24, c.Metadata.AccessTime}} {
		date, err := buildDate(field.value.Value.UTC().Truncate(time.Second))
		if err != nil {
			return 0, err
		}
		be.PutUint32(value[field.offset:], date)
	}
	be.PutUint32(value[20:], stamp)
	return inode.id(), m.patchCatalog(inode.id(), value)
}
