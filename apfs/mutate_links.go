package apfs

import (
	"bytes"
	"errors"
	"io/fs"
	"math"
	"path"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	linkcommand "github.com/deploymenttheory/go-apfs-v3/internal/link"
	"github.com/deploymenttheory/go-apfs-v3/internal/names"
)

func (m *mutation) linkEntry(c Change, stamp uint64) (uint64, error) {
	if err := linkcommand.Validate(c); err != nil {
		return 0, err
	}
	var source *mutationEntry
	if !c.Symbolic {
		var err error
		source, err = m.lookupEntry(c.Path)
		if err != nil {
			return 0, err
		}
		if err = m.protectEntry(source, true); err != nil {
			return 0, err
		}
		inode, _ := m.inodeRecord(source.id)
		if le.Uint16(inode.value[80:])&0170000 != 0100000 {
			return 0, filesystem.ErrUnsupported
		}
	}
	var parent uint64
	var name string
	target, err := m.lookupEntry(c.Destination)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	if target != nil && m.directory(target.id) {
		parent, name = target.id, path.Base(c.Path)
	} else {
		if strings.HasSuffix(c.Destination, "/") {
			return 0, fs.ErrInvalid
		}
		parent, name, err = m.destination(c.Destination)
		if err != nil {
			return 0, err
		}
	}
	existing := m.entries[parent][m.nameKey(name)]
	if _, err = names.Stored(name, "APFS"); err != nil {
		return 0, err
	}
	if err = m.writableParent(parent); err != nil {
		return 0, err
	}
	if existing != nil {
		if !c.Force || source != nil && existing == source {
			return 0, fs.ErrExist
		}
		if m.directory(existing.id) {
			return 0, fs.ErrInvalid
		}
		inode, _ := m.inodeRecord(existing.id)
		if le.Uint16(inode.value[80:])&0170000 == 0120000 && !c.NoFollow {
			return 0, filesystem.ErrUnsupported
		}
		if err = m.removeEntry(existing, false, stamp); err != nil {
			return 0, err
		}
	}
	if source != nil && len(m.links[source.id]) >= math.MaxInt32 {
		return 0, filesystem.ErrLimit
	}
	if c.Symbolic {
		entry, err := m.createEntryKind(parent, name, 0120000, "", stamp)
		if err != nil {
			return 0, err
		}
		attr := buildXattr(entry.id, "com.apple.fs.symlink", append([]byte(c.Path), 0), 6)
		if err = m.fs.put(attr.key, attr.value); err != nil {
			return 0, err
		}
		return entry.id, nil
	}
	// A first hard link gives both the old and new directory entries sibling IDs.
	// Existing entries retain their date, flags and original inode/stream storage.
	if source.sibling == 0 {
		sibling, err := m.nextFileID()
		if err != nil {
			return 0, err
		}
		source.sibling = sibling
		source.record.value = append(bytes.Clone(source.record.value[:18]), buildXFields([]byte{1}, []byte{2}, [][]byte{buildUint64(sibling)})...)
		if err = m.fs.put(source.record.key, source.record.value); err != nil {
			return 0, err
		}
		if err = m.putSibling(source); err != nil {
			return 0, err
		}
	}
	sibling, err := m.nextFileID()
	if err != nil {
		return 0, err
	}
	a := buildAlias{id: sibling, parent: parent, name: name}
	record := buildDirectoryRecord(a, source.id, 8, stamp, m.v.CaseSensitive)
	entry := &mutationEntry{parent: parent, id: source.id, sibling: sibling, name: name, record: record}
	if err = m.fs.put(record.key, record.value); err != nil {
		return 0, err
	}
	if err = m.putSibling(entry); err != nil {
		return 0, err
	}
	m.indexEntry(entry)
	if err = m.parentChanged(parent, 1, stamp); err != nil {
		return 0, err
	}
	return source.id, m.repairPrimary(source.id, stamp)
}

func (m *mutation) putSibling(entry *mutationEntry) error {
	r := buildSibling(entry.id, buildAlias{id: entry.sibling, parent: entry.parent, name: entry.name})
	if err := m.fs.put(r.key, r.value); err != nil {
		return err
	}
	return m.fs.put(buildKey(entry.sibling, 12, 0), buildUint64(entry.id))
}
