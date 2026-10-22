package apfs

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/filesec"
	"github.com/deploymenttheory/go-apfs-v3/internal/mode"
	"github.com/deploymenttheory/go-apfs-v3/internal/names"
)

// mutationEntry addresses one named link, not its shared inode. The index is
// derived from the admitted tree and changed with it, so ordered operations see
// earlier creations and renames without consulting the previous checkpoint.
type mutationEntry struct {
	parent, id, sibling uint64
	name                string
	record              buildRecord
}

func (m *mutation) nameKey(name string) string { return names.APFS(name, m.v.CaseSensitive, true) }
func (m *mutation) inodeRecord(id uint64) (buildRecord, error) {
	r, ok := m.fs.get(buildKey(id, 3, 0))
	if !ok || len(r.value) < 92 {
		return r, corrupt("directory inode", 0)
	}
	return r, nil
}
func (m *mutation) directory(id uint64) bool {
	r, e := m.inodeRecord(id)
	return e == nil && le.Uint16(r.value[80:])&0170000 == 0040000
}
func (m *mutation) indexEntry(e *mutationEntry) {
	if m.entries[e.parent] == nil {
		m.entries[e.parent] = map[string]*mutationEntry{}
	}
	m.entries[e.parent][m.nameKey(e.name)] = e
	if m.links[e.id] == nil {
		m.links[e.id] = map[*mutationEntry]bool{}
	}
	m.links[e.id][e] = true
}
func (m *mutation) unindexEntry(e *mutationEntry) {
	delete(m.entries[e.parent], m.nameKey(e.name))
	delete(m.links[e.id], e)
}
func (m *mutation) loadEntries() error {
	m.entries = map[uint64]map[string]*mutationEntry{}
	m.links = map[uint64]map[*mutationEntry]bool{}
	records := m.fs.all()
	if len(records) > 1<<20 {
		return filesystem.ErrLimit
	}
	inodes := map[uint64]bool{}
	siblings := map[uint64]buildRecord{}
	maps := map[uint64]uint64{}
	var largest uint64
	for _, r := range records {
		p := prefix(r.key)
		largest = max(largest, p.id)
		switch p.kind {
		case 3:
			inodes[p.id] = true
		case 4:
			if _, ok := m.fs.get(buildKey(p.id, 3, 0)); !ok {
				return corrupt("orphan inode attribute", 0)
			}
		case 5:
			if len(r.key) != 16 || len(r.value) < 11 || int(le.Uint16(r.value[8:])) != len(r.value)-10 || r.value[len(r.value)-1] != 0 {
				return corrupt("sibling record bounds", 0)
			}
			id := le.Uint64(r.key[8:])
			if id < 16 || siblings[id].key != nil {
				return corrupt("duplicate sibling identifier", 0)
			}
			largest = max(largest, id)
			siblings[id] = r
		case 12:
			if len(r.key) != 8 || len(r.value) != 8 {
				return corrupt("sibling map bounds", 0)
			}
			maps[p.id] = le.Uint64(r.value)
		case 9:
			if len(r.key) < 13 || int(le.Uint32(r.key[8:])&1023) != len(r.key)-12 || r.key[len(r.key)-1] != 0 || len(r.value) < 18 {
				return corrupt("directory entry bounds", 0)
			}
			name := string(r.key[12 : len(r.key)-1])
			if name == "" || !utf8.ValidString(name) || strings.ContainsAny(name, "/\x00") {
				return corrupt("directory entry name", 0)
			}
			e := &mutationEntry{parent: p.id, id: le.Uint64(r.value), name: name, record: r}
			if err := extendedFields(r.value[18:], func(k byte, b []byte) error {
				if k != 1 {
					return filesystem.ErrUnsupported
				}
				if len(b) != 8 {
					return corrupt("directory sibling field", 0)
				}
				e.sibling = le.Uint64(b)
				return nil
			}); err != nil {
				return err
			}
			expected := buildDirectoryRecord(buildAlias{parent: p.id, name: name}, e.id, 0, 0, m.v.CaseSensitive)
			if !bytes.Equal(expected.key, r.key) || m.entries[p.id][m.nameKey(name)] != nil {
				return corrupt("directory hash or duplicate name", 0)
			}
			m.indexEntry(e)
		}
	}
	for id := range inodes {
		r, _ := m.inodeRecord(id)
		var name string
		if err := extendedFields(r.value[92:], func(k byte, b []byte) error {
			if k == 4 {
				if len(b) == 0 || b[len(b)-1] != 0 {
					return corrupt("inode name", 0)
				}
				name = string(b[:len(b)-1])
			}
			return nil
		}); err != nil {
			return err
		}
		links := m.links[id]
		if len(links) == 0 {
			return corrupt("unlinked inode", 0)
		}
		var primary *mutationEntry
		for e := range links {
			if e.parent != 1 && !m.directory(e.parent) {
				return corrupt("entry parent is not a directory", 0)
			}
			if le.Uint16(e.record.value[16:])&15 != le.Uint16(r.value[80:])>>12 {
				return corrupt("entry/inode type mismatch", 0)
			}
			if e.parent == 1 && id != 2 && id != 3 {
				return corrupt("reserved parent entry", 0)
			}
			if e.sibling != 0 {
				s, ok := siblings[e.sibling]
				if !ok || prefix(s.key).id != id || le.Uint64(s.value) != e.parent || string(s.value[10:len(s.value)-1]) != e.name || maps[e.sibling] != id {
					return corrupt("sibling link/map/entry mismatch", 0)
				}
				delete(siblings, e.sibling)
				delete(maps, e.sibling)
			} else if len(links) > 1 {
				return corrupt("hard link without sibling", 0)
			}
			if primary == nil || e.sibling < primary.sibling {
				primary = e
			}
		}
		if le.Uint64(r.value) != primary.parent || name != primary.name {
			return corrupt("inode primary link mismatch", 0)
		}
		if m.directory(id) {
			if len(links) != 1 || uint64(len(m.entries[id])) != uint64(le.Uint32(r.value[56:])) {
				return corrupt("directory child count", 0)
			}
			cursor := id
			for depth := 0; cursor != 2 && cursor != 3; depth++ {
				if depth >= 256 {
					return corrupt("directory cycle or depth", 0)
				}
				if !m.directory(cursor) {
					return corrupt("directory ancestor", 0)
				}
				parent, _ := m.inodeRecord(cursor)
				cursor = le.Uint64(parent.value)
			}
		}
	}
	for id := range m.links {
		if !inodes[id] {
			return corrupt("entry without inode", 0)
		}
	}
	if len(siblings) != 0 || len(maps) != 0 {
		return corrupt("orphan sibling records", 0)
	}
	if le.Uint64(m.super[176:]) <= largest || le.Uint64(m.super[176:]) > objectMask {
		return corrupt("file identifier high-water mark", 0)
	}
	return m.ctx.Err()
}
func entryPath(path string) ([]string, error) {
	if path == "" || len(path) > 4096 || !strings.HasPrefix(path, "/") {
		return nil, fs.ErrInvalid
	}
	var parts []string
	for _, part := range strings.Split(path, "/") {
		if part == "" {
			continue
		}
		if _, e := names.Stored(part, "APFS"); e != nil {
			return nil, e
		}
		parts = append(parts, part)
	}
	if len(parts) > 256 {
		return nil, filesystem.ErrLimit
	}
	return parts, nil
}
func (m *mutation) lookupParts(parts []string) (*mutationEntry, error) {
	e := m.primaryEntry(2)
	for _, name := range parts {
		if e == nil || !m.directory(e.id) {
			return nil, fs.ErrInvalid
		}
		e = m.entries[e.id][m.nameKey(name)]
		if e == nil {
			return nil, fs.ErrNotExist
		}
	}
	return e, nil
}
func (m *mutation) lookupEntry(path string) (*mutationEntry, error) {
	p, e := entryPath(path)
	if e != nil {
		return nil, e
	}
	return m.lookupParts(p)
}
func (m *mutation) primaryEntry(id uint64) *mutationEntry {
	var first *mutationEntry
	for e := range m.links[id] {
		if first == nil || e.sibling < first.sibling {
			first = e
		}
	}
	return first
}
func (m *mutation) destination(path string) (uint64, string, error) {
	p, e := entryPath(path)
	if e != nil {
		return 0, "", e
	}
	if len(p) == 0 {
		return 0, "", fs.ErrInvalid
	}
	parent, e := m.lookupParts(p[:len(p)-1])
	if e != nil {
		return 0, "", e
	}
	if !m.directory(parent.id) {
		return 0, "", fs.ErrInvalid
	}
	return parent.id, p[len(p)-1], nil
}
func (m *mutation) protectEntry(e *mutationEntry, root bool) error {
	return m.protectMetadataEntry(e, root, false)
}
func (m *mutation) protectMetadataEntry(e *mutationEntry, root, flags bool) error {
	if e == nil {
		return fs.ErrNotExist
	}
	if e.id < 16 && (root || e.id != 2) {
		return filesystem.ErrUnsupported
	}
	r, err := m.inodeRecord(e.id)
	if err != nil {
		return err
	}
	mask := uint32(0x60006)
	if flags {
		mask &^= 6
	}
	if le.Uint32(r.value[68:])&mask != 0 || le.Uint64(r.value[48:])&(1|0x80|0x200000|0x400000) != 0 {
		return fmt.Errorf("protected APFS inode: %w", filesystem.ErrUnsupported)
	}
	for cursor, depth := e, 0; cursor.id != 2; depth++ {
		if depth >= 256 {
			return filesystem.ErrLimit
		}
		if cursor.id < 16 {
			return fmt.Errorf("filesystem-owned ancestor: %w", filesystem.ErrUnsupported)
		}
		if cursor.parent == 2 && (cursor.name == ".fseventsd" || cursor.name == ".Spotlight-V100" || cursor.name == ".Trashes" || cursor.name == ".DocumentRevisions-V100" || cursor.name == ".TemporaryItems") {
			return fmt.Errorf("filesystem-owned directory: %w", filesystem.ErrUnsupported)
		}
		cursor = m.primaryEntry(cursor.parent)
		if cursor == nil {
			return corrupt("missing parent", 0)
		}
	}
	return nil
}
func (m *mutation) writableParent(id uint64) error {
	if !m.directory(id) {
		return fs.ErrInvalid
	}
	if e := m.protectEntry(m.primaryEntry(id), false); e != nil {
		return e
	}
	r, _ := m.inodeRecord(id)
	if le.Uint64(r.value[48:])&0x40 != 0 {
		_, err := m.security(id)
		return err
	}
	return nil
}
func (m *mutation) parentChanged(id uint64, delta int, stamp uint64) error {
	r, e := m.inodeRecord(id)
	if e != nil {
		return e
	}
	v := bytes.Clone(r.value)
	n := int64(le.Uint32(v[56:])) + int64(delta)
	if n < 0 || n > math.MaxInt32 {
		return filesystem.ErrLimit
	}
	le.PutUint32(v[56:], uint32(n))
	le.PutUint64(v[24:], stamp)
	le.PutUint64(v[32:], stamp)
	if err := m.fs.put(r.key, v); err != nil {
		return err
	}
	return m.bumpInodeStatistics(id, 1)
}
func (m *mutation) volumeCount(kind uint16, delta int) error {
	off := 208
	switch kind {
	case 0100000:
		off = 184
	case 0040000:
		off = 192
	case 0120000:
		off = 200
	}
	old := le.Uint64(m.super[off:])
	if delta < 0 && old == 0 || delta > 0 && old == math.MaxUint64 {
		return corrupt("volume file count overflow", 0)
	}
	if delta > 0 {
		old++
	} else {
		old--
	}
	le.PutUint64(m.super[off:], old)
	return nil
}
func (m *mutation) createEntry(parent uint64, name string, directory bool, permission string, stamp uint64) (*mutationEntry, error) {
	kind := uint32(0100000)
	if directory {
		kind = 0040000
	}
	return m.createEntryKind(parent, name, kind, permission, stamp)
}
func (m *mutation) createEntryKind(parent uint64, name string, kind uint32, permission string, stamp uint64) (*mutationEntry, error) {
	if e := m.writableParent(parent); e != nil {
		return nil, e
	}
	if _, e := names.Stored(name, "APFS"); e != nil {
		return nil, e
	}
	if m.entries[parent][m.nameKey(name)] != nil {
		return nil, fs.ErrExist
	}
	perm := kind | 0644
	switch kind {
	case 0040000:
		perm = 0040755
	case 0120000:
		perm = 0120755
	}
	if permission != "" {
		p, e := mode.Parse(permission, 022)
		if e != nil {
			return nil, e
		}
		perm = p.Apply(perm)
	}
	if perm&06000 != 0 && m.actor.State != filesystem.Present {
		return nil, fmt.Errorf("set-ID creation requires credential policy: %w", filesystem.ErrUnsupported)
	}
	id, e := m.nextFileID()
	if e != nil {
		return nil, e
	}
	p, _ := m.inodeRecord(parent)
	uid := le.Uint32(p.value[72:])
	if m.actor.State == filesystem.Present {
		uid = m.actor.Value
	}
	security, e := m.inheritSecurity(parent, kind == 0040000)
	if e != nil {
		return nil, e
	}
	clock := filesystem.Observed(time.Unix(0, int64(stamp)).UTC())
	raw := buildInode(&buildObject{id: id, aliases: []buildAlias{{parent: parent, name: name}}, node: filesystem.Node{Metadata: filesystem.Metadata{
		Mode: filesystem.Observed(perm), UID: filesystem.Observed(uid), GID: filesystem.Observed(le.Uint32(p.value[76:])),
		BirthTime: clock, ModifyTime: clock, ChangeTime: clock, AccessTime: clock,
	}}}, 0)
	statistics, e := statisticsForInode(p.value)
	if e != nil {
		return nil, e
	}
	if statistics.key != 0 {
		raw.value, e = replaceInodeField(raw.value, 10, 0x22, buildUint64(statistics.key))
		if e != nil {
			return nil, e
		}
		le.PutUint64(raw.value[48:], le.Uint64(raw.value[48:])|2)
	}
	if security != nil {
		if e = m.setAttribute(id, filesec.Attribute, bytes.NewReader(security)); e != nil {
			return nil, e
		}
		le.PutUint64(raw.value[48:], le.Uint64(raw.value[48:])|0x40)
	}
	if e = m.fs.put(raw.key, raw.value); e != nil {
		return nil, e
	}
	r := buildDirectoryRecord(buildAlias{parent: parent, name: name}, id, uint16(perm>>12), stamp, m.v.CaseSensitive)
	if e = m.fs.put(r.key, r.value); e != nil {
		return nil, e
	}
	entry := &mutationEntry{parent: parent, id: id, name: name, record: r}
	m.indexEntry(entry)
	if e = m.parentChanged(parent, 1, stamp); e != nil {
		return nil, e
	}
	if e = m.volumeCount(uint16(perm)&0170000, 1); e != nil {
		return nil, e
	}
	return entry, nil
}
func (m *mutation) makeDirectory(c Change, stamp uint64) (uint64, error) {
	p, e := entryPath(c.Path)
	if e != nil {
		return 0, e
	}
	if len(p) == 0 {
		if c.Parents {
			return 0, nil
		}
		return 0, fs.ErrExist
	}
	parent := uint64(2)
	var changed uint64
	for i, name := range p {
		next := m.entries[parent][m.nameKey(name)]
		if next != nil {
			if !m.directory(next.id) || i == len(p)-1 && !c.Parents {
				return 0, fs.ErrExist
			}
		} else {
			if i < len(p)-1 && !c.Parents {
				return 0, fs.ErrNotExist
			}
			permission := ""
			if i == len(p)-1 {
				permission = c.Mode
			}
			next, e = m.createEntry(parent, name, true, permission, stamp)
			if e != nil {
				return 0, e
			}
			changed = next.id
		}
		parent = next.id
	}
	return changed, nil
}

// Deterministic traversal affects deferred-free insertion and physical output.
func (m *mutation) children(id uint64) []*mutationEntry {
	a := make([]*mutationEntry, 0, len(m.entries[id]))
	for _, e := range m.entries[id] {
		a = append(a, e)
	}
	sort.Slice(a, func(i, j int) bool { return m.fs.less(a[i].record.key, a[j].record.key) })
	return a
}

func (m *mutation) applyChange(c Change, stamp uint64) (uint64, error) {
	if err := filesec.ValidateActor(c.ActorUID); err != nil {
		return 0, err
	}
	m.actor = c.ActorUID
	if c.Operation == "copy-metadata" {
		return m.copyMetadata(c, stamp)
	}
	if c.Attributes != nil || len(c.RemoveAttributes) != 0 {
		return 0, fs.ErrInvalid
	}
	if c.Operation == "ln" {
		return m.linkEntry(c, stamp)
	}
	if c.Symbolic {
		return 0, fs.ErrInvalid
	}
	op := c.Operation
	if op == "" {
		op = "cp"
		if c.Data == nil && c.Mode != "" {
			op = "chmod"
		}
	}
	if op == "chown" || op == "chflags" || op == "touch" || op == "xattr" || op == "chmod" {
		c.Operation = op
		return m.editMetadata(c, stamp)
	}
	if c.Metadata != nil || c.Flags != "" || c.Attribute != "" || c.AttributeMode != "" || c.DeleteAttribute || c.NoCreate || c.NoFollow || c.Reference != "" || c.Access || c.Modify {
		return 0, fs.ErrInvalid
	}
	if (op != "mv" && c.Destination != "") || (op != "mkdir" && c.Parents) || (op != "rm" && (c.Recursive || c.Force)) || ((op != "cp" && op != "mv") && c.NoClobber) || (op != "cp" && (c.Name != "" || c.ResourceFork || c.Data != nil)) || ((op == "rm" || op == "mv") && c.Mode != "") {
		return 0, fs.ErrInvalid
	}
	switch op {
	case "mkdir":
		return m.makeDirectory(c, stamp)
	case "mv":
		return m.moveEntry(c, stamp)
	case "rm":
		entry, e := m.lookupEntry(c.Path)
		if errors.Is(e, fs.ErrNotExist) && c.Force {
			return 0, nil
		}
		if e != nil {
			return 0, e
		}
		return entry.id, m.removeEntry(entry, c.Recursive, stamp)
	case "cp", "chmod":
		if op == "cp" && (c.Data == nil || c.Data.Size() < 0) || op == "chmod" && c.Mode == "" {
			return 0, fs.ErrInvalid
		}
		entry, e := m.lookupEntry(c.Path)
		if e == nil && op == "cp" && m.directory(entry.id) && c.Name != "" && !c.ResourceFork {
			if _, e = names.Stored(c.Name, "APFS"); e != nil {
				return 0, e
			}
			c.Path = strings.TrimRight(c.Path, "/") + "/" + c.Name
			entry, e = m.lookupEntry(c.Path)
		}
		if errors.Is(e, fs.ErrNotExist) && op == "cp" && !c.ResourceFork {
			parent, name, err := m.destination(c.Path)
			if err != nil {
				return 0, err
			}
			entry, e = m.createEntry(parent, name, false, c.Mode, stamp)
			c.Mode = ""
		} else if e == nil && op == "cp" && c.NoClobber {
			return 0, fs.ErrExist
		}
		if e != nil {
			return 0, e
		}
		if e = m.protectEntry(entry, true); e != nil {
			return 0, e
		}
		return m.modifyFile(c, entry.id, stamp)
	default:
		return 0, filesystem.ErrUnsupported
	}
}

func (m *mutation) repairPrimary(id, stamp uint64) error {
	primary := m.primaryEntry(id)
	if primary == nil {
		return corrupt("primary link lost", 0)
	}
	r, e := m.inodeRecord(id)
	if e != nil {
		return e
	}
	v := bytes.Clone(r.value)
	le.PutUint64(v, primary.parent)
	le.PutUint64(v[32:], stamp)
	if !m.directory(id) {
		le.PutUint32(v[56:], uint32(len(m.links[id])))
	}
	v, e = replaceInodeField(v, 4, 2, append([]byte(primary.name), 0))
	if e != nil {
		return e
	}
	return m.fs.put(r.key, v)
}
func (m *mutation) eraseEntry(e *mutationEntry, stamp uint64) error {
	if err := m.fs.put(e.record.key, nil); err != nil {
		return err
	}
	if e.sibling != 0 {
		r := buildSibling(e.id, buildAlias{id: e.sibling, parent: e.parent, name: e.name})
		if err := m.fs.put(r.key, nil); err != nil {
			return err
		}
		if err := m.fs.put(buildKey(e.sibling, 12, 0), nil); err != nil {
			return err
		}
	}
	m.unindexEntry(e)
	return m.parentChanged(e.parent, -1, stamp)
}
func (m *mutation) removeEntry(entry *mutationEntry, recursive bool, stamp uint64) error {
	if e := m.ctx.Err(); e != nil {
		return e
	}
	if e := m.protectEntry(entry, true); e != nil {
		return e
	}
	if e := m.writableParent(entry.parent); e != nil {
		return e
	}
	r, e := m.inodeRecord(entry.id)
	if e != nil {
		return e
	}
	kind := le.Uint16(r.value[80:]) & 0170000
	if kind != 0040000 && kind != 0100000 && kind != 0120000 {
		return filesystem.ErrUnsupported
	}
	if kind == 0040000 {
		if !recursive {
			return fmt.Errorf("directory removal requires recursion: %w", fs.ErrInvalid)
		}
		if e = m.writableParent(entry.id); e != nil {
			return e
		}
		for _, child := range m.children(entry.id) {
			if e = m.removeEntry(child, true, stamp); e != nil {
				return e
			}
		}
	}
	// Protection records require a separate qualified updater.
	for _, kind := range []uint8{7, 11} {
		if len(m.fs.records(entry.id, kind)) != 0 {
			return filesystem.ErrUnsupported
		}
	}
	statistics, e := statisticsForInode(r.value)
	if e != nil {
		return e
	}
	last := len(m.links[entry.id]) == 1
	if last {
		if e = m.bumpStatistics(statistics.key, 1); e != nil {
			return e
		}
	}
	if e = m.eraseEntry(entry, stamp); e != nil {
		return e
	}
	if len(m.links[entry.id]) != 0 {
		if e = m.repairPrimary(entry.id, stamp); e != nil {
			return e
		}
		key, err := m.statisticsKey(m.primaryEntry(entry.id).parent)
		if err != nil {
			return err
		}
		return m.setStatisticsReference(entry.id, key, false)
	}
	if statistics.origin {
		if e = m.fs.put(buildKey(statistics.key, 10, 0), nil); e != nil {
			return e
		}
	}
	// Only the last link retires streams. The old checkpoint retains its extents
	// until the existing space-manager deferred-free rules make them reusable.
	stream := le.Uint64(r.value[8:])
	if e = m.releaseStreamReference(stream); e != nil {
		return e
	}
	for _, record := range m.fs.records(entry.id, 4) {
		if e = m.removeAttributeStream(record); e != nil {
			return e
		}
		if e = m.fs.put(record.key, nil); e != nil {
			return e
		}
	}
	if e = m.fs.put(r.key, nil); e != nil {
		return e
	}
	delete(m.links, entry.id)
	delete(m.entries, entry.id)
	return m.volumeCount(kind, -1)
}
func (m *mutation) moveEntry(c Change, stamp uint64) (uint64, error) {
	entry, e := m.lookupEntry(c.Path)
	if e != nil {
		return 0, e
	}
	if e = m.protectEntry(entry, true); e != nil {
		return 0, e
	}
	parent, name, e := m.destination(c.Destination)
	if e != nil {
		return 0, e
	}
	existing := m.entries[parent][m.nameKey(name)]
	if existing != nil && m.directory(existing.id) && existing != entry {
		parent = existing.id
		name = entry.name
		existing = m.entries[parent][m.nameKey(name)]
	}
	if e = m.writableParent(parent); e != nil {
		return 0, e
	}
	if e = m.writableParent(entry.parent); e != nil {
		return 0, e
	}
	for cursor, depth := parent, 0; cursor != 2; depth++ {
		if depth >= 256 {
			return 0, filesystem.ErrLimit
		}
		if cursor == entry.id {
			return 0, fs.ErrInvalid
		}
		p, e := m.inodeRecord(cursor)
		if e != nil {
			return 0, e
		}
		cursor = le.Uint64(p.value)
	}
	if parent == entry.id {
		return 0, fs.ErrInvalid
	}
	key := buildDirectoryRecord(buildAlias{parent: parent, name: name}, entry.id, 0, stamp, m.v.CaseSensitive).key
	if bytes.Equal(key, entry.record.key) {
		return 0, nil
	}
	if existing != nil && existing != entry {
		if c.NoClobber {
			return 0, fs.ErrExist
		}
		if m.directory(existing.id) != m.directory(entry.id) {
			return 0, fs.ErrInvalid
		}
		if m.directory(existing.id) && len(m.entries[existing.id]) != 0 {
			return 0, fmt.Errorf("destination directory is not empty: %w", fs.ErrExist)
		}
		if existing.id == entry.id {
			return 0, nil
		}
		if e = m.removeEntry(existing, m.directory(existing.id), stamp); e != nil {
			return 0, e
		}
	}
	oldParent := entry.parent
	if e = m.fs.put(entry.record.key, nil); e != nil {
		return 0, e
	}
	m.unindexEntry(entry)
	entry.parent, entry.name, entry.record.key = parent, name, key
	entry.record.value = bytes.Clone(entry.record.value)
	le.PutUint64(entry.record.value[8:], stamp)
	if e = m.fs.put(key, entry.record.value); e != nil {
		return 0, e
	}
	m.indexEntry(entry)
	if entry.sibling != 0 {
		r := buildSibling(entry.id, buildAlias{id: entry.sibling, parent: parent, name: name})
		if e = m.fs.put(r.key, r.value); e != nil {
			return 0, e
		}
	}
	if oldParent != parent {
		if e = m.parentChanged(oldParent, -1, stamp); e != nil {
			return 0, e
		}
		if e = m.parentChanged(parent, 1, stamp); e != nil {
			return 0, e
		}
	} else {
		if e = m.parentChanged(parent, 0, stamp); e != nil {
			return 0, e
		}
	}
	if e = m.repairPrimary(entry.id, stamp); e != nil {
		return 0, e
	}
	return entry.id, m.moveStatistics(entry, parent)
}
