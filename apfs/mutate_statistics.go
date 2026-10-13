package apfs

import (
	"bytes"
	"fmt"
	"math"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// The current native profile uses an eight-byte INO_EXT_TYPE_DIR_STATS_KEY on
// every tracked inode. An origin owns a separate type-10 record; inherited
// objects share its key. Nested origins chain their totals into a parent group.
// These layouts and primary-inode accounting come from the retained original
// macOS 15/26/27 controls, rather than inferred private APFS kernel symbols.
type inodeStatistics struct {
	key, allocated uint64
	origin         bool
}

func statisticsForInode(value []byte) (result inodeStatistics, err error) {
	flags := le.Uint64(value[48:])
	result.origin = flags&4 != 0
	var found bool
	err = extendedFields(value[92:], func(kind byte, data []byte) error {
		switch kind {
		case 10:
			if found || len(data) != 8 || le.Uint64(data) == 0 || le.Uint64(data) > objectMask {
				return corrupt("directory statistics reference", 0)
			}
			found, result.key = true, le.Uint64(data)
		case 8:
			if len(data) != 40 {
				return corrupt("directory statistics data stream", 0)
			}
			result.allocated = le.Uint64(data[8:])
		}
		return nil
	})
	if err == nil && (found != (flags&2 != 0) || result.origin && (flags&2 == 0 || le.Uint16(value[80:])&0170000 != 0040000)) {
		err = corrupt("directory statistics inode flags", 0)
	}
	return result, err
}

func (m *mutation) statisticsKey(id uint64) (uint64, error) {
	r, err := m.inodeRecord(id)
	if err != nil {
		return 0, err
	}
	info, err := statisticsForInode(r.value)
	return info.key, err
}

func (m *mutation) setStatisticsReference(id, key uint64, origin bool) error {
	r, err := m.inodeRecord(id)
	if err != nil {
		return err
	}
	value := bytes.Clone(r.value)
	flags := le.Uint64(value[48:]) &^ uint64(2|4)
	if key == 0 {
		value, err = removeInodeField(value, 10)
	} else {
		flags |= 2
		if origin {
			flags |= 4
		}
		value, err = replaceInodeField(value, 10, 0x22, buildUint64(key))
	}
	if err != nil {
		return err
	}
	le.PutUint64(value[48:], flags)
	return m.fs.put(r.key, value)
}

func (m *mutation) bumpStatistics(key, delta uint64) error {
	seen := map[uint64]bool{}
	for key != 0 {
		if len(seen) >= 256 || seen[key] {
			return corrupt("directory statistics chain cycle", 0)
		}
		seen[key] = true
		r, ok := m.fs.get(buildKey(key, 10, 0))
		if !ok || len(r.value) != 32 {
			return corrupt("directory statistics chain record", 0)
		}
		generation := le.Uint64(r.value[24:])
		if delta > math.MaxUint64-generation {
			return fmt.Errorf("directory statistics generation overflow: %w", filesystem.ErrLimit)
		}
		value := bytes.Clone(r.value)
		le.PutUint64(value[24:], generation+delta)
		if err := m.fs.put(r.key, value); err != nil {
			return err
		}
		key = le.Uint64(value[16:])
	}
	return nil
}

func (m *mutation) bumpInodeStatistics(id, delta uint64) error {
	key, err := m.statisticsKey(id)
	if err != nil {
		return err
	}
	return m.bumpStatistics(key, delta)
}

// Moving an inherited directory across groups makes it an origin. Its group
// identity then survives further moves, while its chain follows its parent.
// Existing child origins keep their own IDs; ordinary descendants are rebound.
func (m *mutation) moveStatistics(entry *mutationEntry, parent uint64) error {
	r, err := m.inodeRecord(entry.id)
	if err != nil {
		return err
	}
	info, err := statisticsForInode(r.value)
	if err != nil {
		return err
	}
	key, err := m.statisticsKey(parent)
	if err != nil {
		return err
	}
	if !m.directory(entry.id) {
		// A move of a secondary alias leaves the primary inode's group intact.
		primary := m.primaryEntry(entry.id)
		key, err = m.statisticsKey(primary.parent)
		if err != nil {
			return err
		}
		return m.setStatisticsReference(entry.id, key, false)
	}
	if !info.origin && info.key == key {
		return nil
	}
	if !info.origin {
		info.key, err = m.nextFileID()
		if err != nil {
			return err
		}
		value := make([]byte, 32)
		le.PutUint64(value[16:], key)
		le.PutUint64(value[24:], 1)
		if err = m.fs.put(buildKey(info.key, 10, 0), value); err != nil {
			return err
		}
		if err = m.setStatisticsReference(entry.id, info.key, true); err != nil {
			return err
		}
	}
	return m.rebindStatistics(entry.id, info.key, key, 0)
}

func (m *mutation) rebindStatistics(id, key, parentKey uint64, depth int) error {
	if depth >= 256 {
		return filesystem.ErrLimit
	}
	r, err := m.inodeRecord(id)
	if err != nil {
		return err
	}
	info, err := statisticsForInode(r.value)
	if err != nil {
		return err
	}
	if info.origin {
		key = info.key
		r, ok := m.fs.get(buildKey(key, 10, 0))
		if !ok {
			return corrupt("directory statistics origin record", 0)
		}
		value := bytes.Clone(r.value)
		le.PutUint64(value[16:], parentKey)
		if err = m.fs.put(r.key, value); err != nil {
			return err
		}
	} else if err = m.setStatisticsReference(id, key, false); err != nil {
		return err
	}
	if !m.directory(id) {
		return nil
	}
	for _, entry := range m.children(id) {
		if entry != m.primaryEntry(entry.id) {
			continue
		}
		if err = m.rebindStatistics(entry.id, key, key, depth+1); err != nil {
			return err
		}
	}
	return nil
}

// Complete primary-inode accounting validates the original native totals and
// recomputes final totals after namespace/data edits. Aliases contribute once;
// resource forks and attributes never contribute to data-fork allocated bytes.
func (m *mutation) updateStatistics(validate bool) error {
	type total struct{ children, bytes uint64 }
	groups, owners := map[uint64]buildRecord{}, map[uint64]uint64{}
	counts := map[uint64]total{}
	for _, r := range m.fs.all() {
		p := prefix(r.key)
		if p.kind == 10 {
			if len(r.key) != 8 || len(r.value) != 32 || p.id == 0 {
				return corrupt("directory statistics record bounds", 0)
			}
			groups[p.id] = r
		}
	}
	add := func(key uint64, value total) error {
		old := counts[key]
		if value.children > math.MaxUint64-old.children || value.bytes > math.MaxUint64-old.bytes {
			return corrupt("directory statistics totals overflow", 0)
		}
		counts[key] = total{old.children + value.children, old.bytes + value.bytes}
		return nil
	}
	for _, r := range m.fs.all() {
		p := prefix(r.key)
		if p.kind != 3 {
			continue
		}
		info, err := statisticsForInode(r.value)
		if err != nil {
			return err
		}
		if info.key == 0 {
			continue
		}
		if _, ok := groups[info.key]; !ok {
			return corrupt("missing directory statistics group", 0)
		}
		parentKey, err := m.statisticsKey(le.Uint64(r.value))
		if err != nil {
			return err
		}
		if info.origin {
			if owners[info.key] != 0 || le.Uint64(groups[info.key].value[16:]) != parentKey {
				return corrupt("directory statistics origin/chain disagreement", 0)
			}
			owners[info.key] = p.id
			if parentKey != 0 {
				if err = add(parentKey, total{children: 1}); err != nil {
					return err
				}
			}
		} else {
			if parentKey != info.key {
				return corrupt("inherited directory statistics group disagreement", 0)
			}
			if err = add(info.key, total{1, info.allocated}); err != nil {
				return err
			}
		}
	}
	children := map[uint64][]uint64{}
	for key, record := range groups {
		parent := le.Uint64(record.value[16:])
		if parent != 0 {
			if _, ok := groups[parent]; !ok {
				return corrupt("missing parent directory statistics group", 0)
			}
			children[parent] = append(children[parent], key)
		}
	}
	seen, active := map[uint64]bool{}, map[uint64]bool{}
	var visit func(uint64, int) (total, error)
	visit = func(key uint64, depth int) (total, error) {
		if depth >= 256 || active[key] || owners[key] == 0 {
			return total{}, corrupt("directory statistics orphan/cycle", 0)
		}
		if seen[key] {
			return counts[key], nil
		}
		active[key] = true
		for _, child := range children[key] {
			value, err := visit(child, depth+1)
			if err != nil {
				return total{}, err
			}
			if err = add(key, value); err != nil {
				return total{}, err
			}
		}
		active[key], seen[key] = false, true
		return counts[key], nil
	}
	for key, record := range groups {
		value, err := visit(key, 0)
		if err != nil {
			return err
		}
		if validate {
			if le.Uint64(record.value) != value.children || le.Uint64(record.value[8:]) != value.bytes {
				return corrupt("directory statistics totals disagreement", 0)
			}
		} else {
			data := bytes.Clone(record.value)
			le.PutUint64(data, value.children)
			le.PutUint64(data[8:], value.bytes)
			if !bytes.Equal(data, record.value) {
				if err = m.fs.put(record.key, data); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
