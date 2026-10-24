package apfs

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func (m *mutation) retireMetadata(address uint64, volume bool) error {
	if address == 0 {
		return nil
	}
	if m.history != nil && m.history.metadata[address] {
		return nil
	}
	if m.retired[address] {
		return corrupt("metadata retired twice", 0)
	}
	m.retired[address] = true
	if e := m.space.retire(false, address, 1); e != nil {
		return e
	}
	if volume {
		m.freed++
	}
	return nil
}
func (m *mutation) allocateMetadata(volume bool) (uint64, error) {
	address, _, e := m.space.allocate(1)
	if e == nil && volume {
		m.allocated++
	}
	return address, e
}
func (m *mutation) writeTree(t *cowTree, volume bool) error {
	t.nodes = t.reachable()
	for _, n := range t.removed {
		if e := m.retireMetadata(n.address, volume); e != nil {
			return e
		}
		if t.storage == 0 && n.address != 0 {
			if e := m.pruneVolumeObject(n.oid); e != nil {
				return e
			}
			if record, retained := m.vmap.floor(append(buildUint64(n.oid), buildUint64(m.xid)...)); m.history != nil && retained && le.Uint64(record.key) == n.oid {
				value := make([]byte, 16)
				le.PutUint32(value, 1)
				if err := m.vmap.put(append(buildUint64(n.oid), buildUint64(m.xid)...), value); err != nil {
					return err
				}
			}
		}
	}
	for _, n := range t.nodes {
		if !t.dirty[n] {
			continue
		}
		old := n.address
		address, e := m.allocateMetadata(volume)
		if e != nil {
			return e
		}
		if e = m.retireMetadata(old, volume); e != nil {
			return e
		}
		n.address = address
		if t.storage == 0x40000000 {
			n.oid = address
		}
		b := t.nodeBytes(n, n == t.rootNode)
		sealMutationObject(b, n.oid, m.xid, le.Uint32(b[24:]), t.subtype)
		if e = m.write(b, address*4096); e != nil {
			return e
		}
		if t.storage == 0 {
			m.mappings[n.oid] = address
		}
	}
	return nil
}
func (m *mutation) writeMap(data []byte, tree *cowTree, volume bool) (uint64, error) {
	old := le.Uint64(data[8:])
	address, e := m.allocateMetadata(volume)
	if e != nil {
		return 0, e
	}
	if e = m.retireMetadata(old, volume); e != nil {
		return 0, e
	}
	b := bytes.Clone(data)
	le.PutUint64(b[48:], tree.rootNode.address)
	sealMutationObject(b, address, m.xid, 0x4000000b, 0)
	if e = m.write(b, address*4096); e != nil {
		return 0, e
	}
	return address, nil
}
func (m *mutation) commit(stamp uint64) error {
	if err := m.updateStatistics(false); err != nil {
		return err
	}
	if err := m.encodeHistoryExtents(); err != nil {
		return err
	}
	if e := m.writeTree(m.fs, true); e != nil {
		return e
	}
	if e := m.writeTree(m.extents, true); e != nil {
		return e
	}
	ids := make([]uint64, 0, len(m.mappings))
	for id := range m.mappings {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		if e := m.pruneVolumeObject(id); e != nil {
			return e
		}
		key := append(buildUint64(id), buildUint64(m.xid)...)
		value := make([]byte, 16)
		le.PutUint32(value[4:], 4096)
		le.PutUint64(value[8:], m.mappings[id])
		if e := m.vmap.put(key, value); e != nil {
			return e
		}
	}
	if e := m.writeTree(m.vmap, true); e != nil {
		return e
	}
	volumeMap, e := m.writeMap(m.volumeMap, m.vmap, true)
	if e != nil {
		return e
	}
	volume, e := m.allocateMetadata(false)
	if e != nil {
		return e
	}
	if e = m.retireMetadata(m.volumeAddress, false); e != nil {
		return e
	}
	if e := removeObjectVersions(m.cmap, uint64(m.v.OID)); e != nil {
		return e
	}
	key := append(buildUint64(uint64(m.v.OID)), buildUint64(m.xid)...)
	value := make([]byte, 16)
	le.PutUint32(value[4:], 4096)
	le.PutUint64(value[8:], volume)
	if e = m.cmap.put(key, value); e != nil {
		return e
	}
	if e = m.writeTree(m.cmap, false); e != nil {
		return e
	}
	containerMap, e := m.writeMap(m.containerMap, m.cmap, false)
	if e != nil {
		return e
	}
	le.PutUint64(m.super[128:], volumeMap)
	le.PutUint64(m.super[144:], m.extents.rootNode.address)
	le.PutUint64(m.super[64:], stamp)
	le.PutUint64(m.super[256:], stamp)
	old := le.Uint64(m.super[88:])
	if m.freed > old+m.allocated {
		return corrupt("changed volume allocation underflow", 0)
	}
	le.PutUint64(m.super[88:], old+m.allocated-m.freed)
	if err := m.updateSpaceLimits(old); err != nil {
		return err
	}
	le.PutUint64(m.super[224:], le.Uint64(m.super[224:])+m.allocated)
	le.PutUint64(m.super[232:], le.Uint64(m.super[232:])+m.freed)
	sealMutationObject(m.super, uint64(m.v.OID), m.xid, 13, 0)
	if e = m.write(m.super, volume*4096); e != nil {
		return e
	}
	le.PutUint64(m.nx[160:], containerMap)
	if e = m.space.prepare(); e != nil {
		return e
	}
	return m.writeCheckpoint()
}
func (m *mutation) writeCheckpoint() error {
	// Ephemeral objects use checkpoint data, not device-bitmap allocations.
	// The old selected data range is reserved until the new superblock is written.
	ep := []ephemeral{{kind: 0x80000005, oid: le.Uint64(m.nx[152:]), data: m.space.data}}
	reaper := m.ephemeral[le.Uint64(m.nx[168:])]
	reaper.data = bytes.Clone(reaper.data)
	ep = append(ep, reaper)
	for _, page := range m.reaperLists {
		page.data = bytes.Clone(page.data)
		ep = append(ep, page)
	}
	for _, q := range m.space.queues {
		q.nodes = q.reachable()
		for _, n := range q.nodes {
			ep = append(ep, ephemeral{kind: 0x80000003, subtype: 9, oid: n.oid})
			if n == q.rootNode {
				ep[len(ep)-1].kind = 0x80000002
			}
		}
	}
	blocks := uint32(0)
	for _, item := range ep {
		size := len(item.data)
		if size == 0 {
			size = 4096
		}
		blocks += uint32(size / 4096)
	}
	count := le.Uint32(m.nx[108:])
	base := le.Uint64(m.nx[120:])
	start := le.Uint32(m.nx[132:])
	oldStart, oldLength := le.Uint32(m.nx[144:]), le.Uint32(m.nx[148:])
	if blocks >= count || start >= count {
		return filesystem.ErrLimit
	}
	// The admitted multi-block space manager must remain contiguous within the ring.
	if start+blocks > count {
		start = 0
	}
	for i := uint32(0); i < blocks; i++ {
		for j := uint32(0); j < oldLength; j++ {
			if (start+i)%count == (oldStart+j)%count {
				return fmt.Errorf("checkpoint data ring full: %w", filesystem.ErrLimit)
			}
		}
	}
	at := start
	for i := range ep {
		ep[i].address = base + uint64(at)
		size := len(ep[i].data)
		if size == 0 {
			size = 4096
		}
		at += uint32(size / 4096)
	}
	addresses := map[uint64]uint64{}
	for _, item := range ep {
		addresses[item.oid] = item.address
	}
	for _, q := range m.space.queues {
		for _, n := range q.nodes {
			n.address = addresses[n.oid]
		}
	}
	for i := range ep {
		item := &ep[i]
		if item.data == nil {
			for _, q := range m.space.queues {
				for _, n := range q.nodes {
					if n.oid == item.oid {
						item.data = q.nodeBytes(n, n == q.rootNode)
					}
				}
			}
		}
		sealMutationObject(item.data, item.oid, m.xid, item.kind, item.subtype)
		if e := m.write(item.data, item.address*4096); e != nil {
			return e
		}
	}
	maps := (len(ep) + 100) / 101
	descCount := le.Uint32(m.nx[104:])
	descBase := le.Uint64(m.nx[112:])
	descStart := le.Uint32(m.nx[128:])
	oldDesc, oldDescLen := le.Uint32(m.nx[136:]), le.Uint32(m.nx[140:])
	if maps+1 >= int(descCount) || descStart >= descCount {
		return filesystem.ErrLimit
	}
	for i := uint32(0); i < uint32(maps+1); i++ {
		for j := uint32(0); j < oldDescLen; j++ {
			if (descStart+i)%descCount == (oldDesc+j)%descCount {
				return filesystem.ErrLimit
			}
		}
	}
	for i := 0; i < maps; i++ {
		address := descBase + uint64((descStart+uint32(i))%descCount)
		b := make([]byte, 4096)
		if i == maps-1 {
			le.PutUint32(b[32:], 1)
		}
		items := ep[i*101 : min(len(ep), (i+1)*101)]
		le.PutUint32(b[36:], uint32(len(items)))
		for j, item := range items {
			r := b[40+j*40:]
			le.PutUint32(r, item.kind)
			le.PutUint32(r[4:], item.subtype)
			le.PutUint32(r[8:], uint32(len(item.data)))
			le.PutUint64(r[24:], item.oid)
			le.PutUint64(r[32:], item.address)
		}
		sealMutationObject(b, address, m.xid, 0x4000000c, 0)
		if e := m.write(b, address*4096); e != nil {
			return e
		}
	}
	le.PutUint64(m.nx[88:], m.next)
	le.PutUint64(m.nx[96:], m.xid+1)
	le.PutUint32(m.nx[128:], (descStart+uint32(maps+1))%descCount)
	le.PutUint32(m.nx[132:], at%count)
	le.PutUint32(m.nx[136:], descStart)
	le.PutUint32(m.nx[140:], uint32(maps+1))
	le.PutUint32(m.nx[144:], start)
	le.PutUint32(m.nx[148:], blocks)
	sealMutationObject(m.nx, le.Uint64(m.nx[8:]), m.xid, le.Uint32(m.nx[24:]), 0)
	address := descBase + uint64((descStart+uint32(maps))%descCount)
	if e := m.write(m.nx, address*4096); e != nil {
		return e
	}
	return m.write(m.nx, 0)
}

// Keep the predecessor mapping (including a deletion placeholder) needed by
// each retained filesystem view. Checkpoints use their own physical map trees;
// the ordinary writer has no additional retained views and passes none here.
func removeObjectVersions(t *cowTree, oid uint64, retained ...XID) error {
	if len(retained) > maxSnapshots {
		return filesystem.ErrLimit
	}
	keep := make(map[uint64]bool, len(retained))
	for _, xid := range retained {
		if xid == 0 {
			return corrupt("retained object-map transaction", 0)
		}
		key := append(buildUint64(oid), buildUint64(uint64(xid))...)
		if record, ok := t.floor(key); ok && le.Uint64(record.key) == oid {
			keep[le.Uint64(record.key[8:])] = true
		}
	}
	for _, r := range objectVersions(t, oid) {
		if !keep[le.Uint64(r.key[8:])] {
			if e := t.put(r.key, nil); e != nil {
				return e
			}
		}
	}
	return nil
}

// Versions of one OID can straddle several leaves. Traverse only children
// whose ordered-pair key range can contain that OID, rather than allocating a
// full object-map inventory for every changed filesystem node.
func objectVersions(t *cowTree, oid uint64) []buildRecord {
	var records []buildRecord
	var visit func(*buildTreeNode)
	visit = func(node *buildTreeNode) {
		for index, record := range node.records {
			id := le.Uint64(record.key)
			if id > oid {
				break
			}
			if node.level == 0 {
				if id == oid {
					records = append(records, record)
				}
			} else {
				if index+1 < len(node.records) && le.Uint64(node.records[index+1].key) < oid {
					continue
				}
				visit(node.children[index])
			}
		}
	}
	visit(t.rootNode)
	return records
}
