package apfs

import (
	"bytes"
	"context"
	"fmt"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// cowTree retains virtual OIDs and copies only changed paths. Physical child
// links change with allocation; ephemeral nodes are placed in the checkpoint.
// The node codec is shared with construction, not its fresh-volume planner.
type cowTree struct {
	*buildTree
	rootNode *buildTreeNode
	dirty    map[*buildTreeNode]bool
	removed  []*buildTreeNode
	less     func([]byte, []byte) bool
	newOID   func() (uint64, error)
}

func loadCOWTree(ctx context.Context, root uint64, subtype, storage uint32, read func(uint64) ([]byte, uint64, error), less func([]byte, []byte) bool, newOID func() (uint64, error)) (*cowTree, error) {
	t := &cowTree{buildTree: &buildTree{subtype: subtype, storage: storage}, dirty: map[*buildTreeNode]bool{}, less: less, newOID: newOID}
	seen := map[uint64]bool{}
	var visit func(uint64, int, int) (*buildTreeNode, error)
	visit = func(id uint64, depth, expected int) (*buildTreeNode, error) {
		if e := ctx.Err(); e != nil {
			return nil, e
		}
		if depth >= 32 || len(seen) >= 16000 {
			return nil, filesystem.ErrLimit
		}
		if seen[id] {
			return nil, corrupt("mutation tree cycle", 0)
		}
		seen[id] = true
		b, address, e := read(id)
		if e != nil {
			return nil, e
		}
		if len(b) != 4096 || !validChecksum(b) {
			return nil, corrupt("mutation tree checksum", 0)
		}
		flags, level := le.Uint16(b[32:]), int(le.Uint16(b[34:]))
		kind := uint32(3)
		if depth == 0 {
			kind = 2
		}
		if le.Uint64(b[8:]) != id || le.Uint32(b[24:]) != storage|kind || le.Uint32(b[28:]) != subtype || (depth == 0) != (flags&1 != 0) || (level == 0) != (flags&2 != 0) || (expected >= 0 && level != expected) {
			return nil, corrupt("mutation tree header", 0)
		}
		if flags&^uint16(7) != 0 {
			return nil, fmt.Errorf("mutation tree flags: %w", filesystem.ErrUnsupported)
		}
		if depth == 0 {
			info := b[len(b)-40:]
			t.flags = le.Uint32(info)
			t.keySize = int(le.Uint32(info[8:]))
			t.valueSize = int(le.Uint32(info[12:]))
			t.keyCount = le.Uint64(info[24:])
			t.longestKey = int(le.Uint32(info[16:]))
			t.longestValue = int(le.Uint32(info[20:]))
			if le.Uint32(info[4:]) != 4096 || t.flags&^uint32(0x5e) != 0 {
				return nil, filesystem.ErrUnsupported
			}
		}
		var records []record
		if flags&4 == 0 {
			if t.keySize != 0 || t.valueSize != 0 {
				return nil, corrupt("mutation variable tree sizes", 0)
			}
			records, e = variableRecords(b, depth == 0)
		} else {
			records, e = t.fixedRecords(b, depth == 0, level == 0)
		}
		if e != nil {
			return nil, e
		}
		n := &buildTreeNode{level: uint16(level), address: address, oid: id}
		for i, r := range records {
			if i > 0 && !less(records[i-1].key, r.key) {
				return nil, corrupt("mutation tree key order", 0)
			}
			n.records = append(n.records, buildRecord{bytes.Clone(r.key), bytes.Clone(r.value)})
			if level > 0 {
				if len(r.value) != 8 {
					return nil, corrupt("mutation index pointer", 0)
				}
				child, e := visit(le.Uint64(r.value), depth+1, level-1)
				if e != nil {
					return nil, e
				}
				if len(child.records) == 0 || !bytes.Equal(child.records[0].key, r.key) {
					return nil, corrupt("mutation index separator", 0)
				}
				n.children = append(n.children, child)
			}
		}
		t.nodes = append(t.nodes, n)
		return n, nil
	}
	n, e := visit(root, 0, -1)
	if e != nil {
		return nil, e
	}
	t.rootNode = n
	var count uint64
	for _, n := range t.nodes {
		if n.level == 0 {
			count += uint64(len(n.records))
		}
	}
	if count != t.keyCount {
		return nil, corrupt("mutation tree record count", 0)
	}
	return t, nil
}
func (t *cowTree) fixedRecords(b []byte, root, leaf bool) ([]record, error) {
	if t.keySize != 16 || (t.valueSize != 8 && t.valueSize != 16) {
		return nil, filesystem.ErrUnsupported
	}
	end := len(b)
	if root {
		end -= 40
	}
	toc := 56 + int(le.Uint16(b[40:]))
	keys := toc + int(le.Uint16(b[42:]))
	count := int(le.Uint32(b[36:]))
	if toc > end || keys > end || count > int(le.Uint16(b[42:]))/4 {
		return nil, corrupt("mutation fixed table", 0)
	}
	out := make([]record, 0, count)
	vl := t.valueSize
	if !leaf {
		vl = 8
	}
	for i := 0; i < count; i++ {
		p := toc + i*4
		kp := keys + int(le.Uint16(b[p:]))
		vo := le.Uint16(b[p+2:])
		if kp < keys || kp+16 > end {
			return nil, corrupt("mutation fixed key", 0)
		}
		var value []byte
		if vo == 0xffff {
			if t.subtype != 9 || !leaf || t.flags&4 == 0 {
				return nil, filesystem.ErrUnsupported
			}
			value = buildUint64(1)
		} else {
			vp := end - int(vo)
			if vp < keys || vp+vl > end || kp+16 > vp {
				return nil, corrupt("mutation fixed value", 0)
			}
			value = b[vp : vp+vl]
		}
		out = append(out, record{b[kp : kp+16], value})
	}
	return out, nil
}
func (t *cowTree) get(key []byte) (buildRecord, bool) {
	n := t.rootNode
	for n.level > 0 {
		at := sort.Search(len(n.records), func(i int) bool { return t.less(key, n.records[i].key) }) - 1
		if at < 0 {
			at = 0
		}
		n = n.children[at]
	}
	at := sort.Search(len(n.records), func(i int) bool { return !t.less(n.records[i].key, key) })
	if at < len(n.records) && !t.less(key, n.records[at].key) {
		return n.records[at], true
	}
	return buildRecord{}, false
}
func (t *cowTree) all() []buildRecord {
	var out []buildRecord
	var visit func(*buildTreeNode)
	visit = func(n *buildTreeNode) {
		if n.level == 0 {
			out = append(out, n.records...)
		} else {
			for _, c := range n.children {
				visit(c)
			}
		}
	}
	visit(t.rootNode)
	return out
}
func (t *cowTree) fits(n *buildTreeNode) bool {
	payload := 0
	for _, r := range n.records {
		vl := len(r.value)
		if n.level > 0 {
			vl = 8
		}
		payload += len(r.key) + vl
	}
	return 56+t.tocSize(len(n.records), n.level)+payload+40 <= 4096
}
func (t *cowTree) newNode(level uint16) (*buildTreeNode, error) {
	id, e := t.newOID()
	if e != nil {
		return nil, e
	}
	n := &buildTreeNode{oid: id, level: level}
	t.dirty[n] = true
	return n, nil
}
func (t *cowTree) put(key, value []byte) error {
	old, exists := t.get(key)
	if value == nil && !exists {
		return nil
	}
	if exists && bytes.Equal(old.value, value) {
		return nil
	}
	var update func(*buildTreeNode) (*buildTreeNode, error)
	update = func(n *buildTreeNode) (*buildTreeNode, error) {
		t.dirty[n] = true
		if n.level == 0 {
			at := sort.Search(len(n.records), func(i int) bool { return !t.less(n.records[i].key, key) })
			if at < len(n.records) && !t.less(key, n.records[at].key) {
				if value == nil {
					n.records = append(n.records[:at], n.records[at+1:]...)
				} else {
					n.records[at] = buildRecord{bytes.Clone(key), bytes.Clone(value)}
				}
			} else {
				n.records = append(n.records, buildRecord{})
				copy(n.records[at+1:], n.records[at:])
				n.records[at] = buildRecord{bytes.Clone(key), bytes.Clone(value)}
			}
		} else {
			at := sort.Search(len(n.records), func(i int) bool { return t.less(key, n.records[i].key) }) - 1
			if at < 0 {
				at = 0
			}
			child := n.children[at]
			right, e := update(child)
			if e != nil {
				return nil, e
			}
			if len(child.records) == 0 {
				t.removed = append(t.removed, child)
				delete(t.dirty, child)
				n.records = append(n.records[:at], n.records[at+1:]...)
				n.children = append(n.children[:at], n.children[at+1:]...)
			} else {
				n.records[at].key = child.records[0].key
			}
			if right != nil {
				n.records = append(n.records, buildRecord{})
				copy(n.records[at+2:], n.records[at+1:])
				n.records[at+1] = buildRecord{right.records[0].key, buildUint64(right.oid)}
				n.children = append(n.children, nil)
				copy(n.children[at+2:], n.children[at+1:])
				n.children[at+1] = right
			}
		}
		if t.fits(n) {
			return nil, nil
		}
		if len(n.records) < 2 {
			return nil, filesystem.ErrLimit
		}
		at := len(n.records) / 2
		right, e := t.newNode(n.level)
		if e != nil {
			return nil, e
		}
		right.records = append(right.records, n.records[at:]...)
		n.records = n.records[:at]
		if n.level > 0 {
			right.children = append(right.children, n.children[at:]...)
			n.children = n.children[:at]
		}
		if !t.fits(n) || !t.fits(right) {
			return nil, filesystem.ErrLimit
		}
		return right, nil
	}
	right, e := update(t.rootNode)
	if e != nil {
		return e
	}
	if right != nil {
		root := t.rootNode
		left, e := t.newNode(root.level)
		if e != nil {
			return e
		}
		left.records = append(left.records, root.records...)
		left.children = append(left.children, root.children...)
		root.level++
		root.children = []*buildTreeNode{left, right}
		root.records = []buildRecord{{left.records[0].key, buildUint64(left.oid)}, {right.records[0].key, buildUint64(right.oid)}}
	}
	if t.rootNode.level > 0 && len(t.rootNode.children) == 0 {
		t.rootNode.level = 0
	}
	for t.rootNode.level > 0 && len(t.rootNode.children) == 1 {
		child := t.rootNode.children[0]
		t.rootNode.level = child.level
		t.rootNode.records = child.records
		t.rootNode.children = child.children
		t.removed = append(t.removed, child)
		delete(t.dirty, child)
	}
	if value == nil {
		t.keyCount--
	} else if !exists {
		t.keyCount++
	}
	t.longestKey = max(t.longestKey, len(key))
	t.longestValue = max(t.longestValue, len(value))
	return nil
}
func (t *cowTree) reachable() []*buildTreeNode {
	var nodes []*buildTreeNode
	var visit func(*buildTreeNode)
	visit = func(n *buildTreeNode) {
		for _, c := range n.children {
			visit(c)
		}
		nodes = append(nodes, n)
	}
	visit(t.rootNode)
	return nodes
}
