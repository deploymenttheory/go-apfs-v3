package apfs

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const buildBlockSize = 4096

type buildRecord struct{ key, value []byte }
type buildTreeNode struct {
	records      []buildRecord
	children     []*buildTreeNode
	level        uint16
	address, oid uint64
}
type buildTree struct {
	nodes                    []*buildTreeNode // children precede parents; the root is last
	subtype, storage, flags  uint32
	keySize, valueSize       int
	keyCount                 uint64
	longestKey, longestValue int
}

func newBuildTree(records []buildRecord, subtype, storage uint32, fixed bool) (*buildTree, error) {
	t := &buildTree{subtype: subtype, storage: storage, flags: 0x40, keyCount: uint64(len(records))}
	if storage == 0x40000000 {
		t.flags |= 0x10
	}
	if fixed {
		t.keySize, t.valueSize = 16, 16
		t.flags = 0x10
		if subtype == 9 {
			t.valueSize, t.flags = 8, 0x0c
		}
	}
	for _, r := range records {
		t.longestKey = max(t.longestKey, len(r.key))
		t.longestValue = max(t.longestValue, len(r.value))
	}
	if fixed {
		t.longestKey, t.longestValue = t.keySize, t.valueSize
	}
	level := uint16(0)
	for {
		// Reserve a root footer in every node. This slightly conservative packing
		// avoids an extra root-only sizing rule and still admits full native xattrs.
		var nodes []*buildTreeNode
		for len(records) > 0 || len(nodes) == 0 {
			n := &buildTreeNode{level: level}
			payload := 0
			for len(records) > 0 {
				r := records[0]
				if 56+t.tocSize(len(n.records)+1, level)+payload+len(r.key)+len(r.value)+40 > buildBlockSize {
					break
				}
				n.records = append(n.records, r)
				payload += len(r.key) + len(r.value)
				records = records[1:]
			}
			if len(n.records) == 0 && len(records) > 0 {
				return nil, fmt.Errorf("APFS B-tree record exceeds node: %w", filesystem.ErrLimit)
			}
			nodes = append(nodes, n)
			if len(records) == 0 {
				break
			}
		}
		t.nodes = append(t.nodes, nodes...)
		if len(t.nodes) > 16000 {
			return nil, filesystem.ErrLimit
		}
		if len(nodes) == 1 {
			break
		}
		if level >= 15 {
			return nil, filesystem.ErrLimit
		}
		records = make([]buildRecord, len(nodes))
		for i, n := range nodes {
			records[i] = buildRecord{n.records[0].key, make([]byte, 8)}
		}
		// The next level's records each represent one child. Fill those links
		// after grouping, using order rather than addresses that are not allocated yet.
		level++
	}
	var lower []*buildTreeNode
	for level := uint16(0); level <= t.root().level; level++ {
		var current []*buildTreeNode
		at := 0
		for _, n := range t.nodes {
			if n.level != level {
				continue
			}
			current = append(current, n)
			if level != 0 {
				n.children = lower[at : at+len(n.records)]
				at += len(n.records)
			}
		}
		lower = current
	}
	return t, nil
}

func (t *buildTree) root() *buildTreeNode { return t.nodes[len(t.nodes)-1] }
func (t *buildTree) tocSize(count int, level uint16) int {
	if t.keySize != 0 {
		v := t.valueSize
		if level != 0 {
			v = 8
		}
		return (buildBlockSize - 56) / (t.keySize + v + 4) * 4
	}
	return max(16, (count+7)/8*8) * 8
}
func (t *buildTree) place(start, firstOID uint64) uint64 {
	for i, n := range t.nodes {
		n.address = start + uint64(i)
		n.oid = n.address
		if t.storage != 0x40000000 {
			n.oid = firstOID + uint64(i)
		}
	}
	return start + uint64(len(t.nodes))
}

func (t *buildTree) blocks() []buildPart {
	parts := make([]buildPart, 0, len(t.nodes))
	for _, n := range t.nodes {
		b := make([]byte, buildBlockSize)
		root := n == t.root()
		var flags uint16
		if root {
			flags |= 1
		}
		if n.level == 0 {
			flags |= 2
		}
		if t.keySize != 0 {
			flags |= 4
		}
		le.PutUint16(b[32:], flags)
		le.PutUint16(b[34:], n.level)
		le.PutUint32(b[36:], uint32(len(n.records)))
		toc := t.tocSize(len(n.records), n.level)
		le.PutUint16(b[42:], uint16(toc))
		le.PutUint16(b[48:], 0xffff)
		le.PutUint16(b[52:], 0xffff)
		keyBase := 56 + toc
		keyEnd, valueEnd := keyBase, buildBlockSize
		if root {
			valueEnd -= 40
		}
		valueBase := valueEnd
		for i, r := range n.records {
			value := r.value
			if n.level != 0 {
				value = make([]byte, 8)
				le.PutUint64(value, n.children[i].oid)
			}
			valueEnd -= len(value)
			copy(b[keyEnd:], r.key)
			copy(b[valueEnd:], value)
			if t.keySize != 0 {
				at := 56 + i*4
				le.PutUint16(b[at:], uint16(keyEnd-keyBase))
				le.PutUint16(b[at+2:], uint16(valueBase-valueEnd))
			} else {
				at := 56 + i*8
				le.PutUint16(b[at:], uint16(keyEnd-keyBase))
				le.PutUint16(b[at+2:], uint16(len(r.key)))
				le.PutUint16(b[at+4:], uint16(valueBase-valueEnd))
				le.PutUint16(b[at+6:], uint16(len(value)))
			}
			keyEnd += len(r.key)
		}
		le.PutUint16(b[44:], uint16(keyEnd-keyBase))
		le.PutUint16(b[46:], uint16(valueEnd-keyEnd))
		kind := uint32(3)
		if root {
			kind = 2
			info := b[buildBlockSize-40:]
			for i, v := range []uint32{t.flags, buildBlockSize, uint32(t.keySize), uint32(t.valueSize), uint32(t.longestKey), uint32(t.longestValue)} {
				le.PutUint32(info[4*i:], v)
			}
			le.PutUint64(info[24:], t.keyCount)
			le.PutUint64(info[32:], uint64(len(t.nodes)))
		}
		sealBuildObject(b, n.oid, t.storage|kind, t.subtype)
		parts = append(parts, buildPart{offset: int64(n.address) * buildBlockSize, data: b})
	}
	return parts
}

func sealBuildObject(b []byte, oid uint64, kind, subtype uint32) {
	le.PutUint64(b[8:], oid)
	le.PutUint64(b[16:], 1)
	le.PutUint32(b[24:], kind)
	le.PutUint32(b[28:], subtype)
	const mod = uint64(0xffffffff)
	var a, s uint64
	for at := 8; at < len(b); at += 4 {
		a = (a + uint64(le.Uint32(b[at:]))) % mod
		s = (s + a) % mod
	}
	x := mod - (a+s)%mod
	y := mod - (a+x)%mod
	le.PutUint64(b, y<<32|x)
}
