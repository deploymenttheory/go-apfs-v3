package apfs

import (
	"context"
	"fmt"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const objectMask = uint64(1<<60) - 1

type record struct{ key, value []byte }
type recordPrefix struct {
	id   uint64
	kind uint8
}

func prefix(key []byte) recordPrefix {
	n := le.Uint64(key)
	return recordPrefix{n & objectMask, uint8(n >> 60)}
}
func (p recordPrefix) compare(q recordPrefix) int {
	if p.id < q.id {
		return -1
	}
	if p.id > q.id {
		return 1
	}
	if p.kind < q.kind {
		return -1
	}
	if p.kind > q.kind {
		return 1
	}
	return 0
}

// records visits only subtrees intersecting a record prefix. Working memory is
// bounded by depth, node size and the visited-node budget, not filesystem size.
// The tree's native suffix order is retained for the caller to interpret.
func (v *Volume) records(ctx context.Context, id uint64, kind uint8, yield func(record) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.container == nil {
		return corrupt("unopened volume", 0)
	}
	if err := v.access(); err != nil {
		return err
	}
	if v.Sealed || v.IncompatibleFeatures&^uint64(0xb) != 0 || v.rootType != 2 {
		return fmt.Errorf("filesystem tree features: %w", filesystem.ErrUnsupported)
	}
	if id > objectMask {
		return corrupt("file identifier", 0)
	}
	target := recordPrefix{id, kind}
	return v.walkRecords(ctx, recordTree{v.root, 14, false}, &target, yield)
}

type recordTree struct {
	root     OID
	subtype  uint32
	physical bool
}

// walkRecords shares bounded variable-record traversal between the filesystem
// and snapshot metadata trees. A nil target enumerates the whole tree.
func (v *Volume) walkRecords(ctx context.Context, tree recordTree, target *recordPrefix, yield func(record) error) error {
	seen := map[OID]bool{}
	var visit func(OID, int, int) error
	visit = func(oid OID, depth, expectedLevel int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth >= 32 || len(seen) >= 1<<20 {
			return filesystem.ErrLimit
		}
		if seen[oid] {
			return corrupt("filesystem tree cycle or repeated child", 0)
		}
		seen[oid] = true
		mapping := objectMapping{address: PhysicalAddress(oid)}
		if !tree.physical {
			var err error
			mapping, err = v.container.resolve(v.omap, oid, v.xid)
			if err != nil {
				return err
			}
		}
		objectType := uint32(3)
		if depth == 0 {
			objectType = 2
		}
		address := mapping.address
		b, err := v.object(mapping, objectType)
		if err != nil {
			return err
		}
		flags, level := le.Uint16(b[32:]), int(le.Uint16(b[34:]))
		if OID(le.Uint64(b[8:])) != oid || XID(le.Uint64(b[16:])) > v.xid || le.Uint32(b[28:]) != tree.subtype || (depth == 0) != (flags&1 != 0) || (level == 0) != (flags&2 != 0) || (expectedLevel >= 0 && level != expectedLevel) {
			return corrupt("filesystem tree node header", int64(address)*int64(v.container.BlockSize))
		}
		storage := uint32(0)
		if tree.physical {
			storage = 0x40000000
		}
		if le.Uint32(b[24:])&0xc0000000 != storage {
			return corrupt("tree object storage type", int64(address)*int64(v.container.BlockSize))
		}
		if flags&^uint16(3) != 0 {
			return fmt.Errorf("filesystem tree node flags %#x: %w", flags, filesystem.ErrUnsupported)
		}
		entries, err := variableRecords(b, flags&1 != 0)
		if err != nil {
			return err
		}
		for i, r := range entries {
			cmp := 0
			if target != nil {
				cmp = prefix(r.key).compare(*target)
			}
			if cmp > 0 {
				break
			}
			if level == 0 {
				if cmp == 0 {
					if err := yield(r); err != nil {
						return err
					}
				}
			} else {
				if target != nil && i+1 < len(entries) && prefix(entries[i+1].key).compare(*target) < 0 {
					continue
				}
				if len(r.value) != 8 {
					return corrupt("filesystem tree child", 0)
				}
				if err := visit(OID(le.Uint64(r.value)), depth+1, level-1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return visit(tree.root, 0, -1)
}

func variableRecords(b []byte, root bool) ([]record, error) {
	if len(b) < 56 || (root && len(b) < 96) {
		return nil, corrupt("short filesystem tree node", 0)
	}
	end := len(b)
	if root {
		end -= 40
	}
	toc, space := 56+int(le.Uint16(b[40:])), int(le.Uint16(b[42:]))
	count := int(le.Uint32(b[36:]))
	keys := toc + space
	if toc > end || keys > end || count > space/8 {
		return nil, corrupt("filesystem tree table", 0)
	}
	result := make([]record, 0, count)
	type span struct{ start, end int }
	spans := make([]span, 0, count*2)
	keyEnd, valueStart := keys, end
	for i := 0; i < count; i++ {
		e := b[toc+i*8 : toc+i*8+8]
		kp, kl := keys+int(le.Uint16(e)), int(le.Uint16(e[2:]))
		vp, vl := end-int(le.Uint16(e[4:])), int(le.Uint16(e[6:]))
		if kl < 8 || kp < keys || kp+kl > end || vp < keys || vl == 0 || vp+vl > end {
			return nil, corrupt("filesystem tree record bounds", 0)
		}
		keyEnd = max(keyEnd, kp+kl)
		valueStart = min(valueStart, vp)
		spans = append(spans, span{kp, kp + kl}, span{vp, vp + vl})
		r := record{b[kp : kp+kl], b[vp : vp+vl]}
		if i > 0 && prefix(result[i-1].key).compare(prefix(r.key)) > 0 {
			return nil, corrupt("filesystem tree prefix order", 0)
		}
		result = append(result, r)
	}
	if keyEnd > valueStart {
		return nil, corrupt("filesystem tree key/value overlap", 0)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return nil, corrupt("filesystem tree overlapping records", 0)
		}
	}
	return result, nil
}
