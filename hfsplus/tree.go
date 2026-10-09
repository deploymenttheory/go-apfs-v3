package hfsplus

import (
	"context"
	"unicode/utf16"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type tree struct {
	fork        *fork
	root, total uint32
	nodeSize    uint16
	idOffset    int
}
type treeRecord struct{ key, value []byte }

func openTree(f *fork, idOffset int) (*tree, error) {
	b := make([]byte, 106)
	if err := f.read(b, 0); err != nil {
		return nil, err
	}
	t := &tree{fork: f, root: be.Uint32(b[16:]), total: be.Uint32(b[36:]), nodeSize: be.Uint16(b[32:]), idOffset: idOffset}
	if b[8] != 1 || t.nodeSize < 512 || t.nodeSize&(t.nodeSize-1) != 0 || t.total == 0 || t.root >= t.total || uint64(t.total)*uint64(t.nodeSize) > f.size {
		return nil, bad("B-tree header")
	}
	return t, nil
}

// records selects a parent CNID in the catalog or a file CNID in the attribute
// tree. Each index node bounds its children, so unrelated subtrees are not read.
func (t *tree) records(ctx context.Context, id uint32, yield func(treeRecord) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if t.root == 0 {
		return nil
	}
	seen := map[uint32]bool{}
	var visit func(uint32, int, int) error
	visit = func(node uint32, depth, expectedHeight int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth >= 32 || len(seen) >= 1<<20 {
			return filesystem.ErrLimit
		}
		if node == 0 || node >= t.total || seen[node] {
			return bad("B-tree cycle or child reference")
		}
		seen[node] = true
		b := make([]byte, t.nodeSize)
		if err := t.fork.read(b, uint64(node)*uint64(t.nodeSize)); err != nil {
			return err
		}
		kind, height := int8(b[8]), int(b[9])
		if (kind != -1 && kind != 0) || height < 1 || (kind == -1) != (height == 1) || (expectedHeight >= 0 && height != expectedHeight) {
			return bad("B-tree node kind or height")
		}
		records, err := nodeRecords(b, t.idOffset)
		if err != nil {
			return err
		}
		for i, r := range records {
			keyID := be.Uint32(r.key[t.idOffset:])
			if keyID > id {
				break
			}
			if kind == -1 {
				if keyID == id {
					if err := yield(r); err != nil {
						return err
					}
				}
			} else {
				if i+1 < len(records) && be.Uint32(records[i+1].key[t.idOffset:]) < id {
					continue
				}
				if len(r.value) != 4 {
					return bad("B-tree index value")
				}
				if err := visit(be.Uint32(r.value), depth+1, height-1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return visit(t.root, 0, -1)
}

func nodeRecords(b []byte, idOffset int) ([]treeRecord, error) {
	if len(b) < 14 || idOffset < 2 {
		return nil, bad("short B-tree node")
	}
	n := int(be.Uint16(b[10:]))
	if n == 0 || n > (len(b)-14)/4 {
		return nil, bad("B-tree record count")
	}
	result := make([]treeRecord, 0, n)
	var last uint32
	for i := 0; i < n; i++ {
		start, end := int(be.Uint16(b[len(b)-2*(i+1):])), int(be.Uint16(b[len(b)-2*(i+2):]))
		if start < 14 || end < start+2 || end > len(b)-2*(n+1) {
			return nil, bad("B-tree record bounds")
		}
		r := b[start:end]
		kl := 2 + int(be.Uint16(r))
		if kl < idOffset+4 || kl > len(r) || kl%2 != 0 {
			return nil, bad("B-tree key bounds")
		}
		id := be.Uint32(r[idOffset:])
		if i > 0 && id < last {
			return nil, bad("B-tree identifier order")
		}
		last = id
		result = append(result, treeRecord{r[:kl], r[kl:]})
	}
	return result, nil
}

func unicodeName(b []byte) (string, error) {
	if len(b) < 2 {
		return "", bad("Unicode name")
	}
	n := int(be.Uint16(b))
	if n > 255 || 2+n*2 != len(b) {
		return "", bad("Unicode name length")
	}
	u := make([]uint16, n)
	for i := range u {
		u[i] = be.Uint16(b[2+i*2:])
	}
	for i := 0; i < len(u); i++ {
		if u[i] >= 0xd800 && u[i] <= 0xdbff {
			if i+1 >= len(u) || u[i+1] < 0xdc00 || u[i+1] > 0xdfff {
				return "", bad("Unicode surrogate")
			}
			i++
		} else if u[i] >= 0xdc00 && u[i] <= 0xdfff {
			return "", bad("Unicode surrogate")
		}
	}
	return string(utf16.Decode(u)), nil
}
