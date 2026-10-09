package hfsplus

import (
	"context"
	"fmt"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Extents keys order file ID, fork type, then the logical start allocation block.
// Attribute continuations use a different tree and supply their own resolver.
func (v *Volume) fileFork(ctx context.Context, id uint32, kind byte, descriptor []byte) (*fork, error) {
	return resolveFork(ctx, v.source, v.BlockSize, v.BlockCount, descriptor, func() (map[uint32][]byte, error) {
		records := map[uint32][]byte{}
		if v.overflow == nil {
			return records, nil
		}
		err := v.overflow.records(ctx, id, func(r treeRecord) error {
			if len(r.key) != 12 || r.key[3] != 0 || (r.key[2] != 0 && r.key[2] != 0xff) || len(r.value) != 64 {
				return bad("overflow extent record")
			}
			if r.key[2] != kind {
				return nil
			}
			start := be.Uint32(r.key[8:])
			if records[start] != nil {
				return bad("duplicate overflow extent")
			}
			if len(records) >= 1<<17 {
				return filesystem.ErrLimit
			}
			records[start] = r.value
			return nil
		})
		return records, err
	})
}

func resolveFork(ctx context.Context, source block.Source, bs, count uint32, b []byte, overflow func() (map[uint32][]byte, error)) (*fork, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(b) != 80 || bs == 0 {
		return nil, bad("fork descriptor")
	}
	f := &fork{source: source, size: be.Uint64(b)}
	total := be.Uint32(b[12:])
	if total > count || f.size > uint64(total)*uint64(bs) {
		return nil, bad("fork allocation size")
	}
	var blocks uint32
	appendRecord := func(record []byte) error {
		if len(record) != 64 {
			return bad("extent record length")
		}
		ended := false
		for n := 0; n < 8; n++ {
			start, length := be.Uint32(record[n*8:]), be.Uint32(record[n*8+4:])
			if length == 0 {
				if start != 0 {
					return bad("empty fork extent")
				}
				ended = true
				continue
			}
			if ended || start >= count || length > count-start || length > total-blocks {
				return bad("fork extent range or allocation count")
			}
			f.extents = append(f.extents, extent{uint64(blocks) * uint64(bs), uint64(start) * uint64(bs), uint64(length) * uint64(bs)})
			blocks += length
		}
		if ended && blocks != total {
			return bad("premature extent terminator")
		}
		return nil
	}
	if err := appendRecord(b[16:]); err != nil {
		return nil, err
	}
	if blocks < total {
		if overflow == nil {
			return nil, fmt.Errorf("self-describing extents file requires overflow: %w", filesystem.ErrUnsupported)
		}
		records, err := overflow()
		if err != nil {
			return nil, err
		}
		for blocks < total {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			record, ok := records[blocks]
			if !ok {
				return nil, bad("missing overflow extent")
			}
			delete(records, blocks)
			before := blocks
			if err := appendRecord(record); err != nil {
				return nil, err
			}
			if blocks == before {
				return nil, bad("empty overflow extent")
			}
		}
		if len(records) != 0 {
			return nil, bad("unreachable overflow extent")
		}
	}
	// A fork may not refer to the same physical blocks twice. Sort a copy so
	// logical read order remains intact and validation stays O(n log n).
	physical := append([]extent(nil), f.extents...)
	sort.Slice(physical, func(i, j int) bool { return physical[i].physical < physical[j].physical })
	for i := 1; i < len(physical); i++ {
		if physical[i-1].physical+physical[i-1].size > physical[i].physical {
			return nil, bad("overlapping physical fork extents")
		}
	}
	return f, nil
}
