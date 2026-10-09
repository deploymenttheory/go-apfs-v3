// Package fork implements bounded, read-only fork values shared by the engines.
package fork

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"sync/atomic"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Extent describes a logical byte range. Sparse must be explicit: a missing
// extent is corruption, not permission to substitute zeros for unknown data.
type Extent struct {
	Logical, Physical, Length int64
	Sparse                    bool
}

type value struct {
	ctx     context.Context
	source  block.Source
	size    int64
	extents []Extent
	closed  atomic.Bool
}

func New(ctx context.Context, source block.Source, size int64, extents []Extent) (filesystem.Value, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if size < 0 || source == nil {
		return nil, filesystem.ErrCorrupt
	}
	var end int64
	for _, e := range extents {
		if e.Logical != end || e.Length <= 0 || e.Length > int64(^uint64(0)>>1)-end || e.Physical < 0 || (!e.Sparse && (e.Physical > source.Size() || e.Length > source.Size()-e.Physical)) {
			return nil, fmt.Errorf("fork extent range: %w", filesystem.ErrCorrupt)
		}
		end += e.Length
	}
	if size > end {
		return nil, fmt.Errorf("incomplete fork extents: %w", filesystem.ErrCorrupt)
	}
	return &value{ctx: ctx, source: source, size: size, extents: append([]Extent(nil), extents...)}, nil
}

func Bytes(ctx context.Context, data []byte) (filesystem.Value, error) {
	source := bytes.NewReader(bytes.Clone(data))
	var extents []Extent
	if len(data) > 0 {
		extents = []Extent{{Length: int64(len(data))}}
	}
	return New(ctx, source, int64(len(data)), extents)
}

func (v *value) Size() int64  { return v.size }
func (v *value) Close() error { v.closed.Store(true); return nil }
func (v *value) ReadAt(p []byte, off int64) (int, error) {
	if v.closed.Load() {
		return 0, fs.ErrClosed
	}
	if err := v.ctx.Err(); err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= v.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(len(p)) > v.size-off {
		p = p[:v.size-off]
	}
	n := 0
	index := sort.Search(len(v.extents), func(i int) bool { e := v.extents[i]; return e.Logical+e.Length > off })
	for len(p) > 0 {
		if err := v.ctx.Err(); err != nil {
			return n, err
		}
		if index >= len(v.extents) {
			return n, filesystem.ErrCorrupt
		}
		e := v.extents[index]
		amount := min(int64(len(p)), e.Logical+e.Length-off)
		if e.Sparse {
			clear(p[:amount])
		} else if err := block.ReadFull(v.source, p[:amount], e.Physical+off-e.Logical); err != nil {
			return n, err
		}
		off += amount
		n += int(amount)
		p = p[amount:]
		index++
	}
	if n < want {
		return n, io.EOF
	}
	return n, nil
}
