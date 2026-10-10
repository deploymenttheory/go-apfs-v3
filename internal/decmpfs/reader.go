// Package decmpfs reads Apple's transparent compression storage. Filesystem
// engines decide whether UF_COMPRESSED is active before calling this package.
package decmpfs

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"sync"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const blockSize = 65536
const maxAttribute = 3802
const maxEncodedBlock = 1 << 20

var le = binary.LittleEndian
var be = binary.BigEndian

type Header struct {
	Type uint32
	Size uint64
}

// Attributes opens raw stored attributes, including hidden compression storage.
type Attributes func(string) (filesystem.Value, error)

func readHeader(a filesystem.Value) (Header, error) {
	var b [16]byte
	if a.Size() < 16 || a.Size() > maxAttribute {
		return Header{}, bad("attribute size")
	}
	if err := block.ReadFull(a, b[:], 0); err != nil {
		return Header{}, err
	}
	if le.Uint32(b[:]) != 0x636d7066 {
		return Header{}, bad("attribute magic")
	}
	h := Header{Type: le.Uint32(b[4:]), Size: le.Uint64(b[8:])}
	if h.Size > math.MaxInt64 {
		return Header{}, filesystem.ErrLimit
	}
	return h, nil
}

func attribute(open Attributes) (filesystem.Value, error) {
	a, err := open(filesystem.Decmpfs)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, bad("active compression without attribute")
	}
	return a, err
}

// Inspect reads metadata without decoding contents or requiring a known codec.
func Inspect(open Attributes) (Header, error) {
	a, err := attribute(open)
	if err != nil {
		return Header{}, err
	}
	defer func() { _ = a.Close() }()
	return readHeader(a)
}

// Open owns the values returned by open, including on failure. Memory is bounded
// by one decoded block, one encoded block and codec scratch space. Index entries
// are read on demand; the logical size never determines an allocation size.
func Open(ctx context.Context, open Attributes) (filesystem.Value, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	a, err := attribute(open)
	if err != nil {
		return nil, err
	}
	defer func() { _ = a.Close() }()
	h, err := readHeader(a)
	if err != nil {
		return nil, err
	}
	usesResource, err := UsesResourceFork(h.Type)
	if err != nil {
		return nil, err
	}
	v := &value{ctx: ctx, header: h, cached: -1}
	if !usesResource {
		if h.Size > blockSize {
			return nil, filesystem.ErrLimit
		}
		v.inline = make([]byte, a.Size()-16)
		if err := block.ReadFull(a, v.inline, 16); err != nil {
			return nil, err
		}
		if h.Size == 0 {
			if err := decode(h.Type, nil, v.inline); err != nil {
				return nil, err
			}
		}
		return v, nil
	}
	if a.Size() != 16 {
		return nil, bad("resource compression attribute length")
	}
	v.resource, err = open(filesystem.ResourceFork)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			err = bad("missing compressed resource fork")
		}
		return nil, err
	}
	if err := v.index(); err != nil {
		_ = v.resource.Close()
		return nil, err
	}
	return v, nil
}

type value struct {
	mu       sync.Mutex
	ctx      context.Context
	header   Header
	inline   []byte
	resource filesystem.Value
	blocks   int64
	indexEnd int64
	dataEnd  int64
	cached   int64
	decoded  []byte
	closed   bool
}

func (v *value) Size() int64 { return int64(v.header.Size) }

func (v *value) index() error {
	// Avoid signed addition overflow near MaxInt64.
	v.blocks = v.Size() / blockSize
	if v.Size()%blockSize != 0 {
		v.blocks++
	}
	if v.blocks == 0 {
		return bad("empty resource compression")
	}
	var b [16]byte
	if err := block.ReadFull(v.resource, b[:4], 0); err != nil {
		return err
	}
	if v.header.Type != 4 {
		v.indexEnd = (v.blocks + 1) * 4
		if v.indexEnd > math.MaxUint32 || int64(le.Uint32(b[:])) != v.indexEnd || v.indexEnd > v.resource.Size() {
			return bad("flat block index")
		}
		if err := block.ReadFull(v.resource, b[:4], v.blocks*4); err != nil {
			return err
		}
		v.dataEnd = int64(le.Uint32(b[:]))
		if v.dataEnd < v.indexEnd || v.dataEnd != v.resource.Size() {
			return bad("flat block index end")
		}
		return nil
	}
	if err := block.ReadFull(v.resource, b[:], 0); err != nil {
		return err
	}
	dataStart, mapStart := int64(be.Uint32(b[:])), int64(be.Uint32(b[4:]))
	dataLength, mapLength := int64(be.Uint32(b[8:])), int64(be.Uint32(b[12:]))
	v.dataEnd, v.indexEnd = dataStart+dataLength, 264+v.blocks*8
	if dataStart != 256 || dataLength < 8 || v.dataEnd > v.resource.Size() || mapStart < v.dataEnd || mapStart > v.resource.Size() || mapLength > v.resource.Size()-mapStart || v.indexEnd > v.dataEnd {
		return bad("resource manager ranges")
	}
	if err := block.ReadFull(v.resource, b[:8], 256); err != nil {
		return err
	}
	if int64(be.Uint32(b[:])) != dataLength-4 || int64(le.Uint32(b[4:])) != v.blocks {
		return bad("resource block count or length")
	}
	return nil
}

func (v *value) blockRange(index int64) (int64, int64, error) {
	var b [8]byte
	pos := index * 4
	if v.header.Type == 4 {
		pos = 264 + index*8
	}
	if err := block.ReadFull(v.resource, b[:], pos); err != nil {
		return 0, 0, err
	}
	start, end := int64(le.Uint32(b[:])), int64(le.Uint32(b[4:]))
	if v.header.Type == 4 {
		start += 260
		end += start
		if index != 0 {
			if err := block.ReadFull(v.resource, b[:], pos-8); err != nil {
				return 0, 0, err
			}
			if 260+int64(le.Uint32(b[:]))+int64(le.Uint32(b[4:])) > start {
				return 0, 0, bad("overlapping resource blocks")
			}
		}
	}
	if start < v.indexEnd || end <= start || end > v.dataEnd {
		return 0, 0, bad("compressed block range")
	}
	if end-start > maxEncodedBlock {
		return 0, 0, filesystem.ErrLimit
	}
	return start, end - start, nil
}

func (v *value) load(index int64) error {
	if v.cached == index {
		return nil
	}
	v.cached = -1
	size := min(int64(blockSize), v.Size()-index*blockSize)
	if cap(v.decoded) == 0 {
		v.decoded = make([]byte, blockSize)
	}
	v.decoded = v.decoded[:size]
	source := v.inline
	if v.resource != nil {
		offset, length, err := v.blockRange(index)
		if err != nil {
			return err
		}
		source = make([]byte, length)
		if err := block.ReadFull(v.resource, source, offset); err != nil {
			return err
		}
	}
	if err := decode(v.header.Type, v.decoded, source); err != nil {
		return err
	}
	v.cached = index
	return nil
}

func (v *value) ReadAt(p []byte, off int64) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
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
	if off >= v.Size() {
		return 0, io.EOF
	}
	want, n := len(p), 0
	if int64(len(p)) > v.Size()-off {
		p = p[:v.Size()-off]
	}
	for len(p) > 0 {
		if err := v.ctx.Err(); err != nil {
			return n, err
		}
		if err := v.load(off / blockSize); err != nil {
			return n, err
		}
		amount := copy(p, v.decoded[off%blockSize:])
		n += amount
		off += int64(amount)
		p = p[amount:]
	}
	if n < want {
		return n, io.EOF
	}
	return n, nil
}

func (v *value) Close() error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	v.inline, v.decoded = nil, nil
	if v.resource != nil {
		return v.resource.Close()
	}
	return nil
}

func bad(reason string) error { return fmt.Errorf("decmpfs %s: %w", reason, filesystem.ErrCorrupt) }

// UsesResourceFork classifies admitted decmpfs storage profiles. Unknown types
// must not cause a caller to discard a possibly independent resource fork.
func UsesResourceFork(kind uint32) (bool, error) {
	switch kind {
	case 1, 3, 7, 9, 11, 13, 15:
		return false, nil
	case 4, 8, 10, 12, 14, 16:
		return true, nil
	default:
		return false, fmt.Errorf("decmpfs type %d: %w", kind, filesystem.ErrUnsupported)
	}
}
