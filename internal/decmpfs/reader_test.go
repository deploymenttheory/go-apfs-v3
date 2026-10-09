package decmpfs

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"math"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/fork"
)

func header(kind uint32, size uint64, data []byte) []byte {
	b := make([]byte, 16, 16+len(data))
	le.PutUint32(b, 0x636d7066)
	le.PutUint32(b[4:], kind)
	le.PutUint64(b[8:], size)
	return append(b, data...)
}

func attributes(ctx context.Context, attribute, resource []byte) Attributes {
	return func(name string) (filesystem.Value, error) {
		b := attribute
		if name == filesystem.ResourceFork {
			b = resource
		}
		if b == nil {
			return nil, fs.ErrNotExist
		}
		return fork.Bytes(ctx, b)
	}
}

// Native acceptance establishes compatibility. These deliberately invalid
// layouts establish that no corrupt range becomes successful zero-filled data.
func TestRejectMalformedStorage(t *testing.T) {
	flat := func(offsets ...uint32) []byte {
		b := make([]byte, len(offsets)*4)
		for i, n := range offsets {
			le.PutUint32(b[i*4:], n)
		}
		return b
	}
	cases := []struct {
		name           string
		attr, resource []byte
		want           error
	}{
		{"missing-attribute", nil, nil, filesystem.ErrCorrupt},
		{"short-header", []byte("fpmc"), nil, filesystem.ErrCorrupt},
		{"wrong-magic", make([]byte, 16), nil, filesystem.ErrCorrupt},
		{"oversized-attribute", header(1, 4000, make([]byte, 4000)), nil, filesystem.ErrCorrupt},
		{"size-overflow", header(3, math.MaxUint64, nil), nil, filesystem.ErrLimit},
		{"inline-limit", header(3, 1<<40, []byte{0xff}), nil, filesystem.ErrLimit},
		{"generation-store", header(5, 100, nil), nil, filesystem.ErrUnsupported},
		{"dataless", header(0x80000001, 100, nil), nil, filesystem.ErrUnsupported},
		{"unknown-codec", header(99, 100, nil), nil, filesystem.ErrUnsupported},
		{"missing-resource", header(10, 1, nil), nil, filesystem.ErrCorrupt},
		{"resource-inline-data", header(10, 1, []byte{1}), flat(8, 10), filesystem.ErrCorrupt},
		{"wrong-count", header(10, 1, nil), flat(12, 12, 12), filesystem.ErrCorrupt},
		{"index-outside-fork", header(10, 1, nil), flat(8, 1000), filesystem.ErrCorrupt},
		{"empty-block", header(10, 1, nil), flat(8, 8), filesystem.ErrCorrupt},
		{"stored-size", header(9, 3, []byte{0xcc, 1}), nil, filesystem.ErrCorrupt},
		{"stored-marker", header(9, 1, []byte{0xff, 1}), nil, filesystem.ErrCorrupt},
		{"empty-invalid-codec", header(3, 0, nil), nil, filesystem.ErrCorrupt},
		{"lzvn-truncated", header(7, 3, []byte{0xe3, 1, 2, 3}), nil, filesystem.ErrCorrupt},
		{"lzfse-invalid-stored-marker", header(11, 1, []byte{0, 42}), nil, filesystem.ErrCorrupt},
		{"lzfse-truncated", header(11, 1, []byte("bvx2")), nil, filesystem.ErrCorrupt},
		{"lzbitmap-truncated", header(13, 1, []byte("ZBM\x09")), nil, filesystem.ErrCorrupt},
		{"lz4-truncated", header(15, 1, []byte("bv41")), nil, filesystem.ErrCorrupt},
		{"lz4-excess-output", header(15, 1, []byte{'b', 'v', '4', '-', 2, 0, 0, 0, 1, 2, 'b', 'v', '4', '$'}), nil, filesystem.ErrCorrupt},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v, err := Open(context.Background(), attributes(context.Background(), tc.attr, tc.resource))
			if err == nil {
				defer v.Close()
				_, err = v.ReadAt(make([]byte, 1), 0)
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}

func TestResourceDescriptorBounds(t *testing.T) {
	// One stored byte at offset 280, with legal padding between index and data.
	valid := make([]byte, 282+50)
	be.PutUint32(valid, 256)
	be.PutUint32(valid[4:], 282)
	be.PutUint32(valid[8:], 26)
	be.PutUint32(valid[12:], 50)
	be.PutUint32(valid[256:], 22)
	le.PutUint32(valid[260:], 1)
	le.PutUint32(valid[264:], 20)
	le.PutUint32(valid[268:], 2)
	valid[280], valid[281] = 0xff, 42
	for _, tc := range []struct {
		name   string
		offset int
		number uint32
	}{
		{"map-before-data", 4, 281}, {"map-outside-fork", 12, 51},
		{"count-disagrees", 260, 2}, {"block-in-index", 264, 1},
		{"block-in-resource-map", 268, 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := bytes.Clone(valid)
			var order binary.ByteOrder = le
			if tc.offset < 256 {
				order = be
			}
			order.PutUint32(b[tc.offset:], tc.number)
			v, err := Open(context.Background(), attributes(context.Background(), header(4, 1, nil), b))
			if err == nil {
				defer v.Close()
				_, err = v.ReadAt(make([]byte, 1), 0)
			}
			if !errors.Is(err, filesystem.ErrCorrupt) {
				t.Fatal(err)
			}
		})
	}
}

func TestDeflateChecksTrailerAndOutputLength(t *testing.T) {
	// A final RFC 1951 stored block containing abc, behind a zlib header.
	plain := []byte{0x78, 0x5e, 1, 3, 0, 0xfc, 0xff, 'a', 'b', 'c'}
	checksum := []byte{0x02, 0x4d, 0x01, 0x27}
	for _, tc := range []struct {
		name    string
		payload []byte
		size    int
		valid   bool
	}{
		{"without-trailer", plain, 3, true},
		{"with-trailer", append(bytes.Clone(plain), checksum...), 3, true},
		{"bad-checksum", append(bytes.Clone(plain), 0, 0, 0, 0), 3, false},
		{"short-checksum", append(bytes.Clone(plain), 0), 3, false},
		{"excess-output", plain, 2, false},
		{"short-output", plain, 4, false},
		{"truncated-stream", plain[:len(plain)-1], 3, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := make([]byte, tc.size)
			err := decode(3, out, tc.payload)
			if tc.valid {
				if err != nil || string(out) != "abc" {
					t.Fatalf("%q %v", out, err)
				}
			} else if !errors.Is(err, filesystem.ErrCorrupt) {
				t.Fatal(err)
			}
		})
	}
}

func TestValueLifetimeAndRandomReads(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	plain := bytes.Repeat([]byte{1, 3, 5, 7}, blockSize/4)
	resource := make([]byte, 12)
	le.PutUint32(resource, 12)
	le.PutUint32(resource[4:], 12+blockSize+1)
	le.PutUint32(resource[8:], 12+blockSize+3)
	resource = append(resource, 0xcc)
	resource = append(resource, plain...)
	resource = append(resource, 0xcc, 9)
	open := attributes(ctx, header(10, blockSize+1, nil), resource)
	v, err := Open(ctx, open)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	other, err := Open(ctx, open)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 8 {
				b := make([]byte, 5)
				n, err := v.ReadAt(b, blockSize-3)
				if n != 4 || err != io.EOF || !bytes.Equal(b[:4], []byte{3, 5, 7, 9}) {
					t.Errorf("boundary read %d: %x %d %v", i, b, n, err)
				}
			}
		})
	}
	wg.Wait()
	if _, err := v.ReadAt(nil, -1); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if err := v.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := v.ReadAt(nil, 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatal(err)
	}
	if _, err := other.ReadAt(make([]byte, 1), 0); err != nil {
		t.Fatal("closing sibling", err)
	}
	cancel()
	if _, err := other.ReadAt(make([]byte, 1), 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

type generatedIndex struct {
	reads  int
	closed bool
}

const manyBlocks = 200000

func (*generatedIndex) Size() int64    { return (manyBlocks+1)*4 + manyBlocks*2 }
func (r *generatedIndex) Close() error { r.closed = true; return nil }
func (r *generatedIndex) ReadAt(p []byte, off int64) (int, error) {
	r.reads++
	if len(p) > 16 {
		return 0, errors.New("index was materialized")
	}
	if off == r.Size()-2 {
		copy(p, []byte{0xcc, 42})
		return len(p), nil
	}
	for i := 0; i < len(p); i += 4 {
		le.PutUint32(p[i:], uint32((manyBlocks+1)*4+(off/4+int64(i/4))*2))
	}
	return len(p), nil
}

func TestLargeLogicalSizeUsesBoundedIndexReads(t *testing.T) {
	ctx := context.Background()
	index := &generatedIndex{}
	open := func(name string) (filesystem.Value, error) {
		if name == filesystem.ResourceFork {
			return index, nil
		}
		return fork.Bytes(ctx, header(10, (manyBlocks-1)*blockSize+1, nil))
	}
	v, err := Open(ctx, open)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 1)
	n, err := v.ReadAt(b, v.Size()-1)
	if err != nil || n != 1 || b[0] != 42 || index.reads > 5 {
		t.Fatalf("large index read: %x, %d, %v; %d reads", b, n, err, index.reads)
	}
	if err := v.Close(); err != nil || !index.closed {
		t.Fatal("resource lifetime", err)
	}
}

func FuzzDecmpfs(f *testing.F) {
	f.Add(uint32(3), uint16(32), []byte{0xff, 1})
	f.Add(uint32(11), uint16(32), []byte("bvx2"))
	f.Add(uint32(13), uint16(32), []byte("ZBM\x09"))
	f.Add(uint32(15), uint16(32), []byte("bv41"))
	f.Fuzz(func(t *testing.T, kind uint32, size uint16, payload []byte) {
		if len(payload) > maxAttribute-16 {
			return
		}
		ctx := context.Background()
		v, err := Open(ctx, attributes(ctx, header(kind, uint64(size), payload), payload))
		if err != nil {
			return
		}
		defer v.Close()
		_, _ = io.Copy(io.Discard, io.NewSectionReader(v, 0, v.Size()))
	})
}
