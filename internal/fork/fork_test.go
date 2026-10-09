package fork

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestSparseRangesAndIndependentConcurrentValues(t *testing.T) {

	extents := []Extent{{Logical: 0, Length: 4, Data: bytes.NewReader([]byte("abcd"))}, {Logical: 4, Length: 8}, {Logical: 12, Length: 4, Data: bytes.NewReader([]byte("EFGH"))}}
	a, err := New(context.Background(), 15, extents)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New(context.Background(), 15, extents)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ReadAt(make([]byte, 1), 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("closed handle remained readable", err)
	}
	want := append(append([]byte("abcd"), make([]byte, 8)...), []byte("EFG")...)
	var wg sync.WaitGroup
	for off := range 16 {
		wg.Go(func() {
			p := make([]byte, 8)
			n, err := b.ReadAt(p, int64(off))
			expected := want[off:]
			if len(expected) > len(p) {
				expected = expected[:len(p)]
			}
			if n != len(expected) || !bytes.Equal(p[:n], expected) || (n < len(p) && !errors.Is(err, io.EOF)) || (n == len(p) && err != nil) {
				t.Errorf("offset %d: %x, %d, %v", off, p, n, err)
			}
		})
	}
	wg.Wait()
	if _, err := b.ReadAt(make([]byte, 1), -1); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
}

func TestMissingOverlappingAndOverflowingExtentsFail(t *testing.T) {
	source := bytes.NewReader(make([]byte, 8))
	for _, extents := range [][]Extent{nil, {{Logical: 1, Length: 2}}, {{Length: 4}, {Logical: 3, Length: 2}}, {{Length: 9, Data: source}}, {{Length: 1<<63 - 1}, {Logical: 1<<63 - 1, Length: 1}}} {
		if _, err := New(context.Background(), 4, extents); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatalf("accepted invalid extents %+v: %v", extents, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	v, err := New(ctx, 8, []Extent{{Length: 8, Data: source}})
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	cancel()
	if _, err := v.ReadAt(make([]byte, 1), 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
