package hfsplus

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Corruption checks complement native fragmented forks: gaps and aliases must
// fail explicitly instead of returning zeroes or reading unrelated blocks.
func TestRejectBrokenForkExtents(t *testing.T) {
	for _, name := range []string{"missing", "wrong-logical-start", "empty", "overlap", "outside-volume", "over-allocation", "early-terminator", "unreachable"} {
		t.Run(name, func(t *testing.T) {
			b := make([]byte, 80)
			be.PutUint64(b, 12*512)
			be.PutUint32(b[12:], 12)
			for i := 0; i < 8; i++ {
				be.PutUint32(b[16+i*8:], uint32(2+i*2))
				be.PutUint32(b[20+i*8:], 1)
			}
			overflow := make([]byte, 64)
			be.PutUint32(overflow, 20)
			be.PutUint32(overflow[4:], 4)
			records := map[uint32][]byte{8: overflow}
			switch name {
			case "missing":
				delete(records, 8)
			case "wrong-logical-start":
				records[9] = records[8]
				delete(records, 8)
			case "empty":
				clear(overflow)
			case "overlap":
				be.PutUint32(overflow, 2)
			case "outside-volume":
				be.PutUint32(overflow, 63)
			case "over-allocation":
				be.PutUint32(overflow[4:], 5)
			case "early-terminator":
				clear(b[16+7*8:])
			case "unreachable":
				records[12] = bytes.Clone(overflow)
			}
			_, err := resolveFork(context.Background(), bytes.NewReader(make([]byte, 64*512)), 512, 64, b, func() (map[uint32][]byte, error) { return records, nil })
			if !errors.Is(err, filesystem.ErrCorrupt) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestForkCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolveFork(ctx, nil, 512, 64, make([]byte, 80), nil); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzForkDescriptor(f *testing.F) {
	f.Add(make([]byte, 80))
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = resolveFork(context.Background(), nil, 4096, 1<<20, b, nil)
	})
}
