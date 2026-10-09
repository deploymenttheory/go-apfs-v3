package hfsplus

import (
	"bytes"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestRejectInvalidAllocationGeometry(t *testing.T) {
	for _, bs := range []uint32{0, 511, 513, 0xffffffff} {
		b := make([]byte, 4096)
		copy(b[1024:], "H+")
		be.PutUint16(b[1026:], 4)
		be.PutUint32(b[1064:], bs)
		be.PutUint32(b[1068:], 1)
		if _, err := Open(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatalf("block size %d: %v", bs, err)
		}
	}
}

func FuzzVolume(f *testing.F) {
	f.Add(make([]byte, 4096))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_, _ = Open(bytes.NewReader(b))
	})
}
