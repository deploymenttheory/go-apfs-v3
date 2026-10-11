package hfsplus

import (
	"bytes"
	"context"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/block"
)

// Small native-permitted extent nodes force splits, root growth, metadata-file
// allocation, empty-leaf removal and root collapse with a bounded record set.
func TestMutableExtentTreeSplitsGrowsAndCollapses(t *testing.T) {
	ctx := context.Background()
	b := mutationFixture(t, false, "preserve")
	descriptor := b[1024+192 : 1024+272]
	start := int(be.Uint32(descriptor[16:])) * 4096
	bytesCount := int(be.Uint64(descriptor))
	clear(b[start : start+bytesCount])
	h := b[start : start+512]
	h[8] = 1
	be.PutUint16(h[10:], 3)
	for i, off := range []uint16{14, 120, 248, 504} {
		be.PutUint16(h[512-2*(i+1):], off)
	}
	be.PutUint16(h[32:], 512)
	be.PutUint16(h[34:], 10)
	be.PutUint32(h[36:], uint32(bytesCount/512))
	be.PutUint32(h[40:], uint32(bytesCount/512-1))
	be.PutUint32(h[46:], 4096)
	be.PutUint32(h[52:], 2)
	h[248] = 128
	disk, e := block.Stage(ctx, bytes.NewReader(b), t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer disk.Close()
	v, e := Open(disk)
	if e != nil {
		t.Fatal(e)
	}
	m := &mutation{ctx: ctx, disk: disk, v: v, header: bytes.Clone(b[1024:1536]), trees: map[uint32]*mutableTree{}}
	if e = m.admit(); e != nil {
		t.Fatal(e)
	}
	tree := m.trees[3]
	before := tree.total
	for i := 0; i < 500; i++ {
		value := make([]byte, 64)
		be.PutUint32(value, uint32(i+20))
		be.PutUint32(value[4:], 1)
		if e = tree.set(extentKey(1000, 0, uint32(i*8)), value, false); e != nil {
			t.Fatalf("insert %d: %v", i, e)
		}
	}
	if tree.total <= before || be.Uint16(tree.header[14:]) < 3 {
		t.Fatal("did not force tree and fork growth", tree.total, before, be.Uint16(tree.header[14:]))
	}
	if e = tree.validate(map[uint32]bool{0: true}); e != nil {
		t.Fatal(e)
	}
	// Delete interior, first and last keys, rather than just reversing inserts.
	for remainder := 0; remainder < 3; remainder++ {
		for i := remainder; i < 500; i += 3 {
			if e = tree.set(extentKey(1000, 0, uint32(i*8)), nil, true); e != nil {
				t.Fatalf("delete %d: %v", i, e)
			}
		}
		if e = tree.validate(map[uint32]bool{0: true}); e != nil {
			t.Fatal(e)
		}
	}
	if be.Uint32(tree.header[16:]) != 0 || be.Uint32(tree.header[20:]) != 0 || be.Uint16(tree.header[14:]) != 0 {
		t.Fatal("empty tree did not collapse")
	}
	if e = tree.set(extentKey(1000, 255, 8), make([]byte, 64), false); e != nil {
		t.Fatal(e)
	}
	if e = tree.validate(map[uint32]bool{0: true}); e != nil {
		t.Fatal(e)
	}
}
