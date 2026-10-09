package apfs

import (
	"bytes"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Synthetic checkpoints exercise selection and corruption handling. Genuine
// object decoding is separately checked by the native acceptance corpus.
func checkpoint(xid uint64) []byte {
	b := make([]byte, 4096)
	copy(b[32:], "NXSB")
	le.PutUint64(b[8:], 1)
	le.PutUint64(b[16:], xid)
	le.PutUint32(b[24:], 0x80000001)
	le.PutUint32(b[36:], 4096)
	le.PutUint64(b[40:], 4)
	le.PutUint64(b[64:], 2)
	le.PutUint32(b[104:], 3)
	le.PutUint64(b[112:], 1)
	seal(b)
	return b
}

func seal(b []byte) {
	const mod = uint64(0xffffffff)
	var a, s uint64
	for n := 8; n < len(b); n += 4 {
		a = (a + uint64(le.Uint32(b[n:]))) % mod
		s = (s + a) % mod
	}
	x := mod - (a+s)%mod
	y := mod - (a+x)%mod
	le.PutUint64(b, y<<32|x)
}

func TestSelectLatestValidCheckpoint(t *testing.T) {
	b := append(checkpoint(1), checkpoint(3)...)
	b = append(b, checkpoint(2)...)
	broken := checkpoint(4)
	broken[80] ^= 1
	b = append(b, broken...)
	c, err := Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if c.XID != 3 || c.Checkpoint != 1 {
		t.Fatalf("selected xid %d at %d", c.XID, c.Checkpoint)
	}
}

func TestRejectInvalidBlockZero(t *testing.T) {
	b := append(checkpoint(1), make([]byte, 3*4096)...)
	b[80] ^= 1
	if _, err := Open(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal(err)
	}
}

func TestDoNotFallBackWhenNewestCheckpointIsUnreadable(t *testing.T) {
	b := append(checkpoint(1), checkpoint(2)...)
	b = append(b, make([]byte, 2*4096)...)
	le.PutUint64(b[4096+184:], 100)
	le.PutUint64(b[4096+160:], 99)
	seal(b[4096:8192])
	if _, err := Open(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatalf("expected unresolved latest checkpoint, got %v", err)
	}
}

func FuzzContainer(f *testing.F) {
	f.Add(append(checkpoint(1), make([]byte, 3*4096)...))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1<<20 {
			return
		}
		_, _ = Open(bytes.NewReader(b))
	})
}

func TestObjectMapUsesRequestedTransaction(t *testing.T) {
	b := make([]byte, 5*4096)
	copy(b, checkpoint(7))
	le.PutUint64(b[40:], 5)
	le.PutUint32(b[104:], 0)
	le.PutUint64(b[160:], 1)
	le.PutUint64(b[184:], 1026)
	seal(b[:4096])
	omap := b[4096:8192]
	le.PutUint32(omap[24:], 0x4000000b)
	le.PutUint64(omap[48:], 2)
	seal(omap)
	node := b[8192:12288]
	le.PutUint32(node[24:], 0x40000002)
	le.PutUint32(node[28:], 11)
	le.PutUint16(node[32:], 7)
	le.PutUint32(node[36:], 2)
	le.PutUint16(node[42:], 8)
	for n, xid := range []uint64{5, 9} {
		le.PutUint16(node[56+n*4:], uint16(n*16))
		le.PutUint16(node[58+n*4:], uint16((n+1)*16))
		le.PutUint64(node[64+n*16:], 1026)
		le.PutUint64(node[72+n*16:], xid)
		value := node[4056-(n+1)*16:]
		le.PutUint32(value[4:], 4096)
		le.PutUint64(value[8:], uint64(3+n))
		sb := b[(3+n)*4096 : (4+n)*4096]
		copy(sb[32:], "APSB")
		le.PutUint32(sb[24:], 13)
		le.PutUint64(sb[8:], 1026)
		le.PutUint64(sb[16:], xid)
		copy(sb[704:], []string{"old", "future"}[n])
		seal(sb)
	}
	seal(node)
	c, err := Open(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Volumes) != 1 || c.Volumes[0].Name != "old" {
		t.Fatalf("did not select version at xid 7: %+v", c.Volumes)
	}
	// A tombstone at the selected transaction is not permission to use an
	// earlier/live or later/future mapping.
	le.PutUint32(node[4040:], 1)
	seal(node)
	if _, err := Open(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("accepted deleted mapping", err)
	}
}

func TestChecksumUsesEntireContainerBlock(t *testing.T) {
	const size = 16384
	b := make([]byte, size*4)
	copy(b, checkpoint(1))
	le.PutUint32(b[36:], size)
	le.PutUint32(b[104:], 0)
	seal(b[:size])
	if _, err := Open(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	b[size-1] ^= 1
	if _, err := Open(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("ignored checksum tail", err)
	}
}
