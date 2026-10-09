package apfs

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func testDER(tag byte, b []byte) []byte {
	prefix := []byte{tag, byte(len(b))}
	if len(b) >= 128 {
		prefix = []byte{tag, 0x82, byte(len(b) >> 8), byte(len(b))}
		if len(b) < 256 {
			prefix = []byte{tag, 0x81, byte(len(b))}
		}
	}
	return append(prefix, b...)
}

func testKeyRecord(iterations uint64, flags uint32) []byte {
	info := make([]byte, 8)
	le.PutUint32(info, flags)
	var b []byte
	for _, field := range []struct {
		tag  byte
		data []byte
	}{{0x80, []byte{0}}, {0x81, make([]byte, 16)}, {0x82, info}, {0x83, make([]byte, 40)}} {
		b = append(b, testDER(field.tag, field.data)...)
	}
	var integer [8]byte
	binary.BigEndian.PutUint64(integer[:], iterations)
	n := bytes.TrimLeft(integer[:], "\x00")
	if len(n) == 0 {
		n = []byte{0}
	} else if n[0]&128 != 0 {
		n = append([]byte{0}, n...)
	}
	b = append(b, testDER(0x84, n)...)
	b = append(b, testDER(0x85, make([]byte, 16))...)
	b = testDER(0xa3, b)
	seed := append([]byte{1, 0x16, 0x20, 0x17, 0x15, 5}, make([]byte, 8)...)
	key := sha256.Sum256(seed)
	m := hmac.New(sha256.New, key[:])
	_, _ = m.Write(b)
	outer := testDER(0x80, []byte{0})
	outer = append(outer, testDER(0x81, m.Sum(nil))...)
	outer = append(outer, testDER(0x82, make([]byte, 8))...)
	return testDER(0x30, append(outer, b...))
}

func TestKeyRecordIntegrityAndWorkLimits(t *testing.T) {
	valid := testKeyRecord(100_000, 0)
	if _, err := parseKeyRecord(valid, true); err != nil {
		t.Fatal(err)
	}
	for i := range valid {
		damaged := bytes.Clone(valid)
		damaged[i] ^= 1
		if _, err := parseKeyRecord(damaged, true); err == nil || errors.Is(err, filesystem.ErrAuthentication) {
			t.Fatal("damaged record was accepted or called a bad password", i, err)
		}
	}
	for _, tc := range []struct {
		iterations uint64
		flags      uint32
		want       error
	}{
		{0, 0, filesystem.ErrCorrupt}, {maxPasswordIterations + 1, 0, filesystem.ErrLimit},
		{100, 0x80, filesystem.ErrUnsupported},
		{100, 2, filesystem.ErrUnsupported},
	} {
		if _, err := parseKeyRecord(testKeyRecord(tc.iterations, tc.flags), true); !errors.Is(err, tc.want) {
			t.Fatal(tc, err)
		}
	}
	if _, err := parseKeyRecord(append(bytes.Clone(valid), 0), true); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("trailing bytes", err)
	}
}

func TestDERLengthsAreBigEndianAndBounded(t *testing.T) {
	data := testDER(0x83, make([]byte, 300))
	v, tail, err := takeDER(data, 0x83)
	if err != nil || len(v) != 300 || len(tail) != 0 {
		t.Fatal("multi-byte big-endian DER length", err)
	}
	for _, bad := range [][]byte{{0x83, 0x80}, {0x83, 0x81, 0x7f}, {0x83, 0x82, 0, 0x80}, {0x83, 0x84, 0xff, 0xff, 0xff, 0xff}, {0x83, 3, 0}} {
		if _, _, err := takeDER(bad, 0x83); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatal("invalid DER admitted", bad, err)
		}
	}
}

func TestKeybagExtentAndEntryBounds(t *testing.T) {
	b := make([]byte, 4096)
	le.PutUint32(b[24:], 0x6b657973)
	le.PutUint16(b[32:], 2)
	le.PutUint16(b[34:], 1)
	le.PutUint32(b[36:], 48)
	le.PutUint16(b[64:], 3)
	le.PutUint16(b[66:], 8)
	seal(b)
	c := &Container{source: bytes.NewReader(b), BlockSize: 4096, BlockCount: 1}
	if _, err := c.keybag(context.Background(), 0, 1, [16]byte{}, 0x6b657973); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func([]byte){
		func(b []byte) { le.PutUint16(b[66:], 4000) },
		func(b []byte) { le.PutUint32(b[36:], 47) },
		func(b []byte) { le.PutUint32(b[36:], 4096) },
		func(b []byte) { le.PutUint16(b[34:], 2) },
	} {
		damaged := bytes.Clone(b)
		mutate(damaged)
		seal(damaged)
		c.source = bytes.NewReader(damaged)
		if _, err := c.keybag(context.Background(), 0, 1, [16]byte{}, 0x6b657973); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatal(err)
		}
	}
	c.BlockCount = 1 << 40
	if _, err := c.keybag(context.Background(), 0, 1<<30, [16]byte{}, 0x6b657973); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal("allocation budget", err)
	}
}

func FuzzKeyRecord(f *testing.F) {
	f.Add(testKeyRecord(100_000, 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= 65536 {
			_, _ = parseKeyRecord(b, true)
		}
	})
}
