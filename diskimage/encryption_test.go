package diskimage

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Structural fixture only: ciphertext is deliberately not a valid disk. Native
// image/password success belongs to the independent acceptance corpus.
func encryptedHeader() []byte {
	b := make([]byte, 1536)
	be := binary.BigEndian
	copy(b, "encrcdsa")
	for offset, value := range map[int]uint32{8: 2, 12: 16, 16: 5, 20: 0x80000001, 24: 128, 28: 91, 32: 160, 52: 512, 72: 1, 76: 1} {
		be.PutUint32(b[offset:], value)
	}
	be.PutUint64(b[56:], 512)
	be.PutUint64(b[64:], 1024)
	be.PutUint64(b[80:], 128)
	be.PutUint64(b[88:], 152)
	r := b[128:]
	for offset, value := range map[int]uint32{0: 103, 8: 1, 12: 20, 48: 8, 84: 192, 88: 0x80000001, 92: 7, 96: 6, 100: 48} {
		be.PutUint32(r[offset:], value)
	}
	return b
}

func TestEncryptedImageHeaderBoundsAndAdmission(t *testing.T) {
	if e, records, err := readEnvelope(bytes.NewReader(encryptedHeader())); err != nil || e == nil || len(records) != 1 {
		t.Fatal(err)
	}
	be := binary.BigEndian
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
		want   error
	}{
		{"version", 8, 3, filesystem.ErrUnsupported}, {"cipher", 20, 1, filesystem.ErrUnsupported},
		{"block budget", 52, 1 << 30, filesystem.ErrUnsupported}, {"key table budget", 72, 65, filesystem.ErrLimit},
		{"key record too short", 92, 100, filesystem.ErrCorrupt}, {"key record too large", 92, 4097, filesystem.ErrCorrupt},
		{"zero iterations", 128 + 8, 0, filesystem.ErrCorrupt}, {"iteration budget", 128 + 8, maxImagePasswordIterations + 1, filesystem.ErrLimit},
		{"salt bounds", 128 + 12, 33, filesystem.ErrCorrupt}, {"IV bounds", 128 + 48, 33, filesystem.ErrCorrupt},
		{"wrapped size", 128 + 100, 40, filesystem.ErrCorrupt}, {"unknown KDF", 128, 104, filesystem.ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := encryptedHeader()
			be.PutUint32(b[tc.offset:], tc.value)
			if _, _, err := readEnvelope(bytes.NewReader(b)); !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
		})
	}
	for _, offset := range []int{56, 64, 80, 88} {
		b := encryptedHeader()
		be.PutUint64(b[offset:], ^uint64(0))
		if _, _, err := readEnvelope(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatal("overflow", offset, err)
		}
	}
	b := encryptedHeader()
	be.PutUint64(b[80:], 76)
	if _, _, err := readEnvelope(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("key record overlaps table", err)
	}
	b = make([]byte, 512)
	copy(b[len(b)-8:], "cdsaencr")
	if _, err := New(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal("version 1 became plain image", err)
	}
}

func TestEncryptedImageRecordOverlapAndAggregateWork(t *testing.T) {
	be := binary.BigEndian
	b := encryptedHeader()
	be.PutUint32(b[72:], 2)
	copy(b[96:116], b[76:96])
	if _, _, err := readEnvelope(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("overlapping key records", err)
	}
	be.PutUint64(b[100:], 400)
	copy(b[400:], b[128:280])
	be.PutUint32(b[136:], 6_000_000)
	be.PutUint32(b[408:], 6_000_000)
	if _, _, err := readEnvelope(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal("aggregate password work", err)
	}
}

func TestEncryptedImageConcurrentUnalignedReadsAndTruncation(t *testing.T) {
	b, err := os.ReadFile("../acceptance/testdata/encrypted-dmg/macos-27/hfsplus-raw-aes256.dmg")
	if err != nil {
		t.Fatal(err)
	}
	e, records, err := readEnvelope(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if err := e.unlock(context.Background(), []byte("public-dmg-password"), records); err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	// Native file/metadata hashes independently qualify decrypted bytes. Here
	// compare arbitrary ReaderAt ranges against a whole aligned read, including
	// the last byte, to isolate the source's offset and EOF contract.
	want := make([]byte, e.Size())
	if _, err := e.ReadAt(want, 0); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for _, off := range []int64{0, 1, 15, 16, 511, 512, 513, 4095, e.Size() - 513, e.Size() - 1, e.Size()} {
		wg.Go(func() {
			p := make([]byte, 517)
			n, err := e.ReadAt(p, off)
			expected := want[off:min(off+517, e.Size())]
			if !bytes.Equal(p[:n], expected) || (len(expected) < len(p) && !errors.Is(err, io.EOF)) || (len(expected) == len(p) && err != nil) {
				t.Errorf("offset %d: %d %v", off, n, err)
			}
		})
	}
	wg.Wait()
	if _, err := e.ReadAt(make([]byte, 1), -1); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
	if _, _, err := readEnvelope(bytes.NewReader(b[:len(b)-1])); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("truncated final encrypted block", err)
	}
}

func FuzzEncryptedImageHeader(f *testing.F) {
	f.Add(encryptedHeader())
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) <= 1<<20 {
			_, _, _ = readEnvelope(bytes.NewReader(b))
		}
	})
}
