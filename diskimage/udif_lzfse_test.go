package diskimage

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// lzfseStoredStream uses the reference format's uncompressed block and explicit
// end marker. All payload bytes are synthetic; no firmware is embedded here.
func lzfseStoredStream(payload []byte) []byte {
	stream := make([]byte, 8, len(payload)+12)
	copy(stream, "bvx-")
	binary.LittleEndian.PutUint32(stream[4:], uint32(len(payload)))
	stream = append(stream, payload...)
	return append(stream, "bvx$"...)
}

func lzfseUDIF(stored []byte, sectors uint64) []byte {
	chunk := make([]byte, 244)
	be := binary.BigEndian
	copy(chunk, "mish")
	be.PutUint64(chunk[16:], sectors)
	be.PutUint32(chunk[200:], 1)
	be.PutUint32(chunk[204:], 0x80000007)
	be.PutUint64(chunk[220:], sectors)
	be.PutUint64(chunk[236:], uint64(len(stored)))
	plist := []byte(fmt.Sprintf(`<plist version="1.0"><dict><key>resource-fork</key><dict><key>blkx</key><array><dict><key>Data</key><data>%s</data></dict></array></dict></dict></plist>`, base64.StdEncoding.EncodeToString(chunk)))
	footer := make([]byte, 512)
	copy(footer, "koly")
	be.PutUint32(footer[4:], 4)
	be.PutUint32(footer[8:], 512)
	be.PutUint64(footer[32:], uint64(len(stored)))
	be.PutUint64(footer[216:], uint64(len(stored)))
	be.PutUint64(footer[224:], uint64(len(plist)))
	be.PutUint64(footer[492:], sectors)
	out := append([]byte(nil), stored...)
	out = append(out, plist...)
	return append(out, footer...)
}

func TestUDIFLZFSEReadsAdvertisedDiskBytes(t *testing.T) {
	payload := bytes.Repeat([]byte("LZFSE disk data!"), 64)
	if len(payload) != 1024 {
		t.Fatal("invalid synthetic sector payload", len(payload))
	}
	encoded := lzfseUDIF(lzfseStoredStream(payload), 2)
	image, err := New(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := image.Close(); err != nil {
			t.Error(err)
		}
	})
	got := make([]byte, 700)
	if n, err := image.ReadAt(got, 123); err != nil || n != len(got) || !bytes.Equal(got, payload[123:823]) {
		t.Fatal("decoded LZFSE disk bytes differ", n, err)
	}
}

func TestUDIFLZFSERejectsInvalidStreamsWithoutCachingOutput(t *testing.T) {
	payload := bytes.Repeat([]byte{0x37}, 512)
	valid := lzfseStoredStream(payload)
	for name, stored := range map[string][]byte{
		"truncated header":   valid[:7],
		"truncated payload":  valid[:400],
		"missing end marker": valid[:len(valid)-4],
		"unknown block":      []byte("bvx?bvx$"),
		"trailing byte":      append(bytes.Clone(valid), 0),
		"second stream":      append(bytes.Clone(valid), valid...),
		"decoded too short":  lzfseStoredStream(payload[:511]),
		"decoded too long":   lzfseStoredStream(append(bytes.Clone(payload), 1)),
	} {
		t.Run(name, func(t *testing.T) {
			encoded := lzfseUDIF(stored, 1)
			u, err := openUDIF(bytes.NewReader(encoded), encoded[len(encoded)-512:])
			if err != nil {
				t.Fatal(err)
			}
			out := bytes.Repeat([]byte{0x55}, 20)
			if n, err := u.ReadAt(out, 8); n != 0 || !errors.Is(err, filesystem.ErrCorrupt) {
				t.Fatal("invalid LZFSE stream was admitted", n, err)
			}
			if !bytes.Equal(out, bytes.Repeat([]byte{0x55}, 20)) || len(u.cache) != 0 || u.cacheSize != 0 {
				t.Fatal("failed stream exposed or cached partial output")
			}
		})
	}
}

func TestUDIFLZFSEKeepsChunkAndSourceBounds(t *testing.T) {
	encoded := lzfseUDIF(lzfseStoredStream(make([]byte, 512)), maxChunk/512+1)
	if _, err := New(bytes.NewReader(encoded)); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal("oversized decoded LZFSE chunk was admitted", err)
	}
	// A section reader is the public consumer's stored-ZIP-member view. Prefix
	// and suffix bytes must stay outside the borrowed image's source range.
	encoded = lzfseUDIF(lzfseStoredStream(make([]byte, 512)), 1)
	backing := append(bytes.Repeat([]byte{0x83}, 71), encoded...)
	backing = append(backing, bytes.Repeat([]byte{0x91}, 59)...)
	image, err := New(io.NewSectionReader(bytes.NewReader(backing), 71, int64(len(encoded))))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = image.Close() })
	out := make([]byte, 25)
	if n, err := image.ReadAt(out, 500); n != 12 || !errors.Is(err, io.EOF) || !bytes.Equal(out[:12], make([]byte, 12)) {
		t.Fatal("image read escaped its declared disk", n, err)
	}
}

func TestUDIFLZFSEReadsReferenceCompressedBlocks(t *testing.T) {
	// Apple's pinned portable C encoder produced this bvx2 vector from the
	// formula below; testdata/lzfse-compressed.json records original digests.
	stored, err := os.ReadFile("testdata/lzfse-compressed.lzfse")
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 16384)
	for i := range payload {
		payload[i] = byte((i*17 + (i/127)%29) % 251)
	}
	encoded := lzfseUDIF(stored, uint64(len(payload)/512))
	image, err := New(bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = image.Close() })
	out := make([]byte, len(payload))
	if n, err := image.ReadAt(out, 0); n != len(out) || err != nil || !bytes.Equal(out, payload) {
		t.Fatal("reference bvx2 stream differs from synthetic input", n, err)
	}
	for _, length := range []int{10, len(stored) - 5} {
		encoded := lzfseUDIF(stored[:length], uint64(len(payload)/512))
		if image, err := New(bytes.NewReader(encoded)); !errors.Is(err, filesystem.ErrCorrupt) {
			if image != nil {
				_ = image.Close()
			}
			t.Fatal("truncated reference stream was admitted", length, err)
		}
	}
}
