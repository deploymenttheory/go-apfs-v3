package diskimage

import (
	"bytes"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func udifFixture(t *testing.T, payload []byte, declaredSectors uint64) []byte {
	t.Helper()
	var compressed bytes.Buffer
	z := zlib.NewWriter(&compressed)
	if _, err := z.Write(payload); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	b := make([]byte, 244)
	be := binary.BigEndian
	copy(b, "mish")
	be.PutUint64(b[16:], declaredSectors)
	be.PutUint32(b[200:], 1)
	be.PutUint32(b[204:], 0x80000005)
	be.PutUint64(b[220:], declaredSectors)
	be.PutUint64(b[236:], uint64(compressed.Len()))
	plist := []byte(fmt.Sprintf(`<plist version="1.0"><dict><key>resource-fork</key><dict><key>blkx</key><array><dict><key>Data</key><data>%s</data></dict></array></dict></dict></plist>`, base64.StdEncoding.EncodeToString(b)))
	footer := make([]byte, 512)
	copy(footer, "koly")
	be.PutUint32(footer[4:], 4)
	be.PutUint32(footer[8:], 512)
	be.PutUint64(footer[32:], uint64(compressed.Len()))
	be.PutUint64(footer[216:], uint64(compressed.Len()))
	be.PutUint64(footer[224:], uint64(len(plist)))
	be.PutUint64(footer[492:], declaredSectors)
	out := append([]byte(nil), compressed.Bytes()...)
	out = append(out, plist...)
	return append(out, footer...)
}

func TestUDIFRandomAccessConcurrent(t *testing.T) {
	payload := make([]byte, 8192)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	b := udifFixture(t, payload, 16)
	u, err := openUDIF(bytes.NewReader(b), b[len(b)-512:])
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for n := 0; n < 16; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			p := make([]byte, 700)
			off := int64(n * 433)
			_, err := u.ReadAt(p, off)
			if err != nil || !bytes.Equal(p, payload[off:off+700]) {
				t.Errorf("offset %d: %v", off, err)
			}
		}(n)
	}
	wg.Wait()
	p := make([]byte, 512)
	if n, err := u.ReadAt(p, 8190); n != 2 || !errors.Is(err, io.EOF) {
		t.Fatal(n, err)
	}
}

func TestUDIFRejectsIncorrectDecodedSize(t *testing.T) {
	for _, length := range []int{511, 513} {
		b := udifFixture(t, make([]byte, length), 1)
		u, err := openUDIF(bytes.NewReader(b), b[len(b)-512:])
		if err != nil {
			t.Fatal(err)
		}
		if _, err := u.ReadAt(make([]byte, 1), 0); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatalf("decoded %d: %v", length, err)
		}
	}
}

func TestUDIFRejectsOversizedPlistBeforeAllocation(t *testing.T) {
	b := udifFixture(t, make([]byte, 512), 1)
	binary.BigEndian.PutUint64(b[len(b)-512+224:], ^uint64(0))
	if _, err := New(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal(err)
	}
}
