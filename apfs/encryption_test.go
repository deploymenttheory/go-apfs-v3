package apfs

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	storagecrypto "github.com/deploymenttheory/go-apfs-v3/internal/crypto"
)

func TestEncryptedExtentUnalignedConcurrentReadsAndClose(t *testing.T) {
	b, err := os.ReadFile("../acceptance/testdata/encryption/macos-27/cryptography.json")
	if err != nil {
		t.Fatal(err)
	}
	var reference struct {
		XTS []struct {
			Key, Plain, Ciphertext string
			Sector                 uint64
		}
	}
	if err := json.Unmarshal(b, &reference); err != nil {
		t.Fatal(err)
	}
	vector := reference.XTS[1]
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	x, err := storagecrypto.NewXTS(decode(vector.Key))
	if err != nil {
		t.Fatal(err)
	}
	keys := &volumeKeys{xts: x}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &encryptedSource{bytes.NewReader(decode(vector.Ciphertext)), keys, vector.Sector, ctx}
	want := decode(vector.Plain)
	var wg sync.WaitGroup
	for _, off := range []int64{0, 1, 15, 16, 17, 510, 511, 512, 513, 1023, 1024} {
		wg.Go(func() {
			b := make([]byte, 517)
			n, err := source.ReadAt(b, off)
			expected := want[off:min(off+int64(len(b)), int64(len(want)))]
			if !bytes.Equal(b[:n], expected) || (len(expected) < len(b) && !errors.Is(err, io.EOF)) || (len(expected) == len(b) && err != nil) {
				t.Errorf("offset %d: %d %v", off, n, err)
			}
		})
	}
	wg.Wait()
	cancel()
	if _, err := source.ReadAt(make([]byte, 1), 0); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	view := &Volume{keys: keys}
	if err := view.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := source.ReadAt(make([]byte, 1), 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatal(err)
	}
}

type damagedSource struct {
	block.Source
	offset int64
}

func (s damagedSource) ReadAt(p []byte, off int64) (int, error) {
	n, err := s.Source.ReadAt(p, off)
	if s.offset >= off && s.offset-off < int64(n) {
		p[s.offset-off] ^= 1
	}
	return n, err
}

func TestAuthenticatedKeyDoesNotHideCorruptEncryptedMetadata(t *testing.T) {
	image, err := diskimage.Open("../acceptance/testdata/encryption/macos-27/apfs.dmg")
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	var c *Container
	for _, p := range image.Partitions {
		if p.Type != diskimage.APFSType {
			continue
		}
		source, err := image.Partition(p.Index)
		if err != nil {
			t.Fatal(err)
		}
		c, err = Open(source)
		if err != nil {
			t.Fatal(err)
		}
	}
	if c == nil || len(c.Volumes) != 1 {
		t.Fatal("native APFS volume missing")
	}
	v := &c.Volumes[0]
	mapping, err := c.resolve(v.omap, v.root, c.XID)
	if err != nil || !mapping.encrypted {
		t.Fatal("native root is not encrypted", err)
	}
	c.source = damagedSource{c.source, int64(mapping.address)*int64(c.BlockSize) + 100}
	if unlocked, err := v.Unlock(context.Background(), []byte("apfs-v3-public-fixture")); unlocked != nil || !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("decrypted checksum failure became success or authentication error", err)
	}
	v.Flags &^= 8
	if _, err := v.Unlock(context.Background(), nil); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal("per-file key profile accepted", err)
	}
}
