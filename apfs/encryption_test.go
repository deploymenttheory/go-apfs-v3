package apfs

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	storagecrypto "github.com/deploymenttheory/go-apfs-v3/internal/crypto"
)

type cryptoVectors struct {
	XTS []struct {
		Name, Key, Plain, Ciphertext string
		Sector                       uint64
	}
	PBKDF2HmacSha256 []struct {
		Password, Salt, Key string
		Iterations          uint64
		Size                int
	}
	KeyWrap []struct {
		Name, KEK, Key, Wrapped string
	}
}

func publishedVectors(t *testing.T) cryptoVectors {
	t.Helper()
	b, err := os.ReadFile("testdata/crypto_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v cryptoVectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	if len(v.XTS) < 3 || len(v.PBKDF2HmacSha256) < 3 || len(v.KeyWrap) < 3 {
		t.Fatal("incomplete published vectors")
	}
	return v
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// xtsReference is an independent AES-XTS implementation over Go's AES block
// cipher. The published IEEE P1619 vectors qualify it on their 32-byte data
// units; the product's sector decryptor only accepts complete 512-byte sectors,
// so the qualified reference supplies full-sector ciphertext for it.
func xtsReference(t *testing.T, key []byte, sector uint64, unit int, src []byte, decrypt bool) []byte {
	t.Helper()
	data, err := aes.NewCipher(key[:len(key)/2])
	if err != nil {
		t.Fatal(err)
	}
	tweakCipher, err := aes.NewCipher(key[len(key)/2:])
	if err != nil {
		t.Fatal(err)
	}
	if len(src)%unit != 0 || unit%16 != 0 {
		t.Fatal("reference data unit", len(src), unit)
	}
	out := make([]byte, len(src))
	for base := 0; base < len(src); base += unit {
		var tweak [16]byte
		binary.LittleEndian.PutUint64(tweak[:], sector)
		tweakCipher.Encrypt(tweak[:], tweak[:])
		for off := base; off < base+unit; off += 16 {
			var block [16]byte
			for i := range block {
				block[i] = src[off+i] ^ tweak[i]
			}
			if decrypt {
				data.Decrypt(block[:], block[:])
			} else {
				data.Encrypt(block[:], block[:])
			}
			for i := range block {
				out[off+i] = block[i] ^ tweak[i]
			}
			var carry byte
			for i := range tweak {
				next := tweak[i] >> 7
				tweak[i] = tweak[i]<<1 | carry
				carry = next
			}
			tweak[0] ^= 0x87 * carry
		}
		sector++
	}
	return out
}

func TestPublishedCryptographyVectors(t *testing.T) {
	v := publishedVectors(t)
	ctx := context.Background()
	for _, tc := range v.XTS {
		t.Run(tc.Name, func(t *testing.T) {
			key, plain, ciphertext := unhex(t, tc.Key), unhex(t, tc.Plain), unhex(t, tc.Ciphertext)
			if got := xtsReference(t, key, tc.Sector, len(plain), plain, false); !bytes.Equal(got, ciphertext) {
				t.Fatalf("reference encryption %x", got)
			}
			if got := xtsReference(t, key, tc.Sector, len(plain), ciphertext, true); !bytes.Equal(got, plain) {
				t.Fatalf("reference decryption %x", got)
			}
			// The qualified reference then checks the product over whole sectors,
			// across a sector boundary and with both supported key sizes.
			for _, size := range []int{32, 64} {
				wide := bytes.Repeat(key, 2)[:size]
				text := bytes.Repeat(plain, 1024/len(plain))
				encrypted := xtsReference(t, wide, tc.Sector, 512, text, false)
				x, err := storagecrypto.NewXTS(wide)
				if err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(encrypted))
				if err := x.Decrypt(got, encrypted, tc.Sector); err != nil || !bytes.Equal(got, text) {
					t.Fatal("product sector decryption disagrees with the qualified reference", size, err)
				}
				if err := x.Encrypt(got, text, tc.Sector); err != nil || !bytes.Equal(got, encrypted) {
					t.Fatal("product sector encryption disagrees with the qualified reference", size, err)
				}
			}
		})
	}
	for i, tc := range v.PBKDF2HmacSha256 {
		want := unhex(t, tc.Key)
		got, err := storagecrypto.PBKDF2(ctx, sha256.New, []byte(tc.Password), []byte(tc.Salt), tc.Iterations, tc.Size)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("PBKDF2-HMAC-SHA256 vector %d: %x %v", i, got, err)
		}
		standard, err := pbkdf2.Key(sha256.New, tc.Password, []byte(tc.Salt), int(tc.Iterations), tc.Size)
		if err != nil || !bytes.Equal(standard, want) {
			t.Fatalf("standard library disagrees with vector %d: %v", i, err)
		}
	}
	for _, tc := range v.KeyWrap {
		t.Run(tc.Name, func(t *testing.T) {
			kek, key, wrapped := unhex(t, tc.KEK), unhex(t, tc.Key), unhex(t, tc.Wrapped)
			got, err := storagecrypto.Unwrap(kek, wrapped)
			if err != nil || !bytes.Equal(got, key) {
				t.Fatalf("unwrap %x %v", got, err)
			}
			if got, err := storagecrypto.Wrap(kek, key); err != nil || !bytes.Equal(got, wrapped) {
				t.Fatalf("wrap disagrees with published vector: %x %v", got, err)
			}
			damaged := bytes.Clone(wrapped)
			damaged[len(damaged)-1] ^= 1
			if _, err := storagecrypto.Unwrap(kek, damaged); !errors.Is(err, storagecrypto.ErrIntegrity) {
				t.Fatal("damaged wrapped key admitted", err)
			}
			if _, err := storagecrypto.Unwrap(bytes.Repeat(kek, 2)[:len(kek)+8], wrapped); !errors.Is(err, storagecrypto.ErrInvalid) {
				t.Fatal("unsupported KEK size admitted", err)
			}
		})
	}
}

func TestEncryptedExtentUnalignedConcurrentReadsAndClose(t *testing.T) {
	vector := publishedVectors(t).XTS[1]
	key := unhex(t, vector.Key)
	want := make([]byte, 1536)
	for i := range want {
		want[i] = byte(i*7 + i/512)
	}
	ciphertext := xtsReference(t, key, vector.Sector, 512, want, false)
	x, err := storagecrypto.NewXTS(key)
	if err != nil {
		t.Fatal(err)
	}
	keys := &volumeKeys{xts: x}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	source := &encryptedSource{bytes.NewReader(ciphertext), keys, vector.Sector, ctx}
	var wg sync.WaitGroup
	for _, off := range []int64{0, 1, 15, 16, 17, 510, 511, 512, 513, 1023, 1024, 1535, 1536} {
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
	if _, err := source.ReadAt(make([]byte, 1), -1); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
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

func TestInProgressEncryptionIsInspectableButRefusesFilesystemAccess(t *testing.T) {
	for _, flags := range []uint64{1, 8} {
		b := make([]byte, 4096)
		le.PutUint64(b[264:], flags)
		// Other admission fields are ordinary. A conversion may start before
		// the historical ENC_ROLLED bit is set; the state OID must suffice.
		le.PutUint32(b[116:], 2)
		le.PutUint64(b[976:], 123)
		v := (&Container{}).volume(b, 1)
		if v.EncryptionRollingStateOID != 123 || v.IncompatibleFeatures != 0 {
			t.Fatal("encryption state must remain inspectable")
		}
		ctx := context.Background()
		if _, err := v.Stat(ctx, v.Root()); !errors.Is(err, filesystem.ErrUnsupported) {
			t.Fatal("unfinished conversion exposed filesystem metadata", err)
		}
		if err := v.ListSnapshots(ctx, func(Snapshot) error { return nil }); !errors.Is(err, filesystem.ErrUnsupported) {
			t.Fatal("unfinished conversion exposed retained history", err)
		}
		if v.Encrypted {
			// The empty container has no backing source. Rejection must precede
			// keybag I/O and password derivation, not just eventual root decoding.
			if unlocked, err := v.Unlock(ctx, nil); unlocked != nil || !errors.Is(err, filesystem.ErrUnsupported) {
				t.Fatal("unfinished conversion attempted authentication", err)
			}
		}
		if err := admitMutationVolume(&v); !errors.Is(err, filesystem.ErrUnsupported) {
			t.Fatal("unfinished conversion admitted mutation", err)
		}
	}
}
