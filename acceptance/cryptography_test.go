package acceptance_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"

	storagecrypto "github.com/deploymenttheory/go-apfs-v3/internal/crypto"
)

// Compare with Apple CommonCrypto on each required macOS release. These are
// public primitive vectors, independent of the Go implementation and the
// encrypted filesystem comparisons. AES-256-XTS here is not volume evidence.
func compareNativeCrypto(t *testing.T, dir, name, digest string) {
	t.Helper()
	verifyDigest(t, dir, name, digest)
	var native struct {
		Schema int
		API    string
		XTS    []struct {
			Key, Plain, Ciphertext string
			Sector                 uint64
		}
		PasswordKeys []struct {
			Password, Salt, Key string
			Iterations          uint64
		}
		WrappedKeys []struct {
			Key, Plain, Wrapped, Damaged string
			NativeRejection              int
		}
	}
	decodeEvidence(t, filepath.Join(dir, name), &native)
	if native.Schema != 1 || native.API != "Apple CommonCrypto" || len(native.XTS) != 6 || len(native.PasswordKeys) != 3 || len(native.WrappedKeys) != 4 {
		t.Fatal("incomplete CommonCrypto evidence")
	}
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, v := range native.XTS {
		x, err := storagecrypto.NewXTS(decode(v.Key))
		if err != nil {
			t.Fatal(err)
		}
		b := decode(v.Ciphertext)
		if err := x.Decrypt(b, b, v.Sector); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b, decode(v.Plain)) {
			t.Fatal("XTS differs from CommonCrypto", len(v.Key)*4, v.Sector)
		}
		// A separately requested second sector must use the next data-unit
		// number, not continue the first sector's GF multiplication sequence.
		ciphertext := decode(v.Ciphertext)
		out := make([]byte, 512)
		if err := x.Decrypt(out, ciphertext[512:], v.Sector+1); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(out, b[512:]) {
			t.Fatal("XTS sector boundaries differ")
		}
	}
	for _, v := range native.PasswordKeys {
		got, err := storagecrypto.PasswordKey(context.Background(), decode(v.Password), decode(v.Salt), v.Iterations)
		if err != nil || !bytes.Equal(got[:], decode(v.Key)) {
			t.Fatal("PBKDF2 differs from CommonCrypto", err)
		}
	}
	for _, v := range native.WrappedKeys {
		key := decode(v.Key)
		got, err := storagecrypto.Unwrap(key, decode(v.Wrapped))
		if err != nil || !bytes.Equal(got, decode(v.Plain)) {
			t.Fatal("AES key unwrap differs from CommonCrypto", err)
		}
		if v.NativeRejection == 0 {
			t.Fatal("native damaged key unexpectedly accepted")
		}
		if got, err := storagecrypto.Unwrap(key, decode(v.Damaged)); got != nil || !errors.Is(err, storagecrypto.ErrIntegrity) {
			t.Fatal("damaged wrapped key accepted", err)
		}
	}
}
