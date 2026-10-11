package acceptance_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type nativeEncryption struct {
	Password                string   `json:"password"`
	RejectedPasswords       []string `json:"rejectedPasswords"`
	LockedBefore            bool     `json:"lockedBefore"`
	LockedAfterFailures     bool     `json:"lockedAfterFailures"`
	UnlockedReadOnly        bool     `json:"unlockedReadOnly"`
	LockedObservation       string   `json:"lockedObservation"`
	LockedObservationSHA256 string   `json:"lockedObservationSHA256"`
}

// Passwords and expected bytes come from Apple-created volumes. The same file
// comparison used for plain volumes covers decrypted trees, streams, attributes,
// resource forks, compression, clone modifications and sparse ranges.
func TestNativeEncryptedReading(t *testing.T) {
	t.Parallel()
	testFileCorpus(t, "file-encryption", "APFS_NATIVE_ENCRYPTION", "testdata/encryption", 108, nil)
}

func unlockForReplay(t *testing.T, reader filesystem.Reader, native *nativeEncryption, expected observation, dir string) filesystem.Reader {
	t.Helper()
	v, ok := reader.(*apfs.Volume)
	if !ok || !v.Encrypted || native == nil || !native.LockedBefore || !native.LockedAfterFailures || !native.UnlockedReadOnly || len(native.RejectedPasswords) == 0 {
		t.Fatal("missing native encrypted-volume evidence")
	}
	if v.UUID != expected.UUID || v.Name != expected.Name || v.CaseSensitive != expected.CaseSensitive {
		t.Fatal("encrypted volume identity differs from native observation")
	}
	verifyDigest(t, dir, native.LockedObservation, native.LockedObservationSHA256)
	ctx := context.Background()
	if _, err := v.Stat(ctx, v.Root()); !errors.Is(err, filesystem.ErrAuthentication) {
		t.Fatal("locked metadata read", err)
	}
	for _, password := range native.RejectedPasswords {
		if u, err := v.Unlock(ctx, []byte(password)); u != nil || !errors.Is(err, filesystem.ErrAuthentication) {
			t.Fatal("native-rejected password accepted", err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if u, err := v.Unlock(cancelled, []byte(native.Password)); u != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("unlock ignored cancellation", err)
	}
	password := []byte(native.Password)
	u, err := v.Unlock(ctx, password)
	if err != nil {
		t.Fatal("native-accepted password rejected", err)
	}
	if !bytes.Equal(password, []byte(native.Password)) {
		t.Fatal("Unlock changed caller's password")
	}
	clear(password) // The unlocked view must not borrow credential memory.
	t.Cleanup(func() { _ = u.Close() })
	if _, err := v.Stat(ctx, v.Root()); !errors.Is(err, filesystem.ErrAuthentication) {
		t.Fatal("Unlock changed original locked view", err)
	}
	independent, err := v.Unlock(ctx, []byte(native.Password))
	if err != nil {
		t.Fatal(err)
	}
	id, err := filesystem.Lookup(ctx, independent, "Fixture/example.txt")
	if err != nil {
		t.Fatal(err)
	}
	value, err := independent.OpenData(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	inline, err := independent.OpenAttribute(ctx, id, "org.go-apfs.binary")
	if err != nil {
		t.Fatal(err)
	}
	defer inline.Close()
	compressedID, err := filesystem.Lookup(ctx, independent, "Fixture/compressed")
	if err != nil {
		t.Fatal(err)
	}
	compressed, err := independent.OpenData(ctx, compressedID)
	if err != nil {
		t.Fatal(err)
	}
	defer compressed.Close()
	// Prime a decoder cache before closing its owning unlocked view.
	if _, err := compressed.ReadAt(make([]byte, 1), 0); err != nil {
		t.Fatal(err)
	}
	if err := independent.Close(); err != nil {
		t.Fatal(err)
	}
	if err := independent.Close(); err != nil {
		t.Fatal(err)
	}
	for _, f := range []filesystem.Value{value, inline, compressed} {
		if _, err := f.ReadAt(make([]byte, 1), 0); !errors.Is(err, fs.ErrClosed) {
			t.Fatal("borrowed value survived view close", err)
		}
	}
	if _, err := independent.Stat(ctx, independent.Root()); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("closed view remained readable", err)
	}
	return u
}
