package apfs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	storagecrypto "github.com/deploymenttheory/go-apfs-v3/internal/crypto"
)

type mutationKeyBacking struct {
	*bytes.Reader
	reads, writes, closes int
}

func (s *mutationKeyBacking) ReadAt(b []byte, off int64) (int, error) {
	s.reads++
	return s.Reader.ReadAt(b, off)
}
func (s *mutationKeyBacking) WriteAt(b []byte, _ int64) (int, error) { s.writes++; return len(b), nil }
func (s *mutationKeyBacking) Close() error                           { s.closes++; return nil }

func TestMutationSourceKeyOwnerInvalidatesBorrowedViews(t *testing.T) {
	ciphertext := bytes.Repeat([]byte{0x55}, 512)
	backing := &mutationKeyBacking{Reader: bytes.NewReader(ciphertext)}
	x, err := storagecrypto.NewXTS(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	key := &volumeKeys{xts: x}
	owner := &MutationSource{source: backing, keys: map[[16]byte]*volumeKeys{{}: key}}
	borrowed := Volume{Encrypted: true, Flags: 8, keys: key, keysBorrowed: true}
	read := make([]byte, len(ciphertext))
	if _, err := owner.ReadAt(read, 0); err != nil || !bytes.Equal(read, ciphertext) {
		t.Fatal("authenticated source changed raw encrypted bytes", err)
	}
	if err := borrowed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := borrowed.access(); err != nil {
		t.Fatal("borrower closed the owner's keys", err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(borrowed.access(), fs.ErrClosed) {
		t.Fatal("borrowed keys survived owner closure")
	}
	if _, err := owner.ReadAt(read, 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("closed source read", err)
	}
	if _, err := owner.WriteAt(read, 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("closed source wrote", err)
	}
	if backing.writes != 0 || backing.closes != 0 {
		t.Fatal("key owner changed/closed its borrowed backing", backing.writes, backing.closes)
	}
	if _, err := backing.ReadAt(read, 0); err != nil {
		t.Fatal("backing was invalidated", err)
	}
}

func TestMutationAuthenticationChecksCancellationBeforeReading(t *testing.T) {
	backing := &mutationKeyBacking{Reader: bytes.NewReader(make([]byte, 4096))}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := UnlockMutation(ctx, backing); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if backing.reads != 0 || backing.writes != 0 || backing.closes != 0 {
		t.Fatal("cancelled authentication touched its source")
	}
}

func TestVolumeCredentialReportsDoNotSerializePasswordBytes(t *testing.T) {
	secret := []byte("public-password-serialization-sentinel")
	data, err := json.Marshal([]any{VolumeCredential{Password: secret}, PasswordChange{OldPassword: secret, NewPassword: secret}})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, secret) || bytes.Contains(data, []byte("Password")) {
		t.Fatal("password material was serialized")
	}
}

func TestMutationAdmissionRefusesAReaderOnlyEncryptedKeyWidth(t *testing.T) {
	x, err := storagecrypto.NewXTS(make([]byte, 64))
	if err != nil {
		t.Fatal(err)
	}
	volume := Volume{Encrypted: true, Flags: 8, rootType: 2, keys: &volumeKeys{xts: x, keyBytes: 64}}
	if err := admitMutationVolume(&volume); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal("unqualified encrypted writer key width admitted", err)
	}
}
