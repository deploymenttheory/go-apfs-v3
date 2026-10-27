package imageedit_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func TestCompletedVolumeConversionsComposeWithEditsAndPasswordChanges(t *testing.T) {
	ctx := context.Background()
	source := fixture(t, "APFS")
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	password, replacement := []byte("public-conversion-password"), []byte("public-replacement-password")
	output := filepath.Join(t.TempDir(), "converted.dmg")
	var retained *imageedit.Editor
	r, err := imageedit.Edit(ctx, source, output, imageedit.Options{Time: clock}, func(e *imageedit.Editor) error {
		retained = e
		if _, err := e.ConvertVolumeEncryption(apfs.EncryptionConversion{Encrypt: true, Password: password}); err != nil {
			return err
		}
		if _, err := e.Apply([]imageedit.Change{{Path: "/file", Data: bytes.NewReader([]byte("edited after conversion"))}}); err != nil {
			return err
		}
		_, err := e.ChangeVolumePassword(apfs.PasswordChange{OldPassword: password, NewPassword: replacement})
		return err
	})
	if err != nil || r.VolumeEncryption == nil || !r.VolumeEncryption.Completed || !r.VolumeEncryption.Encrypted {
		t.Fatal("completed encryption transaction", r, err)
	}
	if _, err := retained.ConvertVolumeEncryption(apfs.EncryptionConversion{}); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("expired editor retained keys", err)
	}
	plain := filepath.Join(t.TempDir(), "decrypted.dmg")
	r, err = imageedit.ConvertVolumeEncryption(ctx, output, plain, imageedit.Options{Time: clock, VolumePassword: replacement}, apfs.EncryptionConversion{})
	if err != nil || r.VolumeEncryption == nil || !r.VolumeEncryption.Completed || r.VolumeEncryption.Encrypted {
		t.Fatal("completed decryption", r, err)
	}
	if _, err := imageedit.Apply(ctx, plain, filepath.Join(t.TempDir(), "edited.dmg"), imageedit.Options{Time: clock}, []imageedit.Change{{Path: "/file", Mode: "0700"}}); err != nil {
		t.Fatal("plaintext output requires no inner password", err)
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("conversion changed source", err)
	}
}

func TestFailedVolumeConversionsNeverPublishPartialTransactions(t *testing.T) {
	ctx := context.Background()
	source := fixture(t, "APFS")
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, ignoreFailure := range []bool{false, true} {
		root := t.TempDir()
		output := filepath.Join(root, "incomplete.dmg")
		_, err := imageedit.Edit(ctx, source, output, imageedit.Options{Time: clock}, func(e *imageedit.Editor) error {
			if _, err := e.ConvertVolumeEncryption(apfs.EncryptionConversion{Encrypt: true, Password: []byte("public-failure-password")}); err != nil {
				return err
			}
			if ignoreFailure {
				_, _ = e.ConvertVolumeEncryption(apfs.EncryptionConversion{Encrypt: true, Password: []byte("invalid second encryption")})
				return nil
			}
			return io.ErrUnexpectedEOF
		})
		if err == nil {
			t.Fatal("failed transaction succeeded")
		}
		if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
			t.Fatal("failed conversion left output or publication scratch", entries, err)
		}
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("failed conversion changed source", err)
	}
}
