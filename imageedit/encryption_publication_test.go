package imageedit_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

// Interrupt after final encryption has written real ciphertext into the private
// publication file, rather than merely cancelling before decryption or edits.
type interruptEncryptedOutput struct {
	context.Context
	directory string
}

func (c interruptEncryptedOutput) Err() error {
	paths, _ := filepath.Glob(filepath.Join(c.directory, ".apfs-pack-*"))
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && info.Size() > 122368 {
			os.Exit(17)
		}
	}
	return c.Context.Err()
}

func TestInterruptedEncryptedImagePublicationKeepsPlaintextPrivate(t *testing.T) {
	const password = "public-interruption-password"
	if os.Getenv("APFS_ENCRYPTED_EDIT_INTERRUPT_CHILD") == "1" {
		ctx := interruptEncryptedOutput{context.Background(), os.Getenv("APFS_ENCRYPTED_EDIT_SCRATCH")}
		_, _ = imageedit.Apply(ctx, os.Getenv("APFS_ENCRYPTED_EDIT_SOURCE"), os.Getenv("APFS_ENCRYPTED_EDIT_DESTINATION"), imageedit.Options{Time: clock, Format: "UDRO", ImagePassword: []byte(password)}, []imageedit.Change{{Path: "/file", Mode: "0751"}})
		os.Exit(99)
	}
	source := encryptedFixture(t, fixture(t, "APFS"), 256, []byte(password))
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	destination := filepath.Join(root, "output.dmg")
	command := exec.Command(os.Args[0], "-test.run=^TestInterruptedEncryptedImagePublicationKeepsPlaintextPrivate$")
	command.Env = append(os.Environ(), "APFS_ENCRYPTED_EDIT_INTERRUPT_CHILD=1", "APFS_ENCRYPTED_EDIT_SOURCE="+source, "APFS_ENCRYPTED_EDIT_DESTINATION="+destination, "APFS_ENCRYPTED_EDIT_SCRATCH="+root, "TMPDIR="+root, "TMP="+root, "TEMP="+root)
	var child *exec.ExitError
	if err := command.Run(); !errors.As(err, &child) || child.ExitCode() != 17 {
		t.Fatal("child did not reach encrypted publication", err)
	}
	if _, err := os.Stat(destination); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("incomplete image published", err)
	}
	staging, _ := filepath.Glob(filepath.Join(root, ".apfs-edit-disk-*"))
	publication, _ := filepath.Glob(filepath.Join(root, ".apfs-pack-*"))
	if len(staging) != 1 || len(publication) != 1 {
		t.Fatal("missing interrupted private files", staging, publication)
	}
	for _, path := range append(staging, publication...) {
		info, err := os.Stat(path)
		// Windows protection comes from the inherited temporary-directory ACL,
		// which os.FileMode does not represent.
		if err != nil || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			t.Fatal("private scratch exposes bytes", path, info, err)
		}
	}
	header, err := os.ReadFile(publication[0])
	if err != nil || len(header) < 122368 || string(header[:8]) != "encrcdsa" {
		t.Fatal("interruption did not retain ciphertext publication", err)
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("interruption changed encrypted source", err)
	}
}
