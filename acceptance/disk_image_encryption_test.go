package acceptance_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type nativeDiskImage struct {
	Password               string   `json:"password"`
	RejectedPasswords      []string `json:"rejectedPasswords"`
	KeyBits                uint32   `json:"keyBits"`
	NativeFormat           string   `json:"nativeFormat"`
	UnlockedReadOnly       bool     `json:"unlockedReadOnly"`
	ImageObservation       string   `json:"imageObservation"`
	ImageObservationSHA256 string   `json:"imageObservationSHA256"`
}

// Image encryption surrounds either filesystem and, in one case, another
// independently encrypted APFS volume. File comparisons use native mounted
// results; no image or expected bytes are produced by Go.
func TestNativeEncryptedDiskImages(t *testing.T) {
	testFileCorpus(t, "disk-image-encryption", "APFS_NATIVE_ENCRYPTED_DMG", "testdata/encrypted-dmg", 107, nil)
}

func openReferenceImage(t *testing.T, path string, native *nativeDiskImage, dir string) *diskimage.Image {
	t.Helper()
	if native == nil {
		image, err := diskimage.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		return image
	}
	if !native.UnlockedReadOnly || (native.KeyBits != 128 && native.KeyBits != 256) || len(native.RejectedPasswords) < 2 || (native.NativeFormat != "UDZO" && native.NativeFormat != "UDRW") {
		t.Fatal("incomplete native encrypted-image evidence")
	}
	verifyDigest(t, dir, native.ImageObservation, native.ImageObservationSHA256)
	if image, err := diskimage.Open(path); image != nil || !errors.Is(err, filesystem.ErrAuthentication) {
		t.Fatal("missing image password", err)
	}
	for _, candidate := range native.RejectedPasswords {
		if image, err := diskimage.OpenWithPassword(context.Background(), path, []byte(candidate)); image != nil || !errors.Is(err, filesystem.ErrAuthentication) {
			t.Fatal("native-rejected image password accepted", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if image, err := diskimage.OpenWithPassword(ctx, path, []byte(native.Password)); image != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("image unlock ignored cancellation", err)
	}
	password := []byte(native.Password)
	image, err := diskimage.OpenWithPassword(context.Background(), path, password)
	if err != nil {
		t.Fatal("native-accepted image password rejected", err)
	}
	if !bytes.Equal(password, []byte(native.Password)) {
		t.Fatal("image unlock changed caller's password")
	}
	clear(password)
	if image.Encryption == nil || image.Encryption.KeyBits != native.KeyBits || image.Encryption.Cipher != "AES-CBC" || image.Encryption.Version != 2 {
		t.Fatal("native image cipher differs")
	}
	wantFormat := "udif"
	if native.NativeFormat == "UDRW" {
		wantFormat = "raw"
	}
	if image.Format != wantFormat {
		t.Fatal("inner image format", image.Format, wantFormat)
	}
	// Closing a borrowed decoded view must revoke its cache and partitions,
	// release its keys and leave caller-owned encrypted storage available.
	source, err := block.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	borrowed, err := diskimage.NewWithPassword(context.Background(), source, []byte(native.Password))
	if err != nil {
		t.Fatal(err)
	}
	if len(borrowed.Partitions) == 0 {
		t.Fatal("no native partition")
	}
	view, err := borrowed.Partition(borrowed.Partitions[0].Index)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := view.ReadAt(make([]byte, 512), 0); err != nil {
		t.Fatal(err)
	}
	if err := borrowed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := borrowed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := view.ReadAt(make([]byte, 1), 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("closed image served cached plaintext", err)
	}
	if _, err := source.ReadAt(make([]byte, 8), 0); err != nil {
		t.Fatal("borrowed source was closed", err)
	}
	return image
}
