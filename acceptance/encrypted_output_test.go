package acceptance_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
)

const outputImagePassword = "public-output-λ-😀"

// A bounded set covers both ciphers/encodings, all filesystem builders and a
// System/Data container. Native verification compares complete decrypted disks
// with the already qualified plaintext outputs, including unused sectors.
func encryptedBuildBits(profile, format string) uint32 {
	for _, c := range []struct {
		profile, format string
		bits            uint32
	}{{"apfs", "UDRO", 128}, {"apfs-case-sensitive", "UDZO", 256},
		{"hfsplus", "UDZO", 128}, {"hfsx", "UDRO", 256}, {"group", "UDZO", 256}} {
		if c.profile == profile && c.format == format {
			return c.bits
		}
	}
	return 0
}

func buildEncryptedOutput(t *testing.T, plain string, bits uint32, produce func(string, *diskimage.EncryptionOptions) error) {
	t.Helper()
	if bits == 0 {
		return
	}
	dir := filepath.Join(filepath.Dir(plain), "encrypted")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, filepath.Base(plain))
	password := []byte(outputImagePassword)
	o := &diskimage.EncryptionOptions{KeyBits: bits, Password: password}
	if err := produce(path, o); err != nil {
		t.Fatal(err)
	}
	if string(password) != outputImagePassword {
		t.Fatal("output changed caller's password")
	}
	before := fileDigest(t, path)
	reference, err := diskimage.Open(plain)
	if err != nil {
		t.Fatal(err)
	}
	defer reference.Close()
	image, err := diskimage.OpenWithPassword(context.Background(), path, password)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	if image.Encryption == nil || image.Encryption.KeyBits != bits || image.Size() != reference.Size() ||
		image.Format != reference.Format || !reflect.DeepEqual(image.Partitions, reference.Partitions) {
		t.Fatal("encrypted output profile or disk layout changed")
	}
	if before != fileDigest(t, path) {
		t.Fatal("reading changed encrypted image")
	}
	clear(password)
}
