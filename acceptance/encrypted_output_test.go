package acceptance_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/pack"
)

const outputImagePassword = "public-output-λ-😀"

func encryptedRepackBits(profile, format string) uint32 {
	if profile == "hfsx-apm-raw" {
		if format == "UDRO" {
			return 128
		}
	} else if format == "UDZO" {
		return 256
	}
	return 0
}

// Reuse the existing Apple UDRW/AES-256 fixture; native readback compares the
// complete source device with the decrypted and re-encrypted output devices.
func repackNativeRawEncrypted(t *testing.T, major string) {
	t.Helper()
	root := os.Getenv("APFS_NATIVE_ENCRYPTED_DMG")
	if root == "" {
		root = "testdata/encrypted-dmg"
	}
	dir := filepath.Join(root, "macos-"+major)
	var c corpus
	decodeEvidence(t, filepath.Join(dir, "manifest.json"), &c)
	for _, v := range c.Cases {
		if v.ID != "disk-image-encryption/hfsplus-raw-aes256" {
			continue
		}
		verifyDigest(t, dir, v.Image, v.SHA256)
		verifyDigest(t, dir, v.Files, v.FilesSHA256)
		var native fileObservation
		decodeEvidence(t, filepath.Join(dir, v.Files), &native)
		if native.DiskImage == nil || native.DiskImage.NativeFormat != "UDRW" || native.DiskImage.KeyBits != 256 {
			t.Fatal("missing native encrypted raw-disk profile")
		}
		output := os.Getenv("APFS_REPACKING_OUTPUT")
		if output == "" {
			output = t.TempDir()
		}
		output = filepath.Join(output, "macos-"+major, "hfsplus-encrypted-raw")
		if err := os.MkdirAll(output, 0700); err != nil {
			t.Fatal(err)
		}
		o := diskimage.RepackOptions{Format: "UDZO", SourcePassword: []byte(native.DiskImage.Password), Decrypt: true}
		source, plain := filepath.Join(dir, v.Image), filepath.Join(output, "UDZO.dmg")
		r, err := pack.RepackWithOptions(context.Background(), source, plain, o)
		if err != nil {
			t.Fatal(err)
		}
		if r.SourceFormat != "raw" || r.SourceEncryption == nil || r.SourceEncryption.KeyBits != 256 || r.Encryption != nil {
			t.Fatal("raw encrypted input lost its profile")
		}
		buildEncryptedOutput(t, plain, 128, func(path string, encryption *diskimage.EncryptionOptions) error {
			o.Encryption, o.Decrypt = encryption, false
			wrapped, err := pack.RepackWithOptions(context.Background(), source, path, o)
			if err == nil && (wrapped.DiskSHA256 != r.DiskSHA256 || wrapped.DiskBytes != r.DiskBytes) {
				t.Fatal("raw-disk rewrapping changed sectors")
			}
			return err
		})
		verifyDigest(t, dir, v.Image, v.SHA256)
		return
	}
	// Missing evidence is a failure, never an unsupported-input pass.
	t.Fatal("missing encrypted raw-disk source")
}

func repackEncryptedInput(t *testing.T, source, output string, diskBytes int64, diskSHA256 string) {
	t.Helper()
	for _, operation := range []string{"rewrapped", "decrypted"} {
		dir := filepath.Join(output, operation)
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
		o := diskimage.RepackOptions{Format: "UDZO", SourcePassword: []byte("public-repack-password"), Decrypt: operation == "decrypted"}
		if !o.Decrypt {
			o.Encryption = &diskimage.EncryptionOptions{KeyBits: 256, Password: []byte(outputImagePassword)}
		}
		report, err := pack.RepackWithOptions(context.Background(), source, filepath.Join(dir, "UDZO.dmg"), o)
		if err != nil {
			t.Fatal(operation, err)
		}
		if report.DiskBytes != diskBytes || report.DiskSHA256 != diskSHA256 || report.SourceEncryption == nil || report.SourceEncryption.KeyBits != 128 {
			t.Fatalf("%s changed native sectors or source profile: %+v", operation, report)
		}
		if o.Decrypt && report.Encryption != nil || !o.Decrypt && (report.Encryption == nil || report.Encryption.KeyBits != 256) {
			t.Fatal("incorrect output encryption policy", operation)
		}
	}
}

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
