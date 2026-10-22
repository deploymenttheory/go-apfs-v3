package native

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// This is the backing-store shape retained from Apple's imageinfo for the
// encrypted-images fixture; it is independent of product image inspection.
func encryptedImageInfo(cipher string) map[string]any {
	return map[string]any{
		"Properties": map[string]any{"Encrypted": true},
		"Backing Store Information": map[string]any{
			"Class Name": "CUDIFEncoding",
			"Backing Store Information": map[string]any{
				"Class Name": "CEncryptedEncoding", "Encryption": cipher,
				"Backing Store Information": map[string]any{"Class Name": "CBSDBackingStore"},
			},
		},
	}
}

func TestNativeImageCipherRequiresAnUnambiguousEncryptedBackingStore(t *testing.T) {
	for _, cipher := range []string{"AES-128", "AES-256"} {
		if got, err := nativeImageCipher(encryptedImageInfo(cipher)); err != nil || got != cipher {
			t.Fatal(got, err)
		}
	}
	plain := encryptedImageInfo("AES-128")
	plain["Properties"] = map[string]any{"Encrypted": false}
	ambiguous := encryptedImageInfo("AES-128")
	ambiguous["Backing Store Information"].(map[string]any)["Encryption"] = "AES-128"
	unrelated := map[string]any{
		"Properties":                map[string]any{"Encrypted": true},
		"Encryption":                "AES-256",
		"Backing Store Information": map[string]any{"Class Name": "CBSDBackingStore"},
	}
	cyclic := encryptedImageInfo("AES-128")
	chain := cyclic["Backing Store Information"].(map[string]any)
	chain["Backing Store Information"] = chain
	for name, info := range map[string]map[string]any{
		"plaintext": plain, "ambiguous": ambiguous, "unrelated field": unrelated,
		"unsupported cipher": encryptedImageInfo("AES-512"), "cyclic chain": cyclic,
		"malformed chain": {"Properties": map[string]any{"Encrypted": true}, "Backing Store Information": "AES-128"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := nativeImageCipher(info); err == nil {
				t.Fatal("ambiguous native encryption policy was admitted")
			}
		})
	}
}

type envelopeDisk struct {
	fixture.Disk
	info          map[string]any
	infoCalls     int
	converted     string
	password      []byte
	conversionErr error
}

func (d *envelopeDisk) Imageinfo(_ context.Context, _ string, password []byte) (map[string]any, error) {
	d.infoCalls++
	d.password = bytes.Clone(password)
	return d.info, nil
}

func (d *envelopeDisk) Convert(_ context.Context, _, _, out, cipher string, password []byte) error {
	d.converted = cipher
	d.password = bytes.Clone(password)
	if d.conversionErr != nil {
		return d.conversionErr
	}
	return os.WriteFile(out, []byte("independent native envelope"), 0o600)
}

func TestEncryptedContinuationUsesPrivatePasswordFilesAndPreservesNativeCipher(t *testing.T) {
	ctx := context.Background()
	disk := &envelopeDisk{info: encryptedImageInfo("AES-256")}
	v := &Verifier{Disk: disk}
	password := "exact password\nwith trailing whitespace "
	pair := Paired{Name: "encrypted output", Output: schema.Output{Encrypted: true, Password: "image"}, Passwords: map[string]string{"image": password}}
	envelope, err := v.envelopeForContinuation(ctx, pair, "output.dmg")
	if err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	image, args, err := v.prepareEncryptedContinuation(ctx, envelope, "native.raw", work)
	if err != nil {
		t.Fatal(err)
	}
	if image != filepath.Join(work, "native-edited-encrypted.dmg") || disk.converted != "AES-256" || string(disk.password) != password {
		t.Fatal("native envelope was not retained", image, disk.converted)
	}
	if len(args) != 2 || args[0] != "--image-password-file" {
		t.Fatal("product credentials did not use the password-file interface", args)
	}
	data, err := os.ReadFile(args[1])
	if err != nil || string(data) != password {
		t.Fatal("password bytes were changed", err)
	}
	info, err := os.Stat(args[1])
	if err != nil {
		t.Fatal(err)
	}
	// The native helper runs on Darwin; Windows does not expose POSIX modes.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatal("image password file is not private", err)
	}
	if err := v.checkContinuationEnvelope(ctx, envelope, image); err != nil {
		t.Fatal(err)
	}
	disk.info = encryptedImageInfo("AES-128")
	if err := v.checkContinuationEnvelope(ctx, envelope, image); err == nil {
		t.Fatal("a product cipher downgrade was accepted")
	}
	disk.info["Properties"] = map[string]any{"Encrypted": false}
	if err := v.checkContinuationEnvelope(ctx, envelope, image); err == nil {
		t.Fatal("silent product decryption was accepted")
	}
}

func TestEncryptedContinuationRefusesMissingCredentialsAndFailedNativeConversion(t *testing.T) {
	disk := &envelopeDisk{}
	v := &Verifier{Disk: disk}
	_, err := v.envelopeForContinuation(context.Background(), Paired{Output: schema.Output{Encrypted: true, Password: "absent"}}, "output.dmg")
	if err == nil || disk.infoCalls != 0 {
		t.Fatal("missing image password reached native tools", err)
	}
	work := t.TempDir()
	disk.conversionErr = errors.New("native conversion failed")
	_, _, err = v.prepareEncryptedContinuation(context.Background(), continuationEnvelope{cipher: "AES-128", password: []byte("public")}, "native.raw", work)
	if !errors.Is(err, disk.conversionErr) {
		t.Fatal("native failure lost", err)
	}
	if _, err := os.Stat(filepath.Join(work, "image-password.bin")); !os.IsNotExist(err) {
		t.Fatal("failed native conversion published product credentials", err)
	}
}
