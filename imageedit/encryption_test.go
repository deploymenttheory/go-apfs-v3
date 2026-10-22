package imageedit_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func encryptedFixture(t *testing.T, source string, bits uint32, password []byte) string {
	t.Helper()
	in, err := block.Open(source)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	path := filepath.Join(t.TempDir(), "encrypted.dmg")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = diskimage.RepackWithOptions(context.Background(), out, in, diskimage.RepackOptions{Format: "UDZO", Encryption: &diskimage.EncryptionOptions{KeyBits: bits, Password: password}})
	if err = errors.Join(err, out.Close()); err != nil {
		t.Fatal(err)
	}
	return path
}

func readEditedImage(t *testing.T, path string, password []byte, file string) (*diskimage.Encryption, string, uint32, [32]byte) {
	t.Helper()
	ctx := context.Background()
	var image *diskimage.Image
	var err error
	if password == nil {
		image, err = diskimage.Open(path)
	} else {
		image, err = diskimage.OpenWithPassword(ctx, path, password)
	}
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	p, err := image.Partition(0)
	if err != nil {
		t.Fatal(err)
	}
	var signature [36]byte
	if err = block.ReadFull(p, signature[:], 0); err != nil {
		t.Fatal(err)
	}
	var reader filesystem.Reader
	if string(signature[32:]) == "NXSB" {
		container, e := apfs.Open(p)
		if e != nil {
			t.Fatal(e)
		}
		reader = &container.Volumes[0]
		err = apfs.ValidateMutation(ctx, p)
	} else {
		reader, err = hfsplus.Open(p)
		if err == nil {
			err = hfsplus.ValidateMutation(ctx, p)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	id, err := filesystem.Lookup(ctx, reader, file)
	if err != nil {
		t.Fatal(err)
	}
	node, err := reader.Stat(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	data, err := reader.OpenData(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	content, err := io.ReadAll(io.NewSectionReader(data, 0, data.Size()))
	if err = errors.Join(err, data.Close()); err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	if _, err = io.Copy(h, io.NewSectionReader(image, 0, image.Size())); err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], h.Sum(nil))
	return image.Encryption, string(content), node.Metadata.Mode.Value & 07777, digest
}

func TestEncryptedImageEditingPreservesPolicyAndOrderedCopies(t *testing.T) {
	ctx := context.Background()
	password := []byte("exact-secret-λ-😀\n")
	for _, kind := range []string{"APFS", "APFSX", "HFS+", "HFSX"} {
		plain := fixture(t, kind)
		for _, bits := range []uint32{128, 256} {
			t.Run(fmt.Sprintf("%s/AES-%d", kind, bits), func(t *testing.T) {
				source := encryptedFixture(t, plain, bits, password)
				original, err := os.ReadFile(source)
				if err != nil {
					t.Fatal(err)
				}
				for _, format := range []string{"UDRO", "UDZO"} {
					var previous [32]byte
					var decoded [32]byte
					for repeat := 0; repeat < 2; repeat++ {
						out := filepath.Join(t.TempDir(), "edited.dmg")
						report, err := imageedit.Edit(ctx, source, out, imageedit.Options{Time: clock, Format: format, ImagePassword: password}, func(editor *imageedit.Editor) error {
							if _, err := editor.Apply([]imageedit.Change{{Operation: "mkdir", Path: "/created"}}); err != nil {
								return err
							}
							if _, err := editor.Copy([]imageedit.CopyCommand{{Sources: []string{"/file"}, Destination: "/created", Options: imageedit.CopyOptions{Preserve: true}}}); err != nil {
								return err
							}
							_, err := editor.Apply([]imageedit.Change{{Operation: "chmod", Path: "/created/file", Mode: "0751"}})
							return err
						})
						if err != nil {
							t.Fatal(err)
						}
						encryption, content, mode, disk := readEditedImage(t, out, password, "/created/file")
						if encryption == nil || encryption.KeyBits != bits || content != "existing" || mode != 0751 || report.Encryption == nil || report.Encryption.KeyBits != bits || report.SourceEncryption == nil || report.SourceEncryption.KeyBits != bits || report.Format != format {
							t.Fatalf("lost policy or commands: %+v, %q, %#o, %+v", encryption, content, mode, report)
						}
						encoded, err := os.ReadFile(out)
						if err != nil {
							t.Fatal(err)
						}
						digest := sha256.Sum256(encoded)
						if repeat != 0 && (digest == previous || disk != decoded) {
							t.Fatal("fresh encryption must differ while decoded edits stay reproducible")
						}
						previous, decoded = digest, disk
						if _, err := imageedit.Apply(ctx, source, out, imageedit.Options{Time: clock, ImagePassword: password}, []imageedit.Change{{Path: "/file", Mode: "0600"}}); !errors.Is(err, fs.ErrExist) {
							t.Fatal("destination overwrite admitted", err)
						}
					}
				}
				after, err := os.ReadFile(source)
				if err != nil || !bytes.Equal(original, after) || string(password) != "exact-secret-λ-😀\n" {
					t.Fatal("source or borrowed password changed", err)
				}
			})
		}
	}
}

func TestEncryptedImageEditingRekeysAndRemovesEnvelopeExplicitly(t *testing.T) {
	ctx := context.Background()
	old, replacement := []byte("source-password\n"), []byte("replacement-λ-😀")
	source := encryptedFixture(t, fixture(t), 128, old)
	for _, tc := range []struct {
		name       string
		encryption *diskimage.EncryptionOptions
		decrypt    bool
		bits       uint32
		password   []byte
	}{
		{"password", &diskimage.EncryptionOptions{Password: replacement}, false, 128, replacement},
		{"strength", &diskimage.EncryptionOptions{KeyBits: 256, Password: replacement}, false, 256, replacement},
		{"remove", nil, true, 0, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "edited.dmg")
			r, err := imageedit.Apply(ctx, source, out, imageedit.Options{Time: clock, ImagePassword: old, Encryption: tc.encryption, Decrypt: tc.decrypt}, []imageedit.Change{{Path: "/file", Mode: "0700"}})
			if err != nil {
				t.Fatal(err)
			}
			encryption, content, mode, _ := readEditedImage(t, out, tc.password, "/file")
			if content != "existing" || mode != 0700 || (encryption == nil) != (tc.bits == 0) || encryption != nil && encryption.KeyBits != tc.bits || r.SourceEncryption == nil || r.SourceEncryption.KeyBits != 128 {
				t.Fatal("bad rekey/decryption", encryption, content, mode, r)
			}
			if image, err := diskimage.OpenWithPassword(ctx, out, old); err == nil {
				image.Close()
				t.Fatal("output still accepts replaced credential")
			}
		})
	}
}

func TestEncryptedImageAdmissionAndFailedCommandsPublishNothing(t *testing.T) {
	ctx := context.Background()
	password := []byte("source-password\n")
	source := encryptedFixture(t, fixture(t, "APFS"), 256, password)
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		o    imageedit.Options
		want error
	}{
		{"absent", imageedit.Options{}, filesystem.ErrAuthentication},
		{"wrong", imageedit.Options{ImagePassword: []byte("wrong")}, filesystem.ErrAuthentication},
		{"empty", imageedit.Options{ImagePassword: []byte{}}, filesystem.ErrAuthentication},
		{"trimmed", imageedit.Options{ImagePassword: []byte("source-password")}, filesystem.ErrAuthentication},
		{"volume-is-separate", imageedit.Options{VolumePassword: password}, filesystem.ErrAuthentication},
		{"unencrypted-volume", imageedit.Options{ImagePassword: password, VolumePassword: []byte("volume")}, fs.ErrInvalid},
		{"conflict", imageedit.Options{ImagePassword: password, Encryption: &diskimage.EncryptionOptions{KeyBits: 128, Password: password}, Decrypt: true}, fs.ErrInvalid},
		{"empty-output", imageedit.Options{ImagePassword: password, Encryption: &diskimage.EncryptionOptions{KeyBits: 128}}, fs.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "refused.dmg")
			tc.o.Time = clock
			_, err := imageedit.Edit(ctx, source, out, tc.o, func(*imageedit.Editor) error { t.Fatal("admission reached callback"); return nil })
			if !errors.Is(err, tc.want) {
				t.Fatalf("wrong refusal: %v (want %v)", err, tc.want)
			}
			if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("refused output exists", err)
			}
		})
	}
	out := filepath.Join(t.TempDir(), "failed.dmg")
	_, err = imageedit.Edit(ctx, source, out, imageedit.Options{Time: clock, ImagePassword: password}, func(editor *imageedit.Editor) error {
		if _, err := editor.Apply([]imageedit.Change{{Operation: "mkdir", Path: "/private"}}); err != nil {
			return err
		}
		_, err := editor.Copy([]imageedit.CopyCommand{{Sources: []string{"/absent"}, Destination: "/private/file"}})
		if !errors.Is(err, fs.ErrNotExist) {
			t.Fatal(err)
		}
		return nil
	})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("ignored command failure published", err)
	}
	if _, err = os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("failed output exists", err)
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed edit changed source", err)
	}
}
