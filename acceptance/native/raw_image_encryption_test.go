//go:build native && darwin

package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// requireRawImageEncryption runs before the fixture parent becomes parallel.
// Each proof closes its source and encrypted output before the next starts;
// returning its first failure prevents the parity lineages from being queued.
func requireRawImageEncryption(t *testing.T, v *Verifier, cases []corpus.Case) error {
	t.Helper()
	password, ok := v.Recipes["encrypted-image-edits"].Passwords["image"]
	if !ok || password == "" {
		return fmt.Errorf("encrypted-image-edits has no image password")
	}
	for _, profile := range []string{"apfs", "apfsx", "hfsplus", "hfsx"} {
		var source *corpus.Case
		for i := range cases {
			k := &cases[i]
			if k.Producer == v.Major && k.Recipe == "encrypted-image-edits" && k.Profile == profile && k.Stage == "before" {
				if source != nil {
					return fmt.Errorf("duplicate plaintext %s source from macOS %d", profile, v.Major)
				}
				source = k
			}
		}
		if source == nil {
			return fmt.Errorf("missing plaintext %s source from macOS %d", profile, v.Major)
		}
		for _, cipher := range []string{"AES-128", "AES-256"} {
			name := "raw-image-encryption/" + profile + "/" + cipher
			if !t.Run(name, func(t *testing.T) {
				if err := v.ForSubtest().proveRawImageEncryption(context.Background(), *source, cipher, []byte(password)); err != nil {
					t.Fatal(err)
				}
			}) {
				return fmt.Errorf("%s failed", name)
			}
		}
	}
	return nil
}

type rawEncryptionProof struct {
	Source            schema.CaseRef `json:"source"`
	Cipher            string         `json:"cipher"`
	SourceSHA256      string         `json:"sourceSHA256"`
	SourceAfterSHA256 string         `json:"sourceAfterSHA256"`
	RawSHA256         string         `json:"rawSHA256"`
	RawBytes          int64          `json:"rawBytes"`
	RawAfterSHA256    string         `json:"rawAfterSHA256"`
	DecryptedSHA256   string         `json:"decryptedSHA256"`
	DecryptedBytes    int64          `json:"decryptedBytes"`
	Imageinfo         map[string]any `json:"imageinfo,omitempty"`
}

func (v *Verifier) proveRawImageEncryption(ctx context.Context, k corpus.Case, cipher string, password []byte) (resultErr error) {
	if k.Observation == nil || k.Observation.Image.Encryption != nil || !schema.ValidDigest(k.Observation.Image.DiskSHA256) || k.Observation.Image.DiskBytes <= 0 {
		return fmt.Errorf("%s/%s has no complete plaintext device oracle", k.Recipe, k.Profile)
	}
	work := filepath.Join(v.Work, "raw-image-encryption", k.Profile, cipher)
	if err := os.MkdirAll(work, 0o700); err != nil {
		return err
	}
	transcript := &fixture.Transcript{}
	if disk, ok := v.Disk.(fixture.TranscriptUser); ok {
		disk.SetTranscript(transcript)
	}
	proof := rawEncryptionProof{Source: schema.CaseRef{Producer: k.Producer, Recipe: k.Recipe, Profile: k.Profile, Stage: k.Stage}, Cipher: cipher}
	source := filepath.Join(k.Dir, k.Observation.Image.File)
	raw := filepath.Join(work, "source.raw")
	encrypted := filepath.Join(work, "encrypted.dmg")
	defer func() {
		var err error
		proof.SourceAfterSHA256, err = schema.FileDigest(source)
		if err != nil || proof.SourceAfterSHA256 != k.Observation.Image.SHA256 {
			resultErr = errors.Join(resultErr, fmt.Errorf("original native image changed: %v", err))
		}
		if proof.RawSHA256 != "" {
			proof.RawAfterSHA256, err = schema.FileDigest(raw)
			if err != nil || proof.RawAfterSHA256 != proof.RawSHA256 {
				resultErr = errors.Join(resultErr, fmt.Errorf("private raw input changed: %v", err))
			}
		}
		for name, value := range map[string]any{"commands.json": transcript.Commands, "proof.json": proof} {
			data, err := json.MarshalIndent(value, "", "  ")
			if err == nil {
				err = os.WriteFile(filepath.Join(work, name), data, 0o600)
			}
			if err != nil {
				resultErr = errors.Join(resultErr, fmt.Errorf("retain %s: %w", name, err))
			}
		}
		if resultErr == nil {
			for _, path := range []string{raw, raw + ".gz", encrypted} {
				if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
					resultErr = errors.Join(resultErr, err)
				}
			}
		}
	}()
	var err error
	proof.SourceSHA256, err = schema.FileDigest(source)
	if err != nil || proof.SourceSHA256 != k.Observation.Image.SHA256 {
		return fmt.Errorf("original native image differs from its retained digest: %v", err)
	}
	lease, err := v.Corpus.AcquireImage(ctx, k)
	if err != nil {
		return err
	}
	att, err := v.Disk.Attach(ctx, lease.Path(), fixture.AttachOptions{ReadOnly: true, Raw: k.Observation.Image.Format == "raw", NoInventory: true})
	if err != nil {
		return errors.Join(err, lease.Release(err))
	}
	digest, size, readErr := v.Disk.DeviceDigest(ctx, att.RDev, raw+".gz")
	err = errors.Join(readErr, lease.Release(v.Disk.Detach(ctx, att)))
	if err != nil {
		return fmt.Errorf("copy native plaintext device: %w", err)
	}
	if digest != k.Observation.Image.DiskSHA256 || size != k.Observation.Image.DiskBytes {
		return fmt.Errorf("native plaintext device differs from its retained digest or length")
	}
	if err := corpus.ExpandGzip(raw+".gz", raw); err != nil {
		return err
	}
	proof.RawSHA256, err = schema.FileDigest(raw)
	if err != nil {
		return err
	}
	info, err := os.Stat(raw)
	if err != nil {
		return err
	}
	proof.RawBytes = info.Size()
	if proof.RawSHA256 != digest || proof.RawBytes != size {
		return fmt.Errorf("private raw copy differs from its native source")
	}
	if err := v.Disk.Convert(ctx, raw, "UDZO", encrypted, fixture.ConvertOptions{Raw: true, Encryption: cipher, Password: password}); err != nil {
		return fmt.Errorf("encrypt raw input: %w", err)
	}
	proof.Imageinfo, err = v.Disk.Imageinfo(ctx, encrypted, password)
	if err != nil {
		return err
	}
	gotCipher, err := nativeImageCipher(proof.Imageinfo)
	if err != nil || gotCipher != cipher {
		return fmt.Errorf("native image cipher %q, want %q: %v", gotCipher, cipher, err)
	}
	proof.DecryptedSHA256, proof.DecryptedBytes, err = v.closedImageDeviceDigest(ctx, encrypted, fixture.AttachOptions{ReadOnly: true, Password: password, NoInventory: true}, "")
	if err != nil {
		return fmt.Errorf("read encrypted device: %w", err)
	}
	if proof.DecryptedSHA256 != proof.RawSHA256 || proof.DecryptedBytes != proof.RawBytes {
		return fmt.Errorf("encrypted device differs from its raw input")
	}
	return nil
}

// A digest error never hides a close failure, and no next image is attached
// unless this image has been detached successfully.
func (v *Verifier) closedImageDeviceDigest(ctx context.Context, image string, opts fixture.AttachOptions, archive string) (string, int64, error) {
	att, err := v.Disk.Attach(ctx, image, opts)
	if err != nil {
		return "", 0, err
	}
	digest, size, readErr := v.Disk.DeviceDigest(ctx, att.RDev, archive)
	return digest, size, errors.Join(readErr, v.Disk.Detach(ctx, att))
}
