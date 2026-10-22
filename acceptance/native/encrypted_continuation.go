package native

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
)

// continuationEnvelope keeps the image password separate from any filesystem
// credentials. Its cipher comes from Apple's imageinfo, not the product.
type continuationEnvelope struct {
	cipher    string
	password  []byte
	imageinfo map[string]any
}

func (v *Verifier) envelopeForContinuation(ctx context.Context, p Paired, image string) (continuationEnvelope, error) {
	envelope := continuationEnvelope{}
	if p.Output.Encrypted {
		password, ok := p.Passwords[p.Output.Password]
		if !ok {
			return continuationEnvelope{}, fmt.Errorf("continuation %s: unknown image password reference %q", p.Name, p.Output.Password)
		}
		envelope.password = []byte(password)
	}
	// Keep Apple's partition ordinals for the later raw copy. Raw observations
	// retain current diskutil topology but do not run imageinfo themselves.
	info, err := v.Disk.Imageinfo(ctx, image, envelope.password)
	if err != nil {
		return continuationEnvelope{}, err
	}
	envelope.imageinfo = info
	if !p.Output.Encrypted {
		return envelope, nil
	}
	envelope.cipher, err = nativeImageCipher(info)
	if err != nil {
		return continuationEnvelope{}, err
	}
	return envelope, nil
}

// nativeImageCipher follows only the backing-store chain Apple reports. An
// unrelated field named Encryption cannot supply an expected image policy.
func nativeImageCipher(info map[string]any) (string, error) {
	properties, ok := info["Properties"].(map[string]any)
	if !ok || properties["Encrypted"] != true {
		return "", fmt.Errorf("native imageinfo does not identify an encrypted image")
	}
	node, ok := info["Backing Store Information"].(map[string]any)
	cipher := ""
	for depth := 0; ok && depth < 16; depth++ {
		if value, present := node["Encryption"]; present {
			if cipher != "" || (value != "AES-128" && value != "AES-256") {
				return "", fmt.Errorf("native imageinfo has an ambiguous or unsupported image cipher")
			}
			cipher = value.(string)
		}
		child, present := node["Backing Store Information"]
		if !present {
			if cipher == "" {
				return "", fmt.Errorf("native imageinfo has no image cipher")
			}
			return cipher, nil
		}
		node, ok = child.(map[string]any)
	}
	return "", fmt.Errorf("native imageinfo has an invalid backing-store chain")
}

// prepareEncryptedContinuation puts the natively modified filesystem back in
// an Apple-created envelope before the next product edit. The default product
// output policy must preserve that envelope's cipher and password.
func (v *Verifier) prepareEncryptedContinuation(ctx context.Context, envelope continuationEnvelope, raw, work string) (string, []string, error) {
	if envelope.cipher == "" {
		return raw, nil, nil
	}
	image := filepath.Join(work, "native-edited-encrypted.dmg")
	if err := v.Disk.Convert(ctx, raw, "UDZO", image, fixture.ConvertOptions{Raw: true, Encryption: envelope.cipher, Password: envelope.password}); err != nil {
		return "", nil, fmt.Errorf("encrypt native continuation input: %w", err)
	}
	passwordFile := filepath.Join(work, "image-password.bin")
	f, err := os.OpenFile(passwordFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return "", nil, err
	}
	_, writeErr := f.Write(envelope.password)
	closeErr := f.Close()
	if writeErr != nil {
		return "", nil, writeErr
	}
	if closeErr != nil {
		return "", nil, closeErr
	}
	return image, []string{"--image-password-file", passwordFile}, nil
}

func (v *Verifier) checkContinuationEnvelope(ctx context.Context, envelope continuationEnvelope, image string) error {
	if envelope.cipher == "" {
		return nil
	}
	info, err := v.Disk.Imageinfo(ctx, image, envelope.password)
	if err != nil {
		return err
	}
	cipher, err := nativeImageCipher(info)
	if err != nil {
		return err
	}
	if cipher != envelope.cipher {
		return fmt.Errorf("product continuation changed image encryption from %s to %s", envelope.cipher, cipher)
	}
	return nil
}
