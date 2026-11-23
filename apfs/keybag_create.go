package apfs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"io/fs"

	storagecrypto "github.com/deploymenttheory/go-apfs-v3/internal/crypto"
)

// newSoftwareVolumeKeys creates the native single Disk-user profile shared by
// construction and completed conversion. Only wrapped records escape this call.
func newSoftwareVolumeKeys(ctx context.Context, id [16]byte, password []byte, keyBits int) (*volumeKeys, []byte, []byte, error) {
	if password == nil || len(password) > 4096 {
		return nil, nil, nil, fs.ErrInvalid
	}
	var vek [64]byte
	var kek [32]byte
	defer clear(vek[:])
	defer clear(kek[:])
	keyBytes := 32 // AES-XTS-128 needs a 16-byte data key and a 16-byte tweak key
	if keyBits == 256 {
		keyBytes = 64
	}
	v := vek[:keyBytes]
	var salt, integrity [16]byte
	for _, b := range [][]byte{v, kek[:], salt[:], integrity[:]} {
		if _, err := rand.Read(b); err != nil {
			return nil, nil, nil, err
		}
	}
	const iterations = 600_000
	derived, err := storagecrypto.PBKDF2(ctx, sha256.New, password, salt[:], iterations, 32)
	defer clear(derived)
	if err != nil {
		return nil, nil, nil, err
	}
	wrappedKEK, err := storagecrypto.Wrap(derived, kek[:])
	if err != nil {
		return nil, nil, nil, err
	}
	wrappedVEK, err := storagecrypto.Wrap(kek[:], v)
	if err != nil {
		return nil, nil, nil, err
	}
	user := keyRecord{id: id, info: [8]byte{0, 0, 0, 0, 2, 0, 0x53, 0x49}, wrapped: wrappedKEK, iterations: iterations, salt: salt[:]}
	volume := keyRecord{id: id, info: [8]byte{0, 0, 0, 0, 1, 0, 0x53, 0x49}, wrapped: wrappedVEK}
	xts, err := storagecrypto.NewXTS(v)
	if err != nil {
		return nil, nil, nil, err
	}
	return &volumeKeys{xts: xts, keyBytes: keyBytes}, encodeKeyRecord(user, integrity[:8]), encodeKeyRecord(volume, integrity[8:]), nil
}
