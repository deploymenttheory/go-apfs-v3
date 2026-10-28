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
func newSoftwareVolumeKeys(ctx context.Context, id [16]byte, password []byte) (*volumeKeys, []byte, []byte, error) {
	if password == nil || len(password) > 4096 {
		return nil, nil, nil, fs.ErrInvalid
	}
	var vek, kek [32]byte
	defer clear(vek[:])
	defer clear(kek[:])
	var salt, integrity [16]byte
	for _, b := range [][]byte{vek[:], kek[:], salt[:], integrity[:]} {
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
	wrappedVEK, err := storagecrypto.Wrap(kek[:], vek[:])
	if err != nil {
		return nil, nil, nil, err
	}
	user := keyRecord{id: id, info: [8]byte{0, 0, 0, 0, 2, 0, 0x53, 0x49}, wrapped: wrappedKEK, iterations: iterations, salt: salt[:]}
	volume := keyRecord{id: id, info: [8]byte{0, 0, 0, 0, 1, 0, 0x53, 0x49}, wrapped: wrappedVEK}
	xts, err := storagecrypto.NewXTS(vek[:])
	if err != nil {
		return nil, nil, nil, err
	}
	return &volumeKeys{xts: xts, keyBytes: 32}, encodeKeyRecord(user, integrity[:8]), encodeKeyRecord(volume, integrity[8:]), nil
}
