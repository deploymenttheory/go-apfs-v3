package apfs

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"io/fs"

	storagecrypto "github.com/deploymenttheory/go-apfs-v3/internal/crypto"
)

// VolumeEncryptionOptions creates the admitted software AES-128-XTS Disk-user
// profile. Password is borrowed by Plan only; nil is invalid, non-nil empty is
// valid. It is independent of image-envelope encryption and never fingerprinted.
type VolumeEncryptionOptions struct {
	Password []byte `json:"-"`
}

// BuiltVolumeEncryption describes storage and the selected native Disk user,
// never credentials or wrapping material.
type BuiltVolumeEncryption struct {
	Name       string `json:"name"`
	VolumeUUID string `json:"volumeUUID"`
	CryptoUser string `json:"cryptoUser"`
	Cipher     string `json:"cipher"`
	KeyBits    int    `json:"keyBits"`
}

func (p *Layout) EncryptedVolumes() []BuiltVolumeEncryption {
	p.mu.RLock()
	defer p.mu.RUnlock()
	var result []BuiltVolumeEncryption
	for _, v := range p.volumes {
		if v.encryption != nil {
			result = append(result, BuiltVolumeEncryption{Name: v.options.Name, VolumeUUID: uuid(v.options.UUID[:]), CryptoUser: uuid(v.options.UUID[:]), Cipher: "AES-XTS", KeyBits: 128})
		}
	}
	return result
}

type buildVolumeEncryption struct {
	keys    *volumeKeys
	bag     []byte
	address uint64
}

func (p *Layout) hasEncryption() bool {
	for _, v := range p.volumes {
		if v.encryption != nil {
			return true
		}
	}
	return false
}

func randomBuildUUID() ([16]byte, error) {
	var id [16]byte
	_, err := rand.Read(id[:])
	id[6] = (id[6] & 15) | 0x40
	id[8] = (id[8] & 63) | 0x80
	return id, err
}

// Close invalidates an encrypted plan after its active writes finish. It is
// idempotent and never closes borrowed readers. Plaintext plans need no keys.
func (p *Layout) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.closed {
		p.closed = true
		for _, v := range p.volumes {
			if v.encryption != nil && v.encryption.keys != nil {
				v.encryption.keys.xts = nil
			}
		}
	}
	return nil
}

func buildKeybagSize(encrypted int) int {
	// One 124-byte wrapped VEK and one 16-byte extent per encrypted volume,
	// each with its 24-byte entry header and native 16-byte alignment.
	return (48 + encrypted*(160+48) + 4095) / 4096 * 4096
}

func encodeBuildKeybag(dst []byte, entries []keybagEntry, kind uint32) error {
	clear(dst)
	le.PutUint16(dst[32:], 2)
	le.PutUint16(dst[34:], uint16(len(entries)))
	at := 48
	for _, entry := range entries {
		end := (at + 24 + len(entry.data) + 15) &^ 15
		if end > len(dst) {
			return fmt.Errorf("APFS keybag construction bounds: %w", fs.ErrInvalid)
		}
		copy(dst[at:], entry.id[:])
		le.PutUint16(dst[at+16:], entry.tag)
		le.PutUint16(dst[at+18:], uint16(len(entry.data)))
		copy(dst[at+24:], entry.data)
		at = end
	}
	le.PutUint32(dst[36:], uint32(at-32))
	sealBuildObject(dst, 0, kind, 0)
	return nil
}

func (p *Layout) prepareEncryption(ctx context.Context, inputs []VolumeSpec) error {
	if !p.hasEncryption() {
		return nil
	}
	var root []keybagEntry
	for i, v := range p.volumes {
		if v.encryption == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		keys, user, volume, err := newSoftwareVolumeKeys(ctx, v.options.UUID, inputs[i].Encryption.Password)
		if err != nil {
			return err
		}
		v.encryption.keys = keys
		if err := encodeBuildKeybag(v.encryption.bag, []keybagEntry{{id: v.options.UUID, tag: 3, data: user}}, 0x72656373); err != nil {
			return err
		}
		if err := encryptBuildKeybag(v.encryption.bag, v.options.UUID, v.encryption.address); err != nil {
			return err
		}
		extent := make([]byte, 16)
		le.PutUint64(extent, v.encryption.address)
		le.PutUint64(extent[8:], 1)
		root = append(root, keybagEntry{id: v.options.UUID, tag: 3, data: extent}, keybagEntry{id: v.options.UUID, tag: 2, data: volume})
	}
	if err := encodeBuildKeybag(p.keylocker, root, 0x6b657973); err != nil {
		return err
	}
	return encryptBuildKeybag(p.keylocker, p.options.UUID, p.keylockerAddress)
}

func encryptBuildKeybag(data []byte, id [16]byte, address uint64) error {
	var key [32]byte
	copy(key[:16], id[:])
	copy(key[16:], id[:])
	defer clear(key[:])
	xts, err := storagecrypto.NewXTS(key[:])
	if err != nil {
		return err
	}
	return xts.Encrypt(data, data, address*8)
}

// encryptedBuildWriter verifies the borrowed plaintext stream in the caller,
// encrypting bounded complete sectors, including its final allocated padding.
type encryptedBuildWriter struct {
	ctx    context.Context
	out    io.Writer
	key    *volumeKeys
	offset int64
	buf    [128 << 10]byte
	used   int
}

func (w *encryptedBuildWriter) Write(data []byte) (int, error) {
	n := 0
	for len(data) > 0 {
		count := copy(w.buf[w.used:], data)
		w.used += count
		n += count
		data = data[count:]
		if w.used == len(w.buf) {
			if err := w.flush(w.used); err != nil {
				return n, err
			}
		}
	}
	return n, nil
}
func (w *encryptedBuildWriter) finish() error {
	if w.used == 0 {
		return w.ctx.Err()
	}
	return w.flush((w.used + 4095) &^ 4095)
}
func (w *encryptedBuildWriter) flush(size int) error {
	if err := w.ctx.Err(); err != nil {
		return err
	}
	clear(w.buf[w.used:size])
	if err := w.key.encrypt(w.buf[:size], uint64(w.offset/512)); err != nil {
		return err
	}
	n, err := w.out.Write(w.buf[:size])
	clear(w.buf[:size])
	w.used = 0
	if err == nil && n != size {
		err = io.ErrShortWrite
	}
	w.offset += int64(n)
	return err
}
