package diskimage

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // Required by Apple's encrcdsa v2 format.
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	storagecrypto "github.com/deploymenttheory/go-apfs-v3/internal/crypto"
)

// EncryptionOptions requests a fresh password-protected encrcdsa v2 envelope.
// Password is borrowed for the call and never retained or modified. Every call
// generates new keys, salt, wrapping IV and identity from crypto/rand. There is
// deliberately no deterministic-encryption or caller-supplied-randomness option.
type EncryptionOptions struct {
	KeyBits  uint32
	Password []byte `json:"-"`
}

func (o EncryptionOptions) Validate() error {
	if o.KeyBits != 128 && o.KeyBits != 256 {
		return fmt.Errorf("DMG encryption requires AES-128 or AES-256: %w", filesystem.ErrUnsupported)
	}
	if len(o.Password) == 0 || len(o.Password) > 4096 {
		return fmt.Errorf("output password must contain 1 to 4096 bytes: %w", fs.ErrInvalid)
	}
	return nil
}

// Encrypt streams the bytes supplied by produce into a fresh encrypted image.
// out must be empty and seekable: the plaintext length is patched into its header
// only after produce succeeds. No plaintext temporary file is used. The callback
// must finish all writes before returning and may not retain its writer. Neither
// the destination nor the password is owned; discard all output on any error.
// The returned size includes the encrypted envelope and final block padding.
func Encrypt(ctx context.Context, out io.WriteSeeker, o EncryptionOptions, produce func(io.Writer) error) (int64, error) {
	if out == nil || produce == nil {
		return 0, fs.ErrInvalid
	}
	if err := o.Validate(); err != nil {
		return 0, err
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	position, err := out.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}
	if position != 0 {
		return 0, fmt.Errorf("encrypted image output must start at offset zero: %w", fs.ErrInvalid)
	}
	end, err := out.Seek(0, io.SeekEnd)
	if err != nil {
		return 0, err
	}
	if _, err = out.Seek(0, io.SeekStart); err != nil {
		return 0, err
	}
	if end != 0 {
		return 0, fmt.Errorf("encrypted image output must be empty: %w", fs.ErrInvalid)
	}
	// Match the independently captured Apple AES-wrapped password profile.
	// The 616-byte password slot and reserved header region permit native tools
	// to rewrite credentials without moving the encrypted backing store.
	const offset = 122368
	const iterations = 600000
	header := make([]byte, offset)
	be := binary.BigEndian
	copy(header, "encrcdsa")
	for i, v := range []uint32{2, 16, 5, 0x80000001, o.KeyBits, 91, 160} {
		be.PutUint32(header[8+i*4:], v)
	}
	if _, err = rand.Read(header[36:52]); err != nil {
		return 0, err
	}
	header[42] = header[42]&15 | 0x40
	header[44] = header[44]&63 | 0x80
	be.PutUint32(header[52:], 512)
	be.PutUint64(header[64:], offset)
	be.PutUint32(header[72:], 1)
	be.PutUint32(header[76:], 1)
	be.PutUint64(header[80:], 96)
	be.PutUint64(header[88:], 616)
	r := header[96:712]
	be.PutUint32(r, 103)
	be.PutUint32(r[8:], iterations)
	be.PutUint32(r[12:], 20)
	be.PutUint32(r[48:], 8)
	if _, err = rand.Read(r[16:36]); err != nil {
		return 0, err
	}
	if _, err = rand.Read(r[52:60]); err != nil {
		return 0, err
	}
	for i, v := range []uint32{192, 0x80000001, 7, 6} {
		be.PutUint32(r[84+i*4:], v)
	}
	keySize := int(o.KeyBits / 8)
	key := make([]byte, keySize+20+5)
	defer clear(key)
	if _, err = rand.Read(key[:keySize+20]); err != nil {
		return 0, err
	}
	copy(key[keySize+20:], "CKIE\x00")
	derived, err := storagecrypto.PBKDF2(ctx, sha1.New, o.Password, r[16:36], iterations, 24)
	defer clear(derived)
	if err != nil {
		return 0, err
	}
	wrapping, err := aes.NewCipher(derived)
	if err != nil {
		return 0, err
	}
	pad := aes.BlockSize - len(key)%aes.BlockSize
	wrapped := r[104 : 104+len(key)+pad]
	copy(wrapped, key)
	for i := len(key); i < len(wrapped); i++ {
		wrapped[i] = byte(pad)
	}
	cipher.NewCBCEncrypter(wrapping, r[52:68]).CryptBlocks(wrapped, wrapped)
	be.PutUint32(r[100:], uint32(len(wrapped)))
	payloadCipher, err := aes.NewCipher(key[:keySize])
	if err != nil {
		return 0, err
	}
	buffered := bufio.NewWriterSize(out, 128<<10)
	w := &encryptionWriter{ctx: ctx, out: buffered, cipher: payloadCipher}
	copy(w.ivKey[:], key[keySize:keySize+20])
	defer clear(w.ivKey[:])
	defer clear(w.buffer[:])
	if err = writeEncryptionBytes(ctx, out, header); err != nil {
		return 0, err
	}
	if err = produce(w); err != nil {
		return 0, err
	}
	if w.err != nil {
		return 0, w.err
	}
	if w.size < 512 {
		return 0, fmt.Errorf("encrypted image payload too short: %w", fs.ErrInvalid)
	}
	if w.used != 0 {
		clear(w.buffer[w.used:])
		if err = w.flush(); err != nil {
			return 0, err
		}
	}
	if err = ctx.Err(); err != nil {
		return 0, err
	}
	if err = buffered.Flush(); err != nil {
		return 0, err
	}
	if _, err = out.Seek(56, io.SeekStart); err != nil {
		return 0, err
	}
	var length [8]byte
	be.PutUint64(length[:], uint64(w.size))
	if err = writeEncryptionBytes(ctx, out, length[:]); err != nil {
		return 0, err
	}
	end = offset + (w.size+511)/512*512
	if _, err = out.Seek(end, io.SeekStart); err != nil {
		return 0, err
	}
	return end, ctx.Err()
}

func writeEncryptionBytes(ctx context.Context, out io.Writer, b []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := out.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return err
}

type encryptionWriter struct {
	ctx    context.Context
	out    io.Writer
	cipher cipher.Block
	ivKey  [20]byte
	buffer [512]byte
	used   int
	size   int64
	index  uint64
	err    error
}

func (w *encryptionWriter) Write(b []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	// One TiB of image storage and a 32-bit block counter are separate bounds.
	if int64(len(b)) > 1<<40-w.size {
		w.err = filesystem.ErrLimit
		return 0, w.err
	}
	n := 0
	for len(b) != 0 {
		if w.err = w.ctx.Err(); w.err != nil {
			return n, w.err
		}
		amount := copy(w.buffer[w.used:], b)
		w.used += amount
		w.size += int64(amount)
		n += amount
		b = b[amount:]
		if w.used == len(w.buffer) {
			if w.err = w.flush(); w.err != nil {
				return n, w.err
			}
		}
	}
	return n, nil
}

func (w *encryptionWriter) flush() error {
	if w.index >= 1<<32 {
		return filesystem.ErrLimit
	}
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], uint32(w.index))
	m := hmac.New(sha1.New, w.ivKey[:])
	_, _ = m.Write(counter[:])
	var iv [20]byte
	m.Sum(iv[:0])
	cipher.NewCBCEncrypter(w.cipher, iv[:16]).CryptBlocks(w.buffer[:], w.buffer[:])
	if err := writeEncryptionBytes(w.ctx, w.out, w.buffer[:]); err != nil {
		return err
	}
	w.used = 0
	w.index++
	return nil
}
