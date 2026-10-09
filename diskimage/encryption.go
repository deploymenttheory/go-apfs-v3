package diskimage

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/sha1" // Apple's existing encrypted-image format requires SHA-1.
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"sync"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	storagecrypto "github.com/deploymenttheory/go-apfs-v3/internal/crypto"
)

const maxImagePasswordIterations = 10_000_000

// Encryption describes the outer disk-image envelope, independently of any
// filesystem encryption inside it. Passwords and keys are never exposed here.
type Encryption struct {
	Version   uint32 `json:"version"`
	Cipher    string `json:"cipher"`
	KeyBits   uint32 `json:"keyBits"`
	BlockSize uint32 `json:"blockSize"`
}

type imagePasswordRecord struct {
	iterations        uint64
	salt, iv, wrapped []byte
	algorithm         uint32
}

type encryptedImage struct {
	info         Encryption
	source       block.Source
	offset, size int64
	mu           sync.RWMutex
	aes          cipher.Block
	ivKey        [20]byte
}

// readEnvelope admits only the password-based encrcdsa v2 profile. Old cdsaencr
// footers are identified explicitly, rather than mistaken for partition data.
func readEnvelope(source block.Source) (*encryptedImage, []imagePasswordRecord, error) {
	if source == nil || source.Size() < 512 {
		return nil, nil, corrupt("short image")
	}
	b := make([]byte, 76)
	if err := block.ReadFull(source, b, 0); err != nil {
		return nil, nil, err
	}
	if string(b[:8]) != "encrcdsa" {
		var tail [8]byte
		if err := block.ReadFull(source, tail[:], source.Size()-8); err != nil {
			return nil, nil, err
		}
		if string(tail[:]) == "cdsaencr" {
			return nil, nil, fmt.Errorf("encrypted image version 1: %w", filesystem.ErrUnsupported)
		}
		return nil, nil, nil
	}
	be := binary.BigEndian
	version, bits, size := be.Uint32(b[8:]), be.Uint32(b[24:]), be.Uint32(b[52:])
	if version != 2 || be.Uint32(b[12:]) != 16 || be.Uint32(b[16:]) != 5 || be.Uint32(b[20:]) != 0x80000001 || (bits != 128 && bits != 256) || be.Uint32(b[28:]) != 91 || be.Uint32(b[32:]) != 160 {
		return nil, nil, fmt.Errorf("encrypted image cipher profile: %w", filesystem.ErrUnsupported)
	}
	if size < 512 || size > 65536 || size&(size-1) != 0 {
		return nil, nil, fmt.Errorf("encrypted image block size: %w", filesystem.ErrUnsupported)
	}
	length, offset, count := be.Uint64(b[56:]), be.Uint64(b[64:]), be.Uint32(b[72:])
	if count > 64 {
		return nil, nil, filesystem.ErrLimit
	}
	if count == 0 || length < 512 || offset > uint64(source.Size()) || length > uint64(source.Size())-offset || offset%uint64(size) != 0 || offset < 76+uint64(count)*20 {
		return nil, nil, corrupt("encrypted image data range or key table")
	}
	blocks := (length-1)/uint64(size) + 1
	if blocks > 1<<32 {
		return nil, nil, filesystem.ErrLimit
	}
	if blocks > (uint64(source.Size())-offset)/uint64(size) {
		return nil, nil, corrupt("encrypted image final block")
	}
	table := make([]byte, count*20)
	if err := block.ReadFull(source, table, 76); err != nil {
		return nil, nil, err
	}
	type span struct{ start, end uint64 }
	var spans []span
	var records []imagePasswordRecord
	var work uint64
	for n := range count {
		e := table[n*20:]
		kind, start, length := be.Uint32(e), be.Uint64(e[4:]), be.Uint64(e[12:])
		if start < 76+uint64(len(table)) || start > offset || length == 0 || length > offset-start {
			return nil, nil, corrupt("encrypted image key record range")
		}
		if length > 4096 {
			return nil, nil, filesystem.ErrLimit
		}
		spans = append(spans, span{start, start + length})
		if kind == 2 || kind == 3 {
			continue
		} // Certificate/keybag entries are not password credentials.
		if kind != 1 {
			return nil, nil, fmt.Errorf("encrypted image key record type: %w", filesystem.ErrUnsupported)
		}
		raw := make([]byte, length)
		if err := block.ReadFull(source, raw, int64(start)); err != nil {
			return nil, nil, err
		}
		r, err := readImagePasswordRecord(raw, bits)
		if err != nil {
			return nil, nil, err
		}
		if r.iterations > maxImagePasswordIterations-work {
			return nil, nil, filesystem.ErrLimit
		}
		work += r.iterations
		records = append(records, r)
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return nil, nil, corrupt("overlapping encrypted image key records")
		}
	}
	if len(records) == 0 {
		return nil, nil, fmt.Errorf("encrypted image has no password record: %w", filesystem.ErrUnsupported)
	}
	return &encryptedImage{info: Encryption{version, "AES-CBC", bits, size}, source: source, offset: int64(offset), size: int64(length)}, records, nil
}

func readImagePasswordRecord(b []byte, dataBits uint32) (imagePasswordRecord, error) {
	var r imagePasswordRecord
	if len(b) < 104 {
		return r, corrupt("short encrypted image password record")
	}
	be := binary.BigEndian
	if be.Uint32(b) != 103 || be.Uint32(b[4:]) != 0 || be.Uint32(b[84:]) != 192 || be.Uint32(b[92:]) != 7 || be.Uint32(b[96:]) != 6 {
		return r, fmt.Errorf("encrypted image password profile: %w", filesystem.ErrUnsupported)
	}
	r.iterations = uint64(be.Uint32(b[8:]))
	if r.iterations == 0 {
		return r, corrupt("zero image password iterations")
	}
	if r.iterations > maxImagePasswordIterations {
		return r, filesystem.ErrLimit
	}
	saltSize, ivSize, wrappedSize := be.Uint32(b[12:]), be.Uint32(b[48:]), be.Uint32(b[100:])
	if saltSize == 0 || saltSize > 32 || ivSize == 0 || ivSize > 32 || uint64(wrappedSize) > uint64(len(b)-104) {
		return r, corrupt("encrypted image password field bounds")
	}
	r.algorithm = be.Uint32(b[88:])
	blockSize := 8
	switch r.algorithm {
	case 17: // CSSM_ALGID_3DES_3KEY_EDE, used by older Apple images.
		if ivSize != 8 {
			return r, fmt.Errorf("image 3DES wrapping IV: %w", filesystem.ErrUnsupported)
		}
	case 0x80000001: // Native current images wrap with AES-192-CBC.
		blockSize = 16
		// Current native records still declare an 8-byte IV; its second half
		// is zero. The record retains the older CBCPadIV8 mode identifier.
		if ivSize != 8 && ivSize != 16 {
			return r, fmt.Errorf("image AES wrapping IV: %w", filesystem.ErrUnsupported)
		}
	default:
		return r, fmt.Errorf("image key wrapping algorithm: %w", filesystem.ErrUnsupported)
	}
	plainSize := int(dataBits/8) + 20 + 5 // AES key, IV derivation key, CKIE terminator.
	if int(wrappedSize) != (plainSize/blockSize+1)*blockSize {
		return r, corrupt("encrypted image wrapped key size")
	}
	r.iv = make([]byte, blockSize)
	copy(r.iv, b[52:52+ivSize])
	r.salt, r.wrapped = b[16:16+saltSize], b[104:104+wrappedSize]
	return r, nil
}

func (s *encryptedImage) unlock(ctx context.Context, password []byte, records []imagePasswordRecord) error {
	for _, r := range records {
		key, err := unwrapImageKey(ctx, password, r)
		if err != nil {
			return err
		}
		if key == nil {
			continue
		}
		keySize := int(s.info.KeyBits / 8)
		if len(key) != keySize+20+5 || subtle.ConstantTimeCompare(key[len(key)-5:], []byte("CKIE\x00")) != 1 {
			clear(key)
			continue
		}
		s.aes, err = aes.NewCipher(key[:keySize])
		copy(s.ivKey[:], key[keySize:keySize+20])
		clear(key)
		return err
	}
	return fmt.Errorf("disk image password: %w", filesystem.ErrAuthentication)
}

// The format has padding and a CKIE terminator, not an authenticated key blob.
// A damaged wrapped key can therefore be indistinguishable from a bad password.
func unwrapImageKey(ctx context.Context, password []byte, r imagePasswordRecord) ([]byte, error) {
	derived, err := storagecrypto.PBKDF2(ctx, sha1.New, password, r.salt, r.iterations, 24)
	defer clear(derived)
	if err != nil {
		return nil, err
	}
	var c cipher.Block
	if r.algorithm == 17 {
		c, err = des.NewTripleDESCipher(derived)
	} else {
		c, err = aes.NewCipher(derived)
	}
	if err != nil {
		return nil, err
	}
	b := bytes.Clone(r.wrapped)
	cipher.NewCBCDecrypter(c, r.iv).CryptBlocks(b, b)
	pad := int(b[len(b)-1])
	valid := subtle.ConstantTimeLessOrEq(1, pad) & subtle.ConstantTimeLessOrEq(pad, c.BlockSize())
	for i := range c.BlockSize() {
		match := subtle.ConstantTimeByteEq(b[len(b)-1-i], byte(pad))
		valid &= match | (1 ^ subtle.ConstantTimeLessOrEq(i+1, pad))
	}
	if valid != 1 {
		clear(b)
		return nil, nil
	}
	plain := bytes.Clone(b[:len(b)-pad])
	clear(b)
	return plain, nil
}

func (s *encryptedImage) Size() int64 { return s.size }
func (s *encryptedImage) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.aes = nil
	clear(s.ivKey[:])
	return nil
}

func (s *encryptedImage) decrypt(b []byte, index uint32) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.aes == nil {
		return fs.ErrClosed
	}
	var counter [4]byte
	binary.BigEndian.PutUint32(counter[:], index)
	m := hmac.New(sha1.New, s.ivKey[:])
	_, _ = m.Write(counter[:])
	var iv [20]byte
	m.Sum(iv[:0])
	cipher.NewCBCDecrypter(s.aes, iv[:16]).CryptBlocks(b, b)
	return nil
}

func (s *encryptedImage) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= s.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(len(p)) > s.size-off {
		p = p[:s.size-off]
	}
	blockSize := int64(s.info.BlockSize)
	b := make([]byte, blockSize)
	defer clear(b)
	n := 0
	for len(p) > 0 {
		index := off / blockSize
		if err := block.ReadFull(s.source, b, s.offset+index*blockSize); err != nil {
			return n, err
		}
		if err := s.decrypt(b, uint32(index)); err != nil {
			return n, err
		}
		amount := copy(p, b[off%blockSize:])
		p = p[amount:]
		off += int64(amount)
		n += amount
	}
	if n < want {
		return n, io.EOF
	}
	return n, nil
}
