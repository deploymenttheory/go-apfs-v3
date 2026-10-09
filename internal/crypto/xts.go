// Package crypto implements bounded storage cryptography using Go's standard
// AES, HMAC and SHA-256 primitives. Format admission belongs to the caller.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

var ErrInvalid = errors.New("invalid cryptographic input")
var ErrIntegrity = errors.New("key integrity check failed")

// XTS decrypts complete 512-byte APFS encryption sectors. Keys contain the data
// and tweak keys consecutively: 32 bytes for AES-128-XTS, 64 for AES-256-XTS.
// It is immutable and safe for concurrent use; it does not own source storage.
type XTS struct{ data, tweak cipher.Block }

func NewXTS(key []byte) (*XTS, error) {
	if len(key) != 32 && len(key) != 64 {
		return nil, ErrInvalid
	}
	a, err := aes.NewCipher(key[:len(key)/2])
	if err != nil {
		return nil, err
	}
	b, err := aes.NewCipher(key[len(key)/2:])
	if err != nil {
		return nil, err
	}
	return &XTS{a, b}, nil
}

// Decrypt allows identical or disjoint slices. It rejects partial sectors;
// APFS uses complete sectors and never requires ciphertext stealing here.
func (x *XTS) Decrypt(dst, src []byte, sector uint64) error {
	if x == nil || len(dst) != len(src) || len(src)%512 != 0 || (len(src) > 0 && uint64(len(src)/512-1) > ^uint64(0)-sector) {
		return ErrInvalid
	}
	for base := 0; base < len(src); base += 512 {
		var tweak, block [16]byte
		binary.LittleEndian.PutUint64(tweak[:], sector)
		x.tweak.Encrypt(tweak[:], tweak[:])
		for off := base; off < base+512; off += 16 {
			for i := range block {
				block[i] = src[off+i] ^ tweak[i]
			}
			x.data.Decrypt(block[:], block[:])
			for i := range block {
				dst[off+i] = block[i] ^ tweak[i]
			}
			var carry byte
			for i := range tweak {
				next := tweak[i] >> 7
				tweak[i] = tweak[i]<<1 | carry
				carry = next
			}
			tweak[0] ^= 0x87 * (carry & 1)
		}
		sector++
	}
	return nil
}
