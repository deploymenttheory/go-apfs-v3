package crypto

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
)

// Wrap implements RFC 3394 for the bounded key sizes accepted by Unwrap.
func Wrap(key, plain []byte) ([]byte, error) {
	if (len(key) != 16 && len(key) != 32) || len(plain) < 16 || len(plain) > 64 || len(plain)%8 != 0 {
		return nil, ErrInvalid
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	wrapped := make([]byte, len(plain)+8)
	copy(wrapped[8:], plain)
	a := uint64(0xa6a6a6a6a6a6a6a6)
	blocks := len(plain) / 8
	var b [16]byte
	defer clear(b[:])
	for j := 0; j < 6; j++ {
		for i := 1; i <= blocks; i++ {
			binary.BigEndian.PutUint64(b[:], a)
			copy(b[8:], wrapped[i*8:i*8+8])
			cipher.Encrypt(b[:], b[:])
			a = binary.BigEndian.Uint64(b[:]) ^ uint64(j*blocks+i)
			copy(wrapped[i*8:], b[8:])
		}
	}
	binary.BigEndian.PutUint64(wrapped, a)
	return wrapped, nil
}

// Unwrap implements RFC 3394, including its mandatory integrity check. Wrapped
// APFS keys are small; cap the input before allocating or running unwrap rounds.
func Unwrap(key, wrapped []byte) ([]byte, error) {
	if (len(key) != 16 && len(key) != 32) || len(wrapped) < 24 || len(wrapped) > 72 || len(wrapped)%8 != 0 {
		return nil, ErrInvalid
	}
	aes, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	plain := append([]byte(nil), wrapped[8:]...)
	a := binary.BigEndian.Uint64(wrapped)
	blocks := len(plain) / 8
	var b [16]byte
	defer clear(b[:])
	for j := 5; j >= 0; j-- {
		for i := blocks; i > 0; i-- {
			binary.BigEndian.PutUint64(b[:], a^uint64(j*blocks+i))
			copy(b[8:], plain[(i-1)*8:i*8])
			aes.Decrypt(b[:], b[:])
			a = binary.BigEndian.Uint64(b[:])
			copy(plain[(i-1)*8:], b[8:])
		}
	}
	var got [8]byte
	binary.BigEndian.PutUint64(got[:], a)
	want := [8]byte{0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6, 0xa6}
	if subtle.ConstantTimeCompare(got[:], want[:]) != 1 {
		clear(plain)
		return nil, ErrIntegrity
	}
	return plain, nil
}
