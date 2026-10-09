package crypto

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
)

// PasswordKey derives the one SHA-256 block used by APFS (RFC 8018 PBKDF2).
// The caller admits the iteration budget. Cancellation is checked during the
// expensive loop, and password bytes are neither retained nor converted to text.
func PasswordKey(ctx context.Context, password, salt []byte, iterations uint64) (key [32]byte, err error) {
	if iterations == 0 {
		return key, ErrInvalid
	}
	if err = ctx.Err(); err != nil {
		return key, err
	}
	m := hmac.New(sha256.New, password)
	_, _ = m.Write(salt)
	_, _ = m.Write([]byte{0, 0, 0, 1})
	var u [32]byte
	m.Sum(u[:0])
	key = u
	defer clear(u[:])
	for i := uint64(1); i < iterations; i++ {
		if i%1024 == 0 {
			if err = ctx.Err(); err != nil {
				clear(key[:])
				return key, err
			}
		}
		m.Reset()
		_, _ = m.Write(u[:])
		m.Sum(u[:0])
		for j := range key {
			key[j] ^= u[j]
		}
	}
	if err = ctx.Err(); err != nil {
		clear(key[:])
	}
	return key, err
}
