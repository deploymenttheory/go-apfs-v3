package crypto

import (
	"context"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/binary"
	"hash"
)

// PBKDF2 derives a bounded key using RFC 8018. Callers select the format's hash
// and admit the iteration budget. Password bytes are borrowed for the call only.
// Cancellation is checked during each output block's expensive loop.
func PBKDF2(ctx context.Context, newHash func() hash.Hash, password, salt []byte, iterations uint64, size int) ([]byte, error) {
	if newHash == nil || iterations == 0 || size < 1 || size > 64 {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m := hmac.New(newHash, password)
	key := make([]byte, 0, size)
	u := make([]byte, m.Size())
	sum := make([]byte, m.Size())
	defer clear(u)
	defer clear(sum)
	for block := uint32(1); len(key) < size; block++ {
		m.Reset()
		_, _ = m.Write(salt)
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], block)
		_, _ = m.Write(counter[:])
		m.Sum(u[:0])
		copy(sum, u)
		for i := uint64(1); i < iterations; i++ {
			if i%1024 == 0 {
				if err := ctx.Err(); err != nil {
					clear(key)
					return nil, err
				}
			}
			m.Reset()
			_, _ = m.Write(u)
			m.Sum(u[:0])
			subtle.XORBytes(sum, sum, u)
		}
		key = append(key, sum[:min(len(sum), size-len(key))]...)
		if err := ctx.Err(); err != nil {
			clear(key)
			return nil, err
		}
	}
	return key, nil
}
