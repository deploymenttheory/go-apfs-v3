package crypto

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"
)

// Independently produced success vectors live in acceptance/cryptography_test.go.
// These checks isolate admission and cancellation, not self-roundtrip success.
func TestCryptoInputBounds(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33, 48, 63, 65} {
		if _, err := NewXTS(make([]byte, size)); !errors.Is(err, ErrInvalid) {
			t.Fatal(size, err)
		}
	}
	x, err := NewXTS(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	for _, size := range []int{1, 16, 511, 513} {
		out := bytes.Repeat([]byte{0x55}, size)
		if err := x.Decrypt(out, make([]byte, size), 0); !errors.Is(err, ErrInvalid) {
			t.Fatal(size, err)
		}
		if !bytes.Equal(out, bytes.Repeat([]byte{0x55}, size)) {
			t.Fatal("invalid request wrote output")
		}
	}
	if err := x.Decrypt(make([]byte, 1024), make([]byte, 1024), ^uint64(0)); !errors.Is(err, ErrInvalid) {
		t.Fatal("sector overflow", err)
	}
	for _, size := range []int{0, 8, 16, 23, 25, 80} {
		if _, err := Unwrap(make([]byte, 16), make([]byte, size)); !errors.Is(err, ErrInvalid) {
			t.Fatal(size, err)
		}
	}
	if _, err := PBKDF2(context.Background(), sha256.New, nil, nil, 0, 32); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

type cancelDuringWork struct {
	context.Context
	calls int
}

func (c *cancelDuringWork) Err() error {
	c.calls++
	if c.calls >= 4 {
		return context.Canceled
	}
	return nil
}
func TestPasswordDerivationCancellationClearsPartialKey(t *testing.T) {
	ctx := &cancelDuringWork{Context: context.Background()}
	key, err := PBKDF2(ctx, sha256.New, []byte("public fixture password"), make([]byte, 16), 1_000_000, 32)
	if !errors.Is(err, context.Canceled) || key != nil || ctx.calls != 4 {
		t.Fatal("derivation did not stop and clear its partial result", err, ctx.calls)
	}
}

func FuzzKeyUnwrap(f *testing.F) {
	f.Add(make([]byte, 16), make([]byte, 24))
	f.Fuzz(func(t *testing.T, key, data []byte) { _, _ = Unwrap(key, data) })
}
