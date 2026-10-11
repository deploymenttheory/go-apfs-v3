package crypto

import (
	"context"
	"crypto/sha1" // Apple's encrypted DMG password profile.
	"testing"
)

func BenchmarkPBKDF2ImagePassword(b *testing.B) {
	password, salt := []byte("public benchmark password"), make([]byte, 20)
	for b.Loop() {
		key, err := PBKDF2(context.Background(), sha1.New, password, salt, 600000, 24)
		if err != nil {
			b.Fatal(err)
		}
		clear(key)
	}
}
