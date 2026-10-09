package apfs

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	storagecrypto "github.com/deploymenttheory/go-apfs-v3/internal/crypto"
)

const maxKeybagBytes = 1 << 20
const maxPasswordIterations = 10_000_000

type keybagEntry struct {
	id   [16]byte
	tag  uint16
	data []byte
}
type keyRecord struct {
	id         [16]byte
	flags      uint32
	wrapped    []byte
	iterations uint64
	salt       []byte
}

// keybag uses UUID-derived XTS sectors. This only obscures the outer container;
// password-derived keys protect the wrapped KEK and VEK inside it.
func (c *Container) keybag(ctx context.Context, start, count uint64, id [16]byte, kind uint32) ([]keybagEntry, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if count == 0 || start >= c.BlockCount || count > c.BlockCount-start {
		return nil, corrupt("keybag extent", 0)
	}
	if count > maxKeybagBytes/uint64(c.BlockSize) {
		return nil, filesystem.ErrLimit
	}
	b := make([]byte, count*uint64(c.BlockSize))
	offset := int64(start) * int64(c.BlockSize)
	if err := block.ReadFull(c.source, b, offset); err != nil {
		return nil, err
	}
	if le.Uint32(b[24:]) != kind || !validChecksum(b) {
		key := append(append([]byte(nil), id[:]...), id[:]...)
		x, err := storagecrypto.NewXTS(key)
		clear(key)
		if err != nil {
			return nil, err
		}
		if err := x.Decrypt(b, b, uint64(offset)/512); err != nil {
			return nil, err
		}
	}
	if !validChecksum(b) || le.Uint32(b[24:]) != kind || le.Uint32(b[28:]) != 0 || XID(le.Uint64(b[16:])) > c.XID {
		return nil, corrupt("keybag object", offset)
	}
	if le.Uint16(b[32:]) != 2 {
		return nil, fmt.Errorf("keybag version: %w", filesystem.ErrUnsupported)
	}
	entries, nbytes := int(le.Uint16(b[34:])), int(le.Uint32(b[36:]))
	if nbytes < 16 || nbytes > len(b)-32 || entries > (nbytes-16)/24 {
		return nil, corrupt("keybag header", offset)
	}
	if entries > 4096 {
		return nil, filesystem.ErrLimit
	}
	end, pos := 32+nbytes, 48
	result := make([]keybagEntry, 0, entries)
	seen := map[[18]byte]bool{}
	for range entries {
		if pos > end-24 {
			return nil, corrupt("keybag entry header", offset+int64(pos))
		}
		length := int(le.Uint16(b[pos+18:]))
		if length > end-pos-24 {
			return nil, corrupt("keybag entry bounds", offset+int64(pos))
		}
		var id [16]byte
		copy(id[:], b[pos:pos+16])
		var identity [18]byte
		copy(identity[:], b[pos:pos+18])
		if seen[identity] {
			return nil, corrupt("duplicate keybag entry", offset+int64(pos))
		}
		seen[identity] = true
		result = append(result, keybagEntry{id, le.Uint16(b[pos+16:]), b[pos+24 : pos+24+length]})
		pos = (pos + 24 + length + 15) &^ 15
		if pos > end {
			return nil, corrupt("keybag alignment", offset+int64(pos))
		}
	}
	if pos != end {
		return nil, corrupt("keybag trailing entries", offset+int64(pos))
	}
	return result, nil
}

// takeDER reads one definite, minimally encoded TLV. All APFS tags admitted here
// fit in one byte. Lengths are big-endian, including the multi-byte form.
func takeDER(b []byte, tag byte) (value, rest []byte, err error) {
	if len(b) < 2 || b[0] != tag {
		return nil, nil, corrupt("key record tag", 0)
	}
	n, pos := int(b[1]), 2
	if n&128 != 0 {
		width := n & 127
		if width == 0 || width > 4 || len(b) < 2+width || b[2] == 0 {
			return nil, nil, corrupt("key record length", 0)
		}
		length := uint64(0)
		for _, v := range b[2 : 2+width] {
			length = length<<8 | uint64(v)
		}
		if length < 128 || length > uint64(len(b)-2-width) {
			return nil, nil, corrupt("key record length", 0)
		}
		n, pos = int(length), 2+width
	}
	if n > len(b)-pos {
		return nil, nil, corrupt("key record bounds", 0)
	}
	return b[pos : pos+n], b[pos+n:], nil
}

func derInteger(b []byte) (uint64, error) {
	if len(b) == 0 || len(b) > 8 || (len(b) > 1 && b[0] == 0 && b[1]&128 == 0) || b[0]&128 != 0 {
		return 0, corrupt("key record integer", 0)
	}
	var value uint64
	for _, v := range b {
		value = value<<8 | uint64(v)
	}
	return value, nil
}

// parseKeyRecord checks the record's integrity before spending work on a
// password. HMAC is keyed by the documented blob cookie and record salt; it
// detects damaged storage, not knowledge of the user's password.
func parseKeyRecord(data []byte, kek bool) (keyRecord, error) {
	var result keyRecord
	b, rest, err := takeDER(data, 0x30)
	if err != nil {
		return result, err
	}
	if len(rest) != 0 {
		return result, corrupt("key record trailing bytes", 0)
	}
	version, b, err := takeDER(b, 0x80)
	if err != nil {
		return result, err
	}
	if !bytes.Equal(version, []byte{0}) {
		return result, fmt.Errorf("key record envelope version: %w", filesystem.ErrUnsupported)
	}
	digest, b, err := takeDER(b, 0x81)
	if err != nil {
		return result, err
	}
	salt, b, err := takeDER(b, 0x82)
	if err != nil {
		return result, err
	}
	if len(digest) != 32 || len(salt) != 8 {
		return result, corrupt("key record integrity fields", 0)
	}
	seed := []byte{1, 0x16, 0x20, 0x17, 0x15, 5}
	seed = append(seed, salt...)
	key := sha256.Sum256(seed)
	m := hmac.New(sha256.New, key[:])
	_, _ = m.Write(b)
	if !hmac.Equal(digest, m.Sum(nil)) {
		return result, corrupt("key record HMAC", 0)
	}
	b, rest, err = takeDER(b, 0xa3)
	if err != nil {
		return result, err
	}
	if len(rest) != 0 {
		return result, corrupt("key record payload", 0)
	}
	version, b, err = takeDER(b, 0x80)
	if err != nil {
		return result, err
	}
	if !bytes.Equal(version, []byte{0}) {
		return result, fmt.Errorf("key record payload version: %w", filesystem.ErrUnsupported)
	}
	id, b, err := takeDER(b, 0x81)
	if err != nil {
		return result, err
	}
	if len(id) != 16 {
		return result, corrupt("key record UUID", 0)
	}
	copy(result.id[:], id)
	info, b, err := takeDER(b, 0x82)
	if err != nil {
		return result, err
	}
	if len(info) != 8 {
		return result, fmt.Errorf("key record crypto profile: %w", filesystem.ErrUnsupported)
	}
	result.flags = binary.LittleEndian.Uint32(info)
	// Current native software-key records use AES-256 key wrapping. Legacy
	// flag 2 needs a distinct VEK/tweak derivation and native volume evidence.
	if result.flags&^uint32(0x10) != 0 {
		return result, fmt.Errorf("key record crypto flags %#x: %w", result.flags, filesystem.ErrUnsupported)
	}
	result.wrapped, b, err = takeDER(b, 0x83)
	if err != nil {
		return result, err
	}
	if len(result.wrapped) != 40 {
		return result, fmt.Errorf("wrapped APFS key length: %w", filesystem.ErrUnsupported)
	}
	if kek {
		iterations, tail, err := takeDER(b, 0x84)
		if err != nil {
			return result, err
		}
		b = tail
		result.iterations, err = derInteger(iterations)
		if err != nil {
			return result, err
		}
		if result.iterations == 0 {
			return result, corrupt("zero password iterations", 0)
		}
		if result.iterations > maxPasswordIterations {
			return result, filesystem.ErrLimit
		}
		result.salt, b, err = takeDER(b, 0x85)
		if err != nil {
			return result, err
		}
		if len(result.salt) != 16 {
			return result, corrupt("password salt size", 0)
		}
	}
	if len(b) != 0 {
		return result, fmt.Errorf("key record extensions: %w", filesystem.ErrUnsupported)
	}
	return result, nil
}
