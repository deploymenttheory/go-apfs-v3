package apfs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sync"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	storagecrypto "github.com/deploymenttheory/go-apfs-v3/internal/crypto"
)

// volumeKeys owns the expanded key schedule. Readers borrow it. Close waits for
// active decryptions and releases the schedule; Go's AES API does not expose a
// way to erase its private expanded keys. No password is retained.
type volumeKeys struct {
	mu  sync.RWMutex
	xts *storagecrypto.XTS
}

func (k *volumeKeys) check() error {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.xts == nil {
		return fs.ErrClosed
	}
	return nil
}

func (k *volumeKeys) decrypt(b []byte, sector uint64) error {
	k.mu.RLock()
	defer k.mu.RUnlock()
	if k.xts == nil {
		return fs.ErrClosed
	}
	return k.xts.Decrypt(b, b, sector)
}

func (v *Volume) access() error {
	if v.keys != nil {
		return v.keys.check()
	}
	if v.Encrypted {
		return filesystem.ErrAuthentication
	}
	return nil
}

// Unlock returns an independent read-only view of a software-encrypted volume.
// The receiver remains locked. Password bytes are borrowed for this call only;
// an empty password is distinct from not calling Unlock. The context bounds the
// unlock operation, not the lifetime of the returned view. Close the view before
// closing its backing image. Unsupported hardware/per-file key profiles fail
// explicitly. Encrypted remains true: it describes storage, not access state.
func (v *Volume) Unlock(ctx context.Context, password []byte) (*Volume, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if v.container == nil {
		return nil, corrupt("unopened volume", 0)
	}
	if !v.Encrypted {
		return nil, fmt.Errorf("volume is not encrypted: %w", fs.ErrInvalid)
	}
	if v.Flags&8 == 0 {
		return nil, fmt.Errorf("APFS per-file or hardware keys: %w", filesystem.ErrUnsupported)
	}
	c := v.container
	entries, err := c.keybag(ctx, c.keylockerStart, c.keylockerCount, c.id, 0x6b657973)
	if err != nil {
		return nil, err
	}
	var wrapped, extent []byte
	for _, e := range entries {
		if e.id != v.id {
			continue
		}
		switch e.tag {
		case 2:
			wrapped = e.data
		case 3:
			extent = e.data
		}
	}
	if wrapped == nil || len(extent) != 16 {
		return nil, corrupt("volume keybag references", 0)
	}
	vek, err := parseKeyRecord(wrapped, false)
	if err != nil {
		return nil, err
	}
	entries, err = c.keybag(ctx, le.Uint64(extent), le.Uint64(extent[8:]), v.id, 0x72656373)
	if err != nil {
		return nil, err
	}
	var candidates []keyRecord
	var work uint64
	for _, e := range entries {
		if e.tag != 3 {
			continue
		}
		k, err := parseKeyRecord(e.data, true)
		if err != nil {
			return nil, err
		}
		if k.id != e.id {
			return nil, corrupt("crypto user UUID", 0)
		}
		if k.iterations > maxPasswordIterations-work {
			return nil, filesystem.ErrLimit
		}
		work += k.iterations
		candidates = append(candidates, k)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no password key records: %w", filesystem.ErrUnsupported)
	}
	for _, candidate := range candidates {
		key, err := unlockKey(ctx, password, candidate, vek)
		if errors.Is(err, filesystem.ErrAuthentication) {
			continue
		}
		if err != nil {
			return nil, err
		}
		x, err := storagecrypto.NewXTS(key)
		clear(key)
		if err != nil {
			return nil, err
		}
		view := *v
		view.keys = &volumeKeys{xts: x}
		// A verified wrapped key is necessary but not sufficient: require a valid
		// filesystem root before exposing the view, retaining corruption errors.
		if _, err := view.Stat(ctx, view.Root()); err != nil {
			_ = view.Close()
			return nil, err
		}
		return &view, nil
	}
	return nil, filesystem.ErrAuthentication
}

func unlockKey(ctx context.Context, password []byte, kek, vek keyRecord) ([]byte, error) {
	derived, err := storagecrypto.PasswordKey(ctx, password, kek.salt, kek.iterations)
	defer clear(derived[:])
	if err != nil {
		return nil, err
	}
	key, err := storagecrypto.Unwrap(derived[:], kek.wrapped)
	if errors.Is(err, storagecrypto.ErrIntegrity) {
		return nil, filesystem.ErrAuthentication
	}
	if err != nil {
		return nil, err
	}
	defer clear(key)
	plain, err := storagecrypto.Unwrap(key, vek.wrapped)
	if errors.Is(err, storagecrypto.ErrIntegrity) {
		return nil, corrupt("wrapped volume key integrity", 0)
	}
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		clear(plain)
		return nil, err
	}
	return plain, nil
}

// Close releases an unlocked view's keys and invalidates values borrowed from
// it. It is idempotent and never closes the backing image or another unlock.
// Copies of the same unlocked Volume share this lifetime. For a locked or
// unencrypted volume Close has no effect.
func (v *Volume) Close() error {
	if v.keys != nil {
		v.keys.mu.Lock()
		v.keys.xts = nil
		v.keys.mu.Unlock()
	}
	return nil
}

func (v *Volume) object(m objectMapping, kind uint32) ([]byte, error) {
	if !m.encrypted {
		return v.container.object(m.address, kind)
	}
	if !v.Encrypted {
		return nil, corrupt("encrypted mapping on unencrypted volume", 0)
	}
	if err := v.access(); err != nil {
		return nil, err
	}
	c := v.container
	if uint64(m.address) >= c.BlockCount {
		return nil, corrupt("encrypted object address", 0)
	}
	off := int64(m.address) * int64(c.BlockSize)
	b := make([]byte, c.BlockSize)
	if err := block.ReadFull(c.source, b, off); err != nil {
		return nil, err
	}
	if err := v.keys.decrypt(b, uint64(off)/512); err != nil {
		return nil, err
	}
	if !validChecksum(b) || le.Uint32(b[24:])&0xffff != kind {
		return nil, corrupt("decrypted object checksum or type", off)
	}
	return b, nil
}

// encryptedSource maps arbitrary reads to complete sectors of one extent. The
// extent's crypto_id supplies its initial tweak, independently of its address.
type encryptedSource struct {
	source block.Source
	keys   *volumeKeys
	sector uint64
	ctx    context.Context
}

func (s *encryptedSource) Size() int64 { return s.source.Size() }
func (s *encryptedSource) ReadAt(p []byte, off int64) (int, error) {
	if err := s.keys.check(); err != nil {
		return 0, err
	}
	if err := s.ctx.Err(); err != nil {
		return 0, err
	}
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= s.Size() {
		return 0, io.EOF
	}
	want := len(p)
	if int64(len(p)) > s.Size()-off {
		p = p[:s.Size()-off]
	}
	var b [512]byte
	defer clear(b[:])
	n := 0
	for len(p) > 0 {
		if err := s.ctx.Err(); err != nil {
			return n, err
		}
		base := off &^ 511
		if err := block.ReadFull(s.source, b[:], base); err != nil {
			return n, err
		}
		if err := s.keys.decrypt(b[:], s.sector+uint64(base/512)); err != nil {
			return n, err
		}
		amount := copy(p, b[off-base:])
		p = p[amount:]
		off += int64(amount)
		n += amount
	}
	if n < want {
		return n, io.EOF
	}
	return n, nil
}

type borrowedValue struct {
	filesystem.Value
	keys *volumeKeys
}

func (v borrowedValue) ReadAt(p []byte, off int64) (int, error) {
	if err := v.keys.check(); err != nil {
		return 0, err
	}
	return v.Value.ReadAt(p, off)
}
func (v *Volume) borrow(value filesystem.Value, err error) (filesystem.Value, error) {
	if err != nil || v.keys == nil {
		return value, err
	}
	return borrowedValue{value, v.keys}, nil
}
