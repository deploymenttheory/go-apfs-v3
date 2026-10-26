package apfs

import (
	"context"
	"fmt"
	"io/fs"
	"sync"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// VolumeCredential supplies one volume's exact-byte password. An empty UUID is
// allowed only for a single-volume container. Password is borrowed for the
// authentication call; nil means no credential, while an empty slice is valid.
type VolumeCredential struct {
	VolumeUUID string
	Password   []byte `json:"-"`
}

// MutationSource owns authenticated keys for an exclusively owned unpublished
// source. ReadAt/WriteAt still address the original encrypted disk bytes. Open,
// InspectStorage and ordinary mutation operations borrow its volume keys; this
// is not a decrypted whole-disk adapter. Close invalidates those borrowed views
// and waits for active I/O/cryptography without closing the underlying source.
type MutationSource struct {
	source MutableSource
	mu     sync.RWMutex
	keys   map[[16]byte]*volumeKeys
	closed bool
}

// UnlockMutation authenticates every encrypted volume before ownership can be
// accounted. Credentials for independently encrypted peers are required even
// when the selected operation changes only one volume. No password is retained.
// Authentication does not itself qualify the source for writing; every engine
// operation still performs complete structural and allocation admission.
func UnlockMutation(ctx context.Context, source MutableSource, credentials ...VolumeCredential) (*MutationSource, error) {
	if source == nil {
		return nil, fs.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := Open(source)
	if err != nil {
		return nil, err
	}
	if len(credentials) > len(c.Volumes) {
		return nil, fs.ErrInvalid
	}
	result := &MutationSource{source: source, keys: map[[16]byte]*volumeKeys{}}
	for _, credential := range credentials {
		var selected *Volume
		for i := range c.Volumes {
			v := &c.Volumes[i]
			if credential.VolumeUUID == v.UUID || credential.VolumeUUID == "" && len(c.Volumes) == 1 {
				selected = v
				break
			}
		}
		if selected == nil {
			_ = result.Close()
			return nil, fs.ErrNotExist
		}
		if credential.Password == nil || !selected.Encrypted || result.keys[selected.id] != nil {
			_ = result.Close()
			return nil, fs.ErrInvalid
		}
		view, err := selected.Unlock(ctx, credential.Password)
		if err != nil {
			_ = result.Close()
			return nil, fmt.Errorf("volume %s: %w", selected.UUID, err)
		}
		result.keys[selected.id] = view.keys
	}
	for _, v := range c.Volumes {
		if v.Encrypted && result.keys[v.id] == nil {
			_ = result.Close()
			return nil, fmt.Errorf("credential required for volume %s: %w", v.UUID, filesystem.ErrAuthentication)
		}
	}
	return result, nil
}

func (s *MutationSource) Size() int64 { return s.source.Size() }

func (s *MutationSource) ReadAt(b []byte, off int64) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0, fs.ErrClosed
	}
	return s.source.ReadAt(b, off)
}

func (s *MutationSource) WriteAt(b []byte, off int64) (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0, fs.ErrClosed
	}
	return s.source.WriteAt(b, off)
}

func (s *MutationSource) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		for _, key := range s.keys {
			key.mu.Lock()
			key.xts = nil
			key.mu.Unlock()
		}
	}
	return nil
}

func (s *MutationSource) mutationKeys(id [16]byte) *volumeKeys {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.keys[id]
}

func sourceVolumeKeys(source block.Source, id [16]byte) *volumeKeys {
	if authenticated, ok := source.(interface{ mutationKeys([16]byte) *volumeKeys }); ok {
		return authenticated.mutationKeys(id)
	}
	return nil
}

func (s readOnlyMutation) mutationKeys(id [16]byte) *volumeKeys {
	return sourceVolumeKeys(s.Source, id)
}
