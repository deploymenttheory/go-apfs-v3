// Package diskimage separates image decoding and partition enumeration from
// filesystem interpretation. No partition is implicitly preferred.
package diskimage

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sync"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type Partition struct {
	Index  int    `json:"index"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
}

type Image struct {
	Format       string      `json:"format"`
	PartitionMap string      `json:"partitionMap"`
	Partitions   []Partition `json:"partitions"`
	Encryption   *Encryption `json:"encryption,omitempty"`
	source       block.Source
	closer       io.Closer
	envelope     *encryptedImage
	decoded      *udif
	mu           sync.RWMutex
	closed       bool
}

// Open owns the input file. The caller must close the returned image after all
// its partition views and filesystem readers have finished using it.
func Open(path string) (*Image, error) {
	return openFile(context.Background(), path, nil, false)
}

// OpenWithPassword unlocks an encrypted DMG envelope and owns its read-only
// file. This password is independent of APFS volume credentials. It is borrowed
// only for this call, without normalization; nil is an explicitly empty password.
// ctx bounds opening/derivation, not the lifetime of the returned image.
func OpenWithPassword(ctx context.Context, path string, password []byte) (*Image, error) {
	return openFile(ctx, path, password, true)
}

func openFile(ctx context.Context, path string, password []byte, hasPassword bool) (*Image, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := block.Open(path)
	if err != nil {
		return nil, err
	}
	img, err := newImage(ctx, f, password, hasPassword)
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	img.closer = f
	return img, nil
}

// New borrows source, never closes it, and never requests writable access.
func New(source block.Source) (*Image, error) {
	return newImage(context.Background(), source, nil, false)
}

// NewWithPassword borrows encrypted storage and owns the resulting decrypted
// view. Closing the image releases its keys without closing the caller's source.
func NewWithPassword(ctx context.Context, source block.Source, password []byte) (*Image, error) {
	return newImage(ctx, source, password, true)
}

func newImage(ctx context.Context, source block.Source, password []byte, hasPassword bool) (result *Image, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source == nil || source.Size() < 512 {
		return nil, fmt.Errorf("short image: %w", filesystem.ErrCorrupt)
	}
	i := &Image{Format: "raw", source: source}
	defer func() {
		if result == nil {
			err = errors.Join(err, i.Close())
		}
	}()
	envelope, records, err := readEnvelope(source)
	if err != nil {
		return nil, err
	}
	if envelope != nil {
		if !hasPassword {
			return nil, fmt.Errorf("encrypted disk image requires a password: %w", filesystem.ErrAuthentication)
		}
		if err := envelope.unlock(ctx, password, records); err != nil {
			return nil, err
		}
		info := envelope.info
		i.envelope, i.Encryption = envelope, &info
		source, i.source = envelope, envelope
	} else if hasPassword {
		return nil, fmt.Errorf("disk image is not encrypted: %w", fs.ErrInvalid)
	}
	footer := make([]byte, 512)
	if err := block.ReadFull(source, footer, source.Size()-512); err != nil {
		return nil, err
	}
	if string(footer[:4]) == "koly" {
		decoded, err := openUDIF(source, footer)
		if err != nil {
			return nil, err
		}
		i.Format = "udif"
		i.source, i.decoded = decoded, decoded
	}
	i.source = &imageSource{i.source, i}
	i.PartitionMap, i.Partitions, err = partitions(i.source)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return i, nil
}

func (i *Image) Size() int64 { return i.source.Size() }
func (i *Image) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return nil
	}
	i.closed = true
	if i.decoded != nil {
		i.decoded.clearCache()
	}
	if i.envelope != nil {
		_ = i.envelope.Close()
	}
	if i.closer == nil {
		return nil
	}
	return i.closer.Close()
}

// Partition returns a borrowed view selected by its on-disk index.
func (i *Image) Partition(index int) (*block.Section, error) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	if i.closed {
		return nil, fs.ErrClosed
	}
	for _, p := range i.Partitions {
		if p.Index == index {
			return block.NewSection(i.source, p.Offset, p.Size)
		}
	}
	return nil, fmt.Errorf("partition %d does not exist", index)
}

// Guard above the UDIF cache. Closure waits for reads before clearing the cache,
// so an in-flight read cannot repopulate it after Close returns.
type imageSource struct {
	block.Source
	image *Image
}

func (s *imageSource) ReadAt(p []byte, off int64) (int, error) {
	s.image.mu.RLock()
	defer s.image.mu.RUnlock()
	if s.image.closed {
		return 0, fs.ErrClosed
	}
	return s.Source.ReadAt(p, off)
}
