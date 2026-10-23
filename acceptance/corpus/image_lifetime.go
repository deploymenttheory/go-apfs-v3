package corpus

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

type imageLifetimes struct {
	mu      sync.Mutex
	root    string
	closed  bool
	entries map[string]*leasedImage
	// Per-owner seams exercise publication and deletion failures without
	// timing races, global overrides or native filesystem operations.
	expand func(context.Context, string, string) error
	remove func(string) error
}

type leasedImage struct {
	path    string
	derived bool
	ready   chan struct{}
	refs    int
	err     error
	retain  error
}

// ImageLease keeps one fixture alive through every borrowed reader, value and
// native attachment. Its path must not escape that lifetime.
type ImageLease struct {
	owner *Corpus
	key   string
	image *leasedImage
	mu    sync.Mutex
	done  bool
	err   error
}

func (l *ImageLease) Path() string { return l.image.path }

// AcquireImage returns a retained original or a source-and-content-bound raw copy.
// Concurrent acquisitions share only this corpus run's completed publication.
// The caller must release the lease after closing every reader/attachment.
func (c *Corpus) AcquireImage(ctx context.Context, k Case) (*ImageLease, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if k.Observation == nil || k.Observation.Image.File == "" {
		return nil, errors.New("fixture has no retained image")
	}
	source, err := filepath.Abs(filepath.Join(k.Dir, k.Observation.Image.File))
	if err != nil {
		return nil, err
	}
	derived := strings.HasSuffix(source, ".raw.gz")
	key := source
	if derived {
		if !schema.ValidDigest(k.Observation.Image.SHA256) {
			return nil, errors.New("raw fixture has no valid compressed-image digest")
		}
		key += "\x00" + k.Observation.Image.SHA256
	}
	c.images.mu.Lock()
	if c.images.closed {
		c.images.mu.Unlock()
		return nil, fs.ErrClosed
	}
	if c.images.entries == nil {
		c.images.entries = map[string]*leasedImage{}
	}
	entry, exists := c.images.entries[key]
	if exists && entry.retain != nil {
		c.images.mu.Unlock()
		return nil, fmt.Errorf("fixture backing retained at %s: %w", entry.path, entry.retain)
	}
	if !exists {
		path := source
		if derived {
			if c.images.root == "" {
				parent := c.ExpandDir
				if parent == "" {
					parent = os.TempDir()
				}
				parent, err = filepath.Abs(parent)
				if err != nil {
					c.images.mu.Unlock()
					return nil, err
				}
				if err := os.MkdirAll(parent, 0o755); err != nil {
					c.images.mu.Unlock()
					return nil, err
				}
				root, err := os.MkdirTemp(parent, "apfs-fixture-run-")
				if err != nil {
					c.images.mu.Unlock()
					return nil, err
				}
				c.images.root = root
			}
			// Equal bytes at distinct source paths remain independent images.
			// Hash the composite identity into a portable path component.
			storageKey := fmt.Sprintf("%x", sha256.Sum256([]byte(key)))
			path = filepath.Join(c.images.root, storageKey, "image.raw")
		}
		entry = &leasedImage{path: path, derived: derived, ready: make(chan struct{})}
		c.images.entries[key] = entry
	}
	entry.refs++ // Reserve before publication or the last release can delete.
	lease := &ImageLease{owner: c, key: key, image: entry}
	c.images.mu.Unlock()
	if !exists {
		var err error
		if derived {
			var digest string
			digest, err = schema.FileDigest(source)
			if err == nil && digest != k.Observation.Image.SHA256 {
				err = fmt.Errorf("compressed fixture digest changed: %s", source)
			}
			if err == nil {
				expand := c.images.expand
				if expand == nil {
					expand = ExpandGzipContext
				}
				err = expand(ctx, source, entry.path)
			}
		} else {
			_, err = os.Stat(source)
		}
		c.images.mu.Lock()
		entry.err = err
		close(entry.ready)
		c.images.mu.Unlock()
	}
	select {
	case <-ctx.Done():
		return nil, errors.Join(ctx.Err(), lease.Release(nil))
	case <-entry.ready:
	}
	c.images.mu.Lock()
	err = entry.err
	if entry.retain != nil {
		err = errors.Join(err, fmt.Errorf("fixture backing retained at %s: %w", entry.path, entry.retain))
	}
	if c.images.closed {
		err = errors.Join(err, fs.ErrClosed)
	}
	c.images.mu.Unlock()
	if err != nil {
		return nil, errors.Join(err, lease.Release(nil))
	}
	return lease, nil
}

// Release accepts cleanup certainty separately from an operation/verdict error.
// A failed native attach with unproven cleanup, failed detach or reader close
// must pass that cause. It pins the original path and returns the cause; it
// never renames or unlinks a potentially active image. Releases are idempotent.
func (l *ImageLease) Release(cleanupErr error) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.done {
		return l.err
	}
	l.done = true
	c := l.owner
	c.images.mu.Lock()
	defer c.images.mu.Unlock()
	entry := l.image
	if cleanupErr != nil {
		entry.retain = errors.Join(entry.retain, cleanupErr)
	}
	entry.refs--
	if entry.refs == 0 && entry.retain == nil {
		if entry.derived {
			remove := c.images.remove
			if remove == nil {
				remove = os.Remove
			}
			if err := remove(entry.path); err != nil && !errors.Is(err, os.ErrNotExist) {
				entry.retain = err
			}
		}
		if entry.retain == nil {
			delete(c.images.entries, l.key)
		}
	}
	if entry.retain != nil {
		l.err = fmt.Errorf("fixture backing retained at %s: %w", entry.path, entry.retain)
	}
	if c.images.closed {
		l.err = errors.Join(l.err, c.closeImages())
	}
	return l.err
}

// Close stops acquisitions and releases only this run's safe derived storage.
// Active leases and uncertain cleanup remain retained and make Close fail.
func (c *Corpus) Close() error {
	c.images.mu.Lock()
	defer c.images.mu.Unlock()
	c.images.closed = true
	return c.closeImages()
}

func (c *Corpus) closeImages() error {
	var err error
	for _, entry := range c.images.entries {
		if entry.retain != nil {
			err = errors.Join(err, fmt.Errorf("fixture backing retained at %s: %w", entry.path, entry.retain))
		} else if entry.refs != 0 {
			err = errors.Join(err, fmt.Errorf("fixture backing still has %d active leases at %s", entry.refs, entry.path))
		}
	}
	if err == nil && c.images.root != "" {
		if removeErr := os.RemoveAll(c.images.root); removeErr != nil {
			return fmt.Errorf("remove run-owned fixture directory %s: %w", c.images.root, removeErr)
		}
		c.images.root = ""
	}
	return err
}
