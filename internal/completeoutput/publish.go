// Package completeoutput publishes a flushed, completed image without overwrite.
// The atomic name publication protects against process interruption. File data
// is flushed on every host; Unix also flushes the containing directory. These
// calls depend on the host filesystem/storage honoring its persistence contract.
package completeoutput

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// PublishedError means the completed output is already visible. Callers must
// retain it and report this outcome, rather than retry or describe it as absent.
// Persisted distinguishes a failed directory flush from later cleanup failure.
type PublishedError = filesystem.PublishedOutputError

// AfterPublication preserves the visible-output outcome when a higher layer's
// deferred scratch/input cleanup fails after Publish has completed.
func AfterPublication(path string, err error) error {
	if err == nil {
		return nil
	}
	var outcome *PublishedError
	if errors.As(err, &outcome) {
		return err
	}
	return &PublishedError{Path: path, Persisted: true, Err: err}
}

// Operations are per-invocation fault seams; production always uses OS calls.
type operations struct {
	syncFile      func(*os.File) error
	link          func(string, string) error
	remove        func(string) error
	syncDirectory func(string) error
}

func Publish(ctx context.Context, path string, write func(io.Writer) error) error {
	return publish(ctx, path, write, operations{
		syncFile: (*os.File).Sync, link: os.Link, remove: os.Remove,
		syncDirectory: syncDirectory,
	})
}

func publish(ctx context.Context, path string, write func(io.Writer) error, ops operations) (err error) {
	if err = ctx.Err(); err != nil {
		return err
	}
	if _, e := os.Lstat(path); e == nil {
		return fs.ErrExist
	} else if !errors.Is(e, fs.ErrNotExist) {
		return e
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".apfs-pack-*")
	if err != nil {
		return err
	}
	temporary := f.Name()
	closed := false
	published := false
	persisted := false
	removed := false
	defer func() {
		if !closed {
			err = errors.Join(err, f.Close())
		}
		if !removed {
			removeErr := ops.remove(temporary)
			if !errors.Is(removeErr, fs.ErrNotExist) {
				err = errors.Join(err, removeErr)
			}
		}
		if published && err != nil {
			err = &PublishedError{Path: path, Persisted: persisted, Err: err}
		}
	}()
	err = write(f)
	if err != nil {
		return err
	}
	if err = ops.syncFile(f); err != nil {
		return err
	}
	err = f.Close()
	closed = true
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	err = ops.link(temporary, path)
	published = err == nil
	if err != nil {
		return err
	}
	// Once the name is visible, cancellation cannot retract it. Finish the
	// directory flush and report any failure as an already-published outcome.
	removeErr := ops.remove(temporary)
	removed = removeErr == nil || errors.Is(removeErr, fs.ErrNotExist)
	if removed {
		removeErr = nil
	}
	flushErr := ops.syncDirectory(filepath.Dir(path))
	persisted = flushErr == nil
	err = errors.Join(removeErr, flushErr)
	return err
}
