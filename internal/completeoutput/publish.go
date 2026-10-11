// Package completeoutput publishes a flushed, completed image without overwrite.
// The atomic name publication protects against process interruption. It does not
// promise directory-entry persistence after power loss on every host filesystem.
package completeoutput

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

func Publish(ctx context.Context, path string, write func(io.Writer) error) (err error) {
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
	defer func() {
		if !closed {
			err = errors.Join(err, f.Close())
		}
		removeErr := os.Remove(temporary)
		if !published && !errors.Is(removeErr, fs.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}()
	err = write(f)
	if err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
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
	err = os.Link(temporary, path)
	published = err == nil
	return err
}
