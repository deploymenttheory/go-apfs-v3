package block

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
)

// Staging owns an unpublished regular-file copy of immutable disk bytes. It
// never opens a caller-supplied path for writing. Memory use is independent of
// disk size; temporary storage requires the complete decoded disk size.
// Callers must discard it after any error. Close removes its scratch file.
type Staging struct {
	file   *os.File
	size   int64
	failed error
	closed bool
}

func Stage(ctx context.Context, source Source, directory string) (_ *Staging, err error) {
	if source == nil || source.Size() < 0 {
		return nil, fs.ErrInvalid
	}
	f, err := os.CreateTemp(directory, ".apfs-edit-disk-*")
	if err != nil {
		return nil, err
	}
	s := &Staging{file: f, size: source.Size()}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.Close())
		}
	}()
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	zeroed, err := prepareStaging(f, s.size)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 128<<10)
	zero := make([]byte, len(buf))
	for off := int64(0); off < s.size; {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		n := min(int64(len(buf)), s.size-off)
		if err = ReadFull(source, buf[:n], off); err != nil {
			return nil, err
		}
		// Preparation establishes the complete length and zero-filled holes.
		// Hosts without that guarantee receive every byte, including zeros.
		if !zeroed || !bytes.Equal(buf[:n], zero[:n]) {
			if _, err = s.WriteAt(buf[:n], off); err != nil {
				return nil, err
			}
		}
		off += n
	}
	return s, nil
}

func (s *Staging) Size() int64 { return s.size }
func (s *Staging) ReadAt(p []byte, off int64) (int, error) {
	if s.closed {
		return 0, fs.ErrClosed
	}
	if s.failed != nil {
		return 0, s.failed
	}
	return readAt(s.file, s.size, p, off)
}
func (s *Staging) WriteAt(p []byte, off int64) (n int, err error) {
	if s.closed {
		return 0, fs.ErrClosed
	}
	if s.failed != nil {
		return 0, s.failed
	}
	if off < 0 || off > s.size || int64(len(p)) > s.size-off {
		return 0, fs.ErrInvalid
	}
	n, err = s.file.WriteAt(p, off)
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		s.failed = err
	}
	return n, err
}
func (s *Staging) Sync() error {
	if s.closed {
		return fs.ErrClosed
	}
	if s.failed != nil {
		return s.failed
	}
	s.failed = s.file.Sync()
	return s.failed
}
func (s *Staging) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	return errors.Join(s.file.Close(), os.Remove(s.file.Name()))
}
