//go:build darwin || linux

package session

import (
	"bytes"
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"golang.org/x/sys/unix"
	"io/fs"
	"runtime"
	"strings"
)

func hostAttributes(p string) ([]string, error) {
	n, err := unix.Llistxattr(p, nil)
	if errors.Is(err, unix.ENOTSUP) {
		return nil, filesystem.ErrUnsupported
	}
	if err != nil {
		return nil, err
	}
	if n > 1<<20 {
		return nil, filesystem.ErrLimit
	}
	b := make([]byte, n)
	count, err := unix.Llistxattr(p, b)
	if err != nil {
		return nil, err
	}
	if count != n {
		return nil, filesystem.ErrConflict
	}
	if n == 0 {
		return nil, nil
	}
	if b[n-1] != 0 {
		return nil, filesystem.ErrCorrupt
	}
	return strings.Split(string(b[:n-1]), "\x00"), nil
}
func hostAttribute(p, name string, limit int64) (filesystem.Value, error) {
	if runtime.GOOS == "darwin" && name == filesystem.ResourceFork {
		return block.Open(p + "/..namedfork/rsrc")
	}
	n, err := unix.Lgetxattr(p, name, nil)
	if err != nil {
		return nil, err
	}
	if n < 0 || int64(n) > limit || n > 64<<20 {
		return nil, filesystem.ErrLimit
	}
	b := make([]byte, n)
	got, err := unix.Lgetxattr(p, name, b)
	if err != nil {
		return nil, err
	}
	if got != n {
		return nil, filesystem.ErrConflict
	}
	return &memoryValue{Reader: bytes.NewReader(b)}, nil
}

type memoryValue struct {
	*bytes.Reader
	closed bool
}

func (v *memoryValue) Close() error { v.closed = true; return nil }
func (v *memoryValue) ReadAt(b []byte, off int64) (int, error) {
	if v.closed {
		return 0, fs.ErrClosed
	}
	return v.Reader.ReadAt(b, off)
}
