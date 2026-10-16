//go:build darwin || linux

package decoded

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func lockCache(ctx context.Context, name string) (*os.File, error) {
	file, err := openLock(name)
	if err != nil {
		return nil, err
	}
	err = waitLock(ctx, func() (bool, error) {
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return false, nil
		}
		return err == nil, err
	})
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	return file, nil
}
