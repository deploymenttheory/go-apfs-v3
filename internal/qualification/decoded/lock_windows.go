package decoded

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func lockCache(ctx context.Context, name string) (*os.File, error) {
	file, err := openLock(name)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	err = waitLock(ctx, func() (bool, error) {
		err := windows.LockFileEx(windows.Handle(file.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &overlapped)
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) || errors.Is(err, windows.ERROR_IO_PENDING) {
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
