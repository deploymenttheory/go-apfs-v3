//go:build windows

package corpus

import (
	"os"

	"golang.org/x/sys/windows"
)

// markSparse asks NTFS to deallocate the zero runs copySparse skips; without
// it the gaps would still be allocated when the file is extended.
func markSparse(f *os.File) error {
	var returned uint32
	return windows.DeviceIoControl(windows.Handle(f.Fd()), windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &returned, nil)
}
