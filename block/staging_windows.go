package block

import (
	"errors"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows needs explicit sparse ranges: extending an ordinary file alone can
// make a later write pay for physically zeroing all preceding unwritten bytes.
// See https://learn.microsoft.com/en-us/windows/win32/fileio/sparse-file-operations.
func prepareStaging(f *os.File, size int64) (bool, error) {
	raw, err := f.SyscallConn()
	if err != nil {
		return false, err
	}
	var operationErr error
	if err = raw.Control(func(fd uintptr) {
		var returned uint32
		operationErr = windows.DeviceIoControl(windows.Handle(fd), windows.FSCTL_SET_SPARSE, nil, 0, nil, 0, &returned, nil)
	}); err != nil {
		return false, err
	}
	if errors.Is(operationErr, windows.ERROR_INVALID_FUNCTION) || errors.Is(operationErr, windows.ERROR_NOT_SUPPORTED) {
		// Sparse storage is optional. The caller writes zeros explicitly on
		// filesystems that do not support it; no source bytes are omitted.
		return false, f.Truncate(size)
	}
	if operationErr != nil {
		return false, &os.PathError{Op: "set-sparse", Path: f.Name(), Err: operationErr}
	}
	if err = f.Truncate(size); err != nil {
		return false, err
	}
	if size == 0 {
		return true, nil
	}
	zeros := windows.FileZeroDataInformation{BeyondFinalZero: size}
	if err = raw.Control(func(fd uintptr) {
		var returned uint32
		operationErr = windows.DeviceIoControl(windows.Handle(fd), windows.FSCTL_SET_ZERO_DATA,
			(*byte)(unsafe.Pointer(&zeros)), uint32(unsafe.Sizeof(zeros)), nil, 0, &returned, nil)
	}); err != nil {
		return false, err
	}
	if operationErr != nil {
		return false, &os.PathError{Op: "zero-sparse", Path: f.Name(), Err: operationErr}
	}
	return true, nil
}
