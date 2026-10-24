package copyfile

import (
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"golang.org/x/sys/windows"
)

// Windows named streams have no implicit macOS attribute mapping. Enumeration
// still distinguishes a genuinely empty inventory from a refused conversion.
func hostAttributes(path string) (names []string, err error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, err
	}
	defer func() {
		if closeErr := windows.CloseHandle(h); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()
	for size := 4096; size <= 1<<20; size *= 2 {
		buf := make([]byte, size)
		err = windows.GetFileInformationByHandleEx(h, windows.FileStreamInfo, &buf[0], uint32(len(buf)))
		if errors.Is(err, windows.ERROR_HANDLE_EOF) {
			return nil, nil
		}
		if errors.Is(err, windows.ERROR_MORE_DATA) || errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) || errors.Is(err, windows.ERROR_BAD_LENGTH) {
			continue
		}
		if errors.Is(err, windows.ERROR_NOT_SUPPORTED) || errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return nil, filesystem.ErrUnsupported
		}
		if err != nil {
			return nil, err
		}
		named, e := namedHostStreams(buf)
		if e != nil {
			return nil, e
		}
		if named {
			return nil, errHostAttributeConversion
		}
		return nil, nil
	}
	return nil, filesystem.ErrLimit
}
func hostAttribute(string, string, int64) (filesystem.Value, error) {
	return nil, filesystem.ErrUnsupported
}
