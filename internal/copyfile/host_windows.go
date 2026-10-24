package copyfile

import (
	"errors"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"golang.org/x/sys/windows"
	"os"
	"time"
	"unsafe"
)

func hostMetadata(p string) (m filesystem.Metadata, key string, err error) {
	info, err := os.Lstat(p)
	if err != nil {
		return m, "", err
	}
	name, err := windows.UTF16PtrFromString(p)
	if err != nil {
		return m, "", err
	}
	h, err := windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return m, "", &os.PathError{Op: "CreateFileW(host metadata)", Path: p, Err: err}
	}
	defer func() {
		if closeErr := windows.CloseHandle(h); closeErr != nil {
			err = errors.Join(err, &os.PathError{Op: "CloseHandle(host metadata)", Path: p, Err: closeErr})
		}
	}()
	var st windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &st); err != nil {
		return m, "", &os.PathError{Op: "GetFileInformationByHandle", Path: p, Err: err}
	}
	// FILE_BASIC_INFO adds ChangeTime, which the ordinary Go FileInfo does not
	// expose. ACL/owner-only races must be detected as well as data/mtime changes.
	var basic windowsFileBasicInformation
	if err = windows.GetFileInformationByHandleEx(h, windows.FileBasicInfo, (*byte)(unsafe.Pointer(&basic)), uint32(unsafe.Sizeof(basic))); err != nil {
		return m, "", &os.PathError{Op: "GetFileInformationByHandleEx(FileBasicInfo)", Path: p, Err: err}
	}
	stamp := func(value uint64) filesystem.Observation[time.Time] {
		f := windows.Filetime{LowDateTime: uint32(value), HighDateTime: uint32(value >> 32)}
		return filesystem.Observed(time.Unix(0, f.Nanoseconds()).UTC())
	}
	m = filesystem.Metadata{BirthTime: stamp(basic.CreationTime), AccessTime: stamp(basic.LastAccessTime), ModifyTime: stamp(basic.LastWriteTime), ChangeTime: stamp(basic.ChangeTime)}
	key = p
	if info.Mode().IsRegular() {
		key = fmt.Sprintf("%d:%d:%d", st.VolumeSerialNumber, st.FileIndexHigh, st.FileIndexLow)
	}
	return m, key, nil
}
