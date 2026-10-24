package copyfile

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"golang.org/x/sys/windows"
	"os"
	"time"
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
		return m, "", err
	}
	defer func() { err = errors.Join(err, windows.CloseHandle(h)) }()
	var st windows.ByHandleFileInformation
	if err = windows.GetFileInformationByHandle(h, &st); err != nil {
		return m, "", err
	}
	// FILE_BASIC_INFO adds ChangeTime, which the ordinary Go FileInfo does not
	// expose. ACL/owner-only races must be detected as well as data/mtime changes.
	basic := make([]byte, 40)
	if err = windows.GetFileInformationByHandleEx(h, windows.FileBasicInfo, &basic[0], uint32(len(basic))); err != nil {
		return m, "", err
	}
	stamp := func(off int) filesystem.Observation[time.Time] {
		f := windows.Filetime{LowDateTime: binary.LittleEndian.Uint32(basic[off:]), HighDateTime: binary.LittleEndian.Uint32(basic[off+4:])}
		return filesystem.Observed(time.Unix(0, f.Nanoseconds()).UTC())
	}
	m = filesystem.Metadata{BirthTime: stamp(0), AccessTime: stamp(8), ModifyTime: stamp(16), ChangeTime: stamp(24)}
	key = p
	if info.Mode().IsRegular() {
		key = fmt.Sprintf("%d:%d:%d", st.VolumeSerialNumber, st.FileIndexHigh, st.FileIndexLow)
	}
	return m, key, nil
}
