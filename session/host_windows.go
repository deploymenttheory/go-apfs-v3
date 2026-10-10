package session

import (
	"fmt"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"golang.org/x/sys/windows"
	"os"
	"syscall"
	"time"
)

func hostMetadata(p string) (filesystem.Metadata, string, error) {
	info, err := os.Lstat(p)
	if err != nil {
		return filesystem.Metadata{}, "", err
	}
	m := filesystem.Metadata{ModifyTime: filesystem.Observed(info.ModTime().UTC())}
	if st, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
		m.BirthTime = filesystem.Observed(time.Unix(0, st.CreationTime.Nanoseconds()).UTC())
		m.AccessTime = filesystem.Observed(time.Unix(0, st.LastAccessTime.Nanoseconds()).UTC())
	}
	key := p
	if info.Mode().IsRegular() {
		f, err := os.Open(p)
		if err != nil {
			return m, "", err
		}
		var st windows.ByHandleFileInformation
		e := windows.GetFileInformationByHandle(windows.Handle(f.Fd()), &st)
		closeErr := f.Close()
		if e != nil {
			return m, "", e
		}
		if closeErr != nil {
			return m, "", closeErr
		}
		key = fmt.Sprintf("%d:%d:%d", st.VolumeSerialNumber, st.FileIndexHigh, st.FileIndexLow)
	}
	return m, key, nil
}
