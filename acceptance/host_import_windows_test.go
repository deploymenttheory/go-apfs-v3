package acceptance_test

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func observeHostImportMetadata(t *testing.T, info os.FileInfo) hostImportObservation {
	t.Helper()
	st, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		t.Fatalf("host stat has unexpected metadata type %T", info.Sys())
	}
	mode := uint32(0o100644)
	if info.IsDir() {
		mode = 0o040755
	} else if info.Mode()&os.ModeSymlink != 0 {
		mode = 0o120777
	}
	return hostImportObservation{info: info, mode: mode, uid: hostImportUID, gid: hostImportGID, access: time.Unix(0, st.LastAccessTime.Nanoseconds())}
}
