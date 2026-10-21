package acceptance_test

import (
	"os"
	"syscall"
	"testing"
	"time"
)

func observeHostImportMetadata(t *testing.T, info os.FileInfo) hostImportObservation {
	t.Helper()
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		t.Fatalf("host stat has unexpected metadata type %T", info.Sys())
	}
	return hostImportObservation{info: info, mode: st.Mode, uid: st.Uid, gid: st.Gid, access: time.Unix(st.Atim.Sec, st.Atim.Nsec)}
}
