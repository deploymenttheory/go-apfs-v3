package session

import (
	"fmt"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"golang.org/x/sys/unix"
	"time"
)

func hostMetadata(p string) (filesystem.Metadata, string, error) {
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		return filesystem.Metadata{}, "", err
	}
	stamp := func(t unix.Timespec) filesystem.Observation[time.Time] {
		return filesystem.Observed(time.Unix(t.Sec, t.Nsec).UTC())
	}
	m := filesystem.Metadata{Mode: filesystem.Observed(st.Mode), UID: filesystem.Observed(st.Uid), GID: filesystem.Observed(st.Gid), ModifyTime: stamp(st.Mtim), ChangeTime: stamp(st.Ctim), AccessTime: stamp(st.Atim)}
	// Linux inode flags and security policy are not macOS BSD flags or ACLs.
	var x unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, p, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &x); err == nil && x.Mask&unix.STATX_BTIME != 0 {
		m.BirthTime = filesystem.Observed(time.Unix(x.Btime.Sec, int64(x.Btime.Nsec)).UTC())
	}
	return m, fmt.Sprintf("%d:%d", st.Dev, st.Ino), nil
}
