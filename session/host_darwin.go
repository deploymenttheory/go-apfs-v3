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
	m := filesystem.Metadata{Mode: filesystem.Observed(uint32(st.Mode)), UID: filesystem.Observed(st.Uid), GID: filesystem.Observed(st.Gid), BSDFlags: filesystem.Observed(st.Flags), BirthTime: stamp(st.Btim), ModifyTime: stamp(st.Mtim), ChangeTime: stamp(st.Ctim), AccessTime: stamp(st.Atim)}
	// Darwin exposes logical contents and only independent resource forks through
	// the public host interfaces. Compression storage is not imported as a fork.
	m.BSDFlags.Value &^= 32
	return m, fmt.Sprintf("%d:%d", st.Dev, st.Ino), nil
}
