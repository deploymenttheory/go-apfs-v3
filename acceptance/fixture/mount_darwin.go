//go:build darwin

package fixture

import (
	"strings"

	"golang.org/x/sys/unix"
)

func mountedFilesystem(dir string) (mountIdentity, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return mountIdentity{}, err
	}
	return mountIdentity{
		MountPoint: strings.TrimRight(string(st.Mntonname[:clen(st.Mntonname[:])]), "\x00"),
		Source:     strings.TrimRight(string(st.Mntfromname[:clen(st.Mntfromname[:])]), "\x00"),
		FSID:       st.Fsid.Val,
	}, nil
}

func clen(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}
