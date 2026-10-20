//go:build darwin

package fixture

import (
	"strings"

	"golang.org/x/sys/unix"
)

// mountedFrom reports the device the kernel has mounted at dir; an
// unmounted directory reports the device of the filesystem containing it.
func mountedFrom(dir string) (string, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return "", err
	}
	return strings.TrimRight(string(st.Mntfromname[:clen(st.Mntfromname[:])]), "\x00"), nil
}

func clen(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return len(b)
}
