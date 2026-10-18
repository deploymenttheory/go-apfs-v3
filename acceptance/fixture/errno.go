package fixture

import (
	"fmt"
	"syscall"
)

// errnoNames covers every errno a recipe may declare as an expectation.
var errnoNames = map[syscall.Errno]string{
	syscall.EPERM:        "EPERM",
	syscall.ENOENT:       "ENOENT",
	syscall.EIO:          "EIO",
	syscall.EEXIST:       "EEXIST",
	syscall.EXDEV:        "EXDEV",
	syscall.ENOTDIR:      "ENOTDIR",
	syscall.EISDIR:       "EISDIR",
	syscall.EINVAL:       "EINVAL",
	syscall.ENOSPC:       "ENOSPC",
	syscall.ERANGE:       "ERANGE",
	syscall.ENAMETOOLONG: "ENAMETOOLONG",
	syscall.ENOTEMPTY:    "ENOTEMPTY",
	syscall.EDQUOT:       "EDQUOT",
	syscall.Errno(93):    "ENOATTR",
}

func errnoName(e syscall.Errno) string {
	if name, ok := errnoNames[e]; ok {
		return name
	}
	return fmt.Sprintf("errno-%d", int(e))
}

// ErrnoByName returns the errno for a declared expectation name.
func ErrnoByName(name string) (syscall.Errno, bool) {
	for e, n := range errnoNames {
		if n == name {
			return e, true
		}
	}
	return 0, false
}
