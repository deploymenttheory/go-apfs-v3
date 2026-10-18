package fixture

// Volume is the POSIX surface a recipe touches on a mounted volume and the
// observer reads back. Paths are absolute host paths under the mount point.
// The darwin implementation uses system calls; MemoryVolume backs tests.
type Volume interface {
	WriteFile(path string, data []byte, exclusive bool) error
	AppendFile(path string, data []byte) error
	Pwrite(path string, offset int64, data []byte) error
	Truncate(path string, size int64) error
	Mkdir(path string, mode uint32) error
	Symlink(target, path string) error
	Link(oldPath, newPath string) error
	Rename(oldPath, newPath string) error
	Remove(path string) error
	Rmdir(path string) error
	Lchmod(path string, mode uint32) error
	Chflags(path string, flags uint32) error
	// Setxattr never follows symlinks. Option is "", "create" or "replace".
	Setxattr(path, name string, data []byte, option string) error
	Removexattr(path, name string) error
	Settimes(path string, birth, modify, access int64) error
	Fullfsync(path string) error
	Clone(src, dst string) error
	// FreeBytes reports f_bavail*f_frsize for the filesystem holding path.
	FreeBytes(path string) (int64, error)

	Lstat(path string) (Stat, error)
	Readdir(path string) ([]string, error)
	Readlink(path string) ([]byte, error)
	// Listxattr and Getxattr never follow symlinks; showCompression adds
	// XATTR_SHOWCOMPRESSION so compression-owned storage is visible.
	Listxattr(path string, showCompression bool) ([]string, error)
	Getxattr(path, name string, showCompression bool) ([]byte, error)
	// Hash reads the whole file through the kernel and returns its SHA-256
	// and length; a read error is returned with whatever was read.
	Hash(path string) (string, int64, error)
	Pread(path string, offset int64, length int) ([]byte, error)
	// Extents returns [logical, physical, length] runs for the data fork
	// (fork "data") or resource fork (fork "rsrc").
	Extents(path, fork string) ([][3]int64, error)
	// Holes returns [offset, length] ranges reported as holes.
	Holes(path string) ([][2]int64, error)
	// ACL returns the raw extended security blob, or nil when absent.
	ACL(path string) ([]byte, error)
}

// Stat is lstat's view of one object.
type Stat struct {
	Kind      string // file, dir, symlink, other
	Ino       uint64
	Nlink     uint32
	Mode      uint32 // permission and set-ID bits
	UID       uint32
	GID       uint32
	Flags     uint32
	Size      int64
	Allocated int64
	Birth     int64
	Modify    int64
	Change    int64
	Access    int64
}
