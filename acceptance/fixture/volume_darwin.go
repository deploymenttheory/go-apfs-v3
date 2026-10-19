//go:build darwin && (fixture || native)

package fixture

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// HostVolume is the darwin Volume: every operation is a system call on the
// mounted fixture volume. It knows nothing about on-disk formats.
type HostVolume struct{}

func (HostVolume) WriteFile(path string, data []byte, exclusive bool) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_TRUNC
	if exclusive {
		flags |= os.O_EXCL
	}
	f, err := os.OpenFile(path, flags, 0o644)
	if err != nil {
		return unwrap(err)
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return unwrap(err)
}

func (HostVolume) AppendFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return unwrap(err)
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return unwrap(err)
}

func (HostVolume) Pwrite(path string, offset int64, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE, 0o644)
	if err != nil {
		return unwrap(err)
	}
	_, err = f.WriteAt(data, offset)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return unwrap(err)
}

func (HostVolume) Truncate(path string, size int64) error { return unwrap(os.Truncate(path, size)) }
func (HostVolume) Mkdir(path string, mode uint32) error {
	return unwrap(os.Mkdir(path, os.FileMode(mode)))
}
func (HostVolume) Symlink(target, path string) error  { return unwrap(os.Symlink(target, path)) }
func (HostVolume) Link(oldPath, newPath string) error { return unwrap(os.Link(oldPath, newPath)) }

// Rename calls rename(2) directly: os.Rename reports EEXIST where the
// kernel reports EISDIR or ENOTDIR, and those errnos are observations.
func (HostVolume) Rename(oldPath, newPath string) error { return unwrap(unix.Rename(oldPath, newPath)) }
func (HostVolume) Remove(path string) error             { return unwrap(unix.Unlink(path)) }
func (HostVolume) Rmdir(path string) error              { return unwrap(unix.Rmdir(path)) }

func (HostVolume) Lchmod(path string, mode uint32) error {
	return unwrap(unix.Fchmodat(unix.AT_FDCWD, path, mode, unix.AT_SYMLINK_NOFOLLOW))
}

func (HostVolume) Chflags(path string, flags uint32) error {
	return unwrap(unix.Chflags(path, int(flags)))
}

func (HostVolume) Setxattr(path, name string, data []byte, option string) error {
	flags := unix.XATTR_NOFOLLOW
	switch option {
	case "create":
		flags |= unix.XATTR_CREATE
	case "replace":
		flags |= unix.XATTR_REPLACE
	}
	var ptr unsafe.Pointer
	if len(data) > 0 {
		ptr = unsafe.Pointer(&data[0])
	}
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return err
	}
	n, err := unix.BytePtrFromString(name)
	if err != nil {
		return err
	}
	_, _, e := syscall.Syscall6(syscall.SYS_SETXATTR, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(n)), uintptr(ptr), uintptr(len(data)), 0, uintptr(flags))
	if e != 0 {
		return e
	}
	return nil
}

func (HostVolume) Removexattr(path, name string) error {
	return unwrap(unix.Lremovexattr(path, name))
}

// Settimes uses setattrlist so birth time can be set exactly; unspecified
// fields are re-supplied from the current state because HFS clamps birth
// time to the modification time otherwise.
func (HostVolume) Settimes(path string, birth, modify, access int64) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return unwrap(err)
	}
	if birth == 0 {
		birth = st.Btim.Nano()
	}
	if modify == 0 {
		modify = st.Mtim.Nano()
	}
	if access == 0 {
		access = st.Atim.Nano()
	}
	attrs := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_CRTIME | unix.ATTR_CMN_MODTIME | unix.ATTR_CMN_ACCTIME}
	buf := make([]byte, 3*int(unsafe.Sizeof(unix.Timespec{})))
	times := []int64{birth, modify, access}
	for i, t := range times {
		ts := unix.NsecToTimespec(t)
		copy(buf[i*int(unsafe.Sizeof(ts)):], (*[unsafe.Sizeof(ts)]byte)(unsafe.Pointer(&ts))[:])
	}
	return unwrap(unix.Setattrlist(path, &attrs, buf, unix.FSOPT_NOFOLLOW))
}

func (HostVolume) Fullfsync(path string) error {
	f, err := os.OpenFile(path, os.O_RDONLY, 0)
	if err != nil {
		return unwrap(err)
	}
	defer func() { _ = f.Close() }()
	_, err = unix.FcntlInt(f.Fd(), unix.F_FULLFSYNC, 0)
	return unwrap(err)
}

func (HostVolume) Clone(src, dst string) error {
	return unwrap(unix.Clonefile(src, dst, unix.CLONE_NOFOLLOW))
}

func (HostVolume) FreeBytes(path string) (int64, error) {
	var st unix.Statfs_t
	if err := unix.Statfs(path, &st); err != nil {
		return 0, unwrap(err)
	}
	return int64(st.Bavail) * int64(st.Bsize), nil
}

func (HostVolume) Lstat(path string) (Stat, error) {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		return Stat{}, unwrap(err)
	}
	kind := "other"
	switch st.Mode & unix.S_IFMT {
	case unix.S_IFREG:
		kind = "file"
	case unix.S_IFDIR:
		kind = "dir"
	case unix.S_IFLNK:
		kind = "symlink"
	}
	return Stat{Kind: kind, Ino: st.Ino, Nlink: uint32(st.Nlink), Mode: uint32(st.Mode & 0o7777), UID: st.Uid, GID: st.Gid, Flags: st.Flags, Size: st.Size, Allocated: st.Blocks * 512, Birth: st.Btim.Nano(), Modify: st.Mtim.Nano(), Change: st.Ctim.Nano(), Access: st.Atim.Nano()}, nil
}

func (HostVolume) Readdir(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, unwrap(err)
	}
	defer func() { _ = f.Close() }()
	names, err := f.Readdirnames(-1)
	return names, unwrap(err)
}

func (HostVolume) Readlink(path string) ([]byte, error) {
	buf := make([]byte, 4096)
	n, err := unix.Readlink(path, buf)
	if err != nil {
		return nil, unwrap(err)
	}
	return buf[:n], nil
}

func xattrOptions(showCompression bool) int {
	opts := unix.XATTR_NOFOLLOW
	if showCompression {
		opts |= unix.XATTR_SHOWCOMPRESSION
	}
	return opts
}

func (HostVolume) Listxattr(path string, showCompression bool) ([]string, error) {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 64<<10)
	n, _, e := syscall.Syscall6(syscall.SYS_LISTXATTR, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(xattrOptions(showCompression)), 0, 0)
	if e != 0 {
		return nil, e
	}
	return splitNUL(buf[:n]), nil
}

func (HostVolume) Getxattr(path, name string, showCompression bool) ([]byte, error) {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}
	n, err := unix.BytePtrFromString(name)
	if err != nil {
		return nil, err
	}
	size, _, e := syscall.Syscall6(syscall.SYS_GETXATTR, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(n)), 0, 0, 0, uintptr(xattrOptions(showCompression)))
	if e != 0 {
		return nil, e
	}
	if size == 0 {
		return []byte{}, nil
	}
	buf := make([]byte, size)
	got, _, e := syscall.Syscall6(syscall.SYS_GETXATTR, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(n)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0, uintptr(xattrOptions(showCompression)))
	if e != 0 {
		return nil, e
	}
	return buf[:got], nil
}

func (HostVolume) Hash(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, unwrap(err)
	}
	defer func() { _ = f.Close() }()
	digest := sha256.New()
	n, err := io.Copy(digest, f)
	return hex.EncodeToString(digest.Sum(nil)), n, unwrap(err)
}

func (HostVolume) Pread(path string, offset int64, length int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, unwrap(err)
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, length)
	n, err := f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, unwrap(err)
	}
	return buf[:n], nil
}

// log2phys is struct log2phys as <sys/fcntl.h> declares it under
// #pragma pack(4): a 4-byte flags word followed by two unaligned 8-byte
// fields, 20 bytes in all. A naturally aligned Go struct would be 24 bytes
// and the kernel would fill the wrong offsets.
const log2physSize = 20

func (HostVolume) Extents(path, fork string) ([][3]int64, error) {
	if fork == "rsrc" {
		path = filepath.Join(path, "..namedfork", "rsrc")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, unwrap(err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	var runs [][3]int64
	var arg [log2physSize]byte
	for offset := int64(0); offset < size && len(runs) < 4096; {
		binary.LittleEndian.PutUint32(arg[0:4], 0)
		binary.LittleEndian.PutUint64(arg[4:12], uint64(size-offset))
		binary.LittleEndian.PutUint64(arg[12:20], uint64(offset))
		if _, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), unix.F_LOG2PHYS_EXT, uintptr(unsafe.Pointer(&arg[0]))); e != 0 {
			return nil, e
		}
		contig := int64(binary.LittleEndian.Uint64(arg[4:12]))
		devoffset := int64(binary.LittleEndian.Uint64(arg[12:20]))
		if contig <= 0 {
			break
		}
		runs = append(runs, [3]int64{offset, devoffset, contig})
		offset += contig
	}
	return runs, nil
}

func (HostVolume) Holes(path string) ([][2]int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, unwrap(err)
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	size := info.Size()
	var holes [][2]int64
	for offset := int64(0); offset < size; {
		hole, err := unix.Seek(int(f.Fd()), offset, unix.SEEK_HOLE)
		if err != nil {
			return nil, unwrap(err)
		}
		if hole >= size {
			break
		}
		data, err := unix.Seek(int(f.Fd()), hole, unix.SEEK_DATA)
		if err != nil {
			data = size
		}
		holes = append(holes, [2]int64{hole, data - hole})
		offset = data
	}
	return holes, nil
}

// ACL returns the raw filesec blob from getattrlist's extended security
// attribute, or nil when the object carries no ACL.
func (HostVolume) ACL(path string) ([]byte, error) {
	attrs := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_RETURNED_ATTRS | unix.ATTR_CMN_EXTENDED_SECURITY}
	buf := make([]byte, 64<<10)
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return nil, err
	}
	if _, _, e := syscall.Syscall6(syscall.SYS_GETATTRLIST, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), unix.FSOPT_NOFOLLOW, 0); e != 0 {
		return nil, e
	}
	// Layout: u32 length, attribute_set_t returned (20 bytes), then an
	// attrreference_t {int32 offset; u32 length} for extended security
	// when present.
	if len(buf) < 32 {
		return nil, nil
	}
	returned := uint32(buf[4]) | uint32(buf[5])<<8 | uint32(buf[6])<<16 | uint32(buf[7])<<24
	if returned&unix.ATTR_CMN_EXTENDED_SECURITY == 0 {
		return nil, nil
	}
	refOffset := 24
	off := int32(uint32(buf[refOffset]) | uint32(buf[refOffset+1])<<8 | uint32(buf[refOffset+2])<<16 | uint32(buf[refOffset+3])<<24)
	length := uint32(buf[refOffset+4]) | uint32(buf[refOffset+5])<<8 | uint32(buf[refOffset+6])<<16 | uint32(buf[refOffset+7])<<24
	start := refOffset + int(off)
	if length == 0 || start < 0 || start+int(length) > len(buf) {
		return nil, nil
	}
	return append([]byte(nil), buf[start:start+int(length)]...), nil
}

func splitNUL(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == 0 {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	return out
}

// unwrap returns the underlying errno so transcript entries name it.
func unwrap(err error) error {
	switch e := err.(type) {
	case nil:
		return nil
	case *os.PathError:
		return e.Err
	case *os.LinkError:
		return e.Err
	case *os.SyscallError:
		return e.Err
	}
	return err
}

// fsoptListSnapshot is FSOPT_LIST_SNAPSHOT from <sys/attr.h>, which x/sys
// does not export; sysGetattrlistbulk is the getattrlistbulk trap number
// that x/sys exports only as a deprecated constant.
const (
	fsoptListSnapshot  = 0x40
	sysGetattrlistbulk = 461
)

// snapshotLister holds the volume root open, as libc's fs_snapshot_list
// callers do, so listing keeps working while asr remounts the volume.
type snapshotLister struct{ fd int }

// SnapshotLister opens the mounted volume's root directory.
func (HostVolume) SnapshotLister(mount string) (SnapshotLister, error) {
	fd, err := unix.Open(mount, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, unwrap(err)
	}
	return &snapshotLister{fd: fd}, nil
}

func (l *snapshotLister) Close() error { return unix.Close(l.fd) }

// List enumerates snapshots with getattrlistbulk and FSOPT_LIST_SNAPSHOT,
// asking for names only.
func (l *snapshotLister) List() ([]string, error) {
	// getattrlistbulk is a directory cursor; rewind so every call
	// enumerates from the start.
	if _, err := unix.Seek(l.fd, 0, 0); err != nil {
		return nil, unwrap(err)
	}
	attrs := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_RETURNED_ATTRS | unix.ATTR_CMN_NAME}
	buf := make([]byte, 64<<10)
	var names []string
	for {
		n, _, e := syscall.Syscall6(sysGetattrlistbulk, uintptr(l.fd), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), uintptr(fsoptListSnapshot), 0)
		if e != 0 {
			return nil, e
		}
		if n == 0 {
			return names, nil
		}
		offset := 0
		for i := 0; i < int(n); i++ {
			entry := buf[offset:]
			length := int(binary.LittleEndian.Uint32(entry[0:4]))
			returned := binary.LittleEndian.Uint32(entry[4:8])
			if returned&unix.ATTR_CMN_NAME != 0 && length >= 32 {
				refOffset := 24
				off := int(int32(binary.LittleEndian.Uint32(entry[refOffset : refOffset+4])))
				size := int(binary.LittleEndian.Uint32(entry[refOffset+4 : refOffset+8]))
				start := refOffset + off
				if size > 0 && start >= 0 && start+size <= length {
					names = append(names, strings.TrimRight(string(entry[start:start+size]), "\x00"))
				}
			}
			offset += length
		}
	}
}
