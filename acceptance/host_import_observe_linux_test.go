package acceptance_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"golang.org/x/sys/unix"
)

// This observer uses ordinary no-follow syscalls directly. No product host
// reader or product metadata conversion supplies its expected values.
func observeHostInputPlatform(filename string, info os.FileInfo) (schema.HostInputEntry, error) {
	var st unix.Stat_t
	if err := unix.Lstat(filename, &st); err != nil {
		return schema.HostInputEntry{}, err
	}
	v := schema.HostInputEntry{Identity: fmt.Sprintf("%d:%d", st.Dev, st.Ino), SourceLinks: st.Nlink, SourceMode: st.Mode}
	v.Entry.ID, v.Entry.Mode, v.Entry.UID, v.Entry.GID = st.Ino, st.Mode&07777, st.Uid, st.Gid
	if !info.IsDir() {
		v.Entry.Links = uint32(st.Nlink)
	}
	v.Entry.Times = schema.Times{Access: time.Unix(st.Atim.Sec, st.Atim.Nsec).UnixNano(), Modify: time.Unix(st.Mtim.Sec, st.Mtim.Nsec).UnixNano(), Change: time.Unix(st.Ctim.Sec, st.Ctim.Nsec).UnixNano()}
	for _, field := range []string{"identity", "links", "mode", "uid", "gid", "accessTime", "modifyTime", "changeTime"} {
		v.Fields = append(v.Fields, hostInputField(field, "present", "linux-stat", ""))
	}
	var extended unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, filename, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BTIME, &extended); err == nil && extended.Mask&unix.STATX_BTIME != 0 {
		v.Entry.Times.Birth = time.Unix(extended.Btime.Sec, int64(extended.Btime.Nsec)).UnixNano()
		v.Fields = append(v.Fields, hostInputField("birthTime", "present", "linux-statx", ""))
	} else if err != nil && !errors.Is(err, unix.ENOSYS) && !errors.Is(err, unix.ENOTSUP) && !errors.Is(err, unix.EINVAL) {
		return v, err
	} else {
		v.Fields = append(v.Fields, hostInputField("birthTime", "unavailable", "linux-statx", "filesystem did not return birth time"))
	}
	v.Fields = append(v.Fields, hostInputField("bsdFlags", "unavailable", "linux-inode-flags", "Linux inode flags are not Darwin BSD flags"), hostInputField("resourceFork", "unavailable", "linux-xattrs", "Linux attributes have no implicit Darwin resource fork mapping"))
	flagsState := "unavailable"
	if info.Mode()&os.ModeSymlink == 0 {
		fd, err := unix.Open(filename, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return v, err
		}
		flags, queryErr := unix.IoctlGetInt(fd, unix.FS_IOC_GETFLAGS)
		closeErr := unix.Close(fd)
		if closeErr != nil {
			return v, errors.Join(queryErr, closeErr)
		}
		if queryErr == nil {
			v.SourceFlags = uint64(uint32(flags))
			flagsState = "present"
		} else if !errors.Is(queryErr, unix.ENOTTY) && !errors.Is(queryErr, unix.ENOTSUP) && !errors.Is(queryErr, unix.EINVAL) {
			return v, queryErr
		}
	}
	reason := ""
	if flagsState == "unavailable" {
		reason = "inode flags are unavailable for this object"
	}
	v.Fields = append(v.Fields, hostInputField("sourceFlags", flagsState, "linux-inode-flags", reason))
	n, err := unix.Llistxattr(filename, nil)
	if errors.Is(err, unix.ENOTSUP) {
		v.Fields = append(v.Fields, hostInputField("attributes", "unavailable", "linux-xattrs", "filesystem does not enumerate attributes"), hostInputField("acl", "unavailable", "linux-posix-acl", "filesystem does not expose POSIX ACLs"))
		v.Security = schema.HostInputSecurity{State: "unavailable", Format: "linux-posix-acl", Reason: "filesystem does not expose POSIX ACLs"}
		slices.SortFunc(v.Fields, func(a, b schema.HostInputField) int { return strings.Compare(a.Field, b.Field) })
		return v, nil
	}
	if err != nil {
		return v, err
	}
	if n > schema.HostInputMaxValueBytes {
		return v, fmt.Errorf("host attribute name budget exceeded")
	}
	names := make([]byte, n)
	got, err := unix.Llistxattr(filename, names)
	if err != nil {
		return v, err
	}
	if got != n {
		return v, fmt.Errorf("host attribute inventory changed")
	}
	v.Fields = append(v.Fields, hostInputField("attributes", "present", "linux-xattrs", ""))
	var list []string
	if n > 0 {
		if names[n-1] != 0 {
			return v, fmt.Errorf("unterminated host attribute inventory")
		}
		list = strings.Split(string(names[:n-1]), "\x00")
	}
	if len(list) > schema.HostInputMaxAttributes {
		return v, fmt.Errorf("host attribute count budget exceeded")
	}
	slices.Sort(list)
	for _, name := range list {
		length, err := unix.Lgetxattr(filename, name, nil)
		if err != nil {
			return v, err
		}
		limit := schema.HostInputMaxValueBytes
		if strings.HasPrefix(name, "system.posix_acl_") {
			limit = 64 << 10
		}
		if length < 0 || length > limit {
			return v, fmt.Errorf("host attribute value budget exceeded")
		}
		value := make([]byte, length)
		got, err := unix.Lgetxattr(filename, name, value)
		if err != nil {
			return v, err
		}
		if got != length {
			return v, fmt.Errorf("host attribute changed")
		}
		v.Attributes = append(v.Attributes, hostInputValue(name, value))
	}
	v.Security = schema.HostInputSecurity{State: "absent", Format: "linux-posix-acl"}
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		length, err := unix.Lgetxattr(filename, name, nil)
		if errors.Is(err, unix.ENODATA) {
			continue
		}
		if errors.Is(err, unix.ENOTSUP) {
			v.Security = schema.HostInputSecurity{State: "unavailable", Format: "linux-posix-acl", Reason: "filesystem does not expose POSIX ACLs"}
			break
		}
		if err != nil {
			return v, err
		}
		if length < 4 || length > 64<<10 {
			return v, fmt.Errorf("invalid POSIX ACL size")
		}
		value := make([]byte, length)
		got, err := unix.Lgetxattr(filename, name, value)
		if err != nil {
			return v, err
		}
		if got != length {
			return v, fmt.Errorf("POSIX ACL changed")
		}
		if binary.LittleEndian.Uint32(value) != 2 || (length-4)%8 != 0 {
			return v, fmt.Errorf("invalid POSIX ACL encoding")
		}
		v.Security.Values = append(v.Security.Values, hostInputValue(name, value))
		v.Security.State = "present"
	}
	v.Fields = append(v.Fields, hostInputField("acl", v.Security.State, "linux-posix-acl", v.Security.Reason))
	slices.SortFunc(v.Fields, func(a, b schema.HostInputField) int { return strings.Compare(a.Field, b.Field) })
	return v, nil
}

func configureHostInputMetadata(root string) error {
	binaryValue := []byte{0, 1, 127, 128, 255, 0, 104, 111, 115, 116}
	for _, name := range []string{"observed", "metadata-dir"} {
		filename := filepath.Join(root, name)
		for attr, value := range map[string][]byte{"user.apfs.acceptance.binary": binaryValue, "user.apfs.acceptance.empty": {}} {
			if err := unix.Lsetxattr(filename, attr, value, 0); err != nil {
				return err
			}
		}
		owner, other := uint16(6), uint16(4)
		if name == "metadata-dir" {
			owner, other = 7, 5
		}
		acl := make([]byte, 44)
		binary.LittleEndian.PutUint32(acl, 2)
		for i, entry := range [][3]uint32{{1, uint32(owner), ^uint32(0)}, {2, uint32(other), 65534}, {4, uint32(other), ^uint32(0)}, {16, uint32(other), ^uint32(0)}, {32, uint32(other), ^uint32(0)}} {
			at := 4 + 8*i
			binary.LittleEndian.PutUint16(acl[at:], uint16(entry[0]))
			binary.LittleEndian.PutUint16(acl[at+2:], uint16(entry[1]))
			binary.LittleEndian.PutUint32(acl[at+4:], entry[2])
		}
		if err := unix.Lsetxattr(filename, "system.posix_acl_access", acl, 0); err != nil {
			return err
		}
		if name == "metadata-dir" {
			if err := unix.Lsetxattr(filename, "system.posix_acl_default", acl, 0); err != nil {
				return err
			}
		}
	}
	return nil
}
