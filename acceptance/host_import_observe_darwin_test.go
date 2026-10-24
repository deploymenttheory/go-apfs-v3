package acceptance_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"golang.org/x/sys/unix"
)

func observeHostInputPlatform(filename string, info os.FileInfo) (schema.HostInputEntry, error) {
	var st unix.Stat_t
	if err := unix.Lstat(filename, &st); err != nil {
		return schema.HostInputEntry{}, err
	}
	v := schema.HostInputEntry{Identity: fmt.Sprintf("%d:%d", st.Dev, st.Ino), SourceLinks: uint64(st.Nlink), SourceMode: uint32(st.Mode), SourceFlags: uint64(st.Flags)}
	v.Entry.ID, v.Entry.Mode, v.Entry.UID, v.Entry.GID, v.Entry.Flags = st.Ino, uint32(st.Mode)&07777, st.Uid, st.Gid, st.Flags
	if !info.IsDir() {
		v.Entry.Links = uint32(st.Nlink)
	}
	v.Entry.Times = schema.Times{Birth: time.Unix(st.Btim.Sec, st.Btim.Nsec).UnixNano(), Access: time.Unix(st.Atim.Sec, st.Atim.Nsec).UnixNano(), Modify: time.Unix(st.Mtim.Sec, st.Mtim.Nsec).UnixNano(), Change: time.Unix(st.Ctim.Sec, st.Ctim.Nsec).UnixNano()}
	for _, name := range []string{"identity", "links", "mode", "uid", "gid", "bsdFlags", "sourceFlags", "birthTime", "accessTime", "modifyTime", "changeTime"} {
		v.Fields = append(v.Fields, hostInputField(name, "present", "darwin-stat", ""))
	}
	n, err := unix.Llistxattr(filename, nil)
	if errors.Is(err, unix.ENOTSUP) {
		v.Fields = append(v.Fields, hostInputField("attributes", "unavailable", "darwin-xattrs", "filesystem does not enumerate extended attributes"), hostInputField("resourceFork", "unavailable", "darwin-xattrs", "filesystem does not enumerate extended attributes"))
	} else {
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
		fork := "absent"
		for _, name := range list {
			length, err := unix.Lgetxattr(filename, name, nil)
			if err != nil {
				return v, err
			}
			if length < 0 || length > schema.HostInputMaxValueBytes {
				return v, fmt.Errorf("host attribute value budget exceeded")
			}
			data := make([]byte, length)
			got, err := unix.Lgetxattr(filename, name, data)
			if err != nil {
				return v, err
			}
			if got != length {
				return v, fmt.Errorf("host attribute changed")
			}
			v.Attributes = append(v.Attributes, hostInputValue(name, data))
			if name == "com.apple.ResourceFork" {
				fork = "present"
			}
		}
		v.Fields = append(v.Fields, hostInputField("attributes", "present", "darwin-xattrs", ""), hostInputField("resourceFork", fork, "darwin-xattrs", ""))
	}
	v.Security, err = observeHostInputDarwinSecurity(filename)
	if err != nil {
		return v, err
	}
	state := v.Security.State
	if state == "empty" {
		state = "present"
	}
	v.Fields = append(v.Fields, hostInputField("acl", state, "darwin-filesec", v.Security.Reason))
	slices.SortFunc(v.Fields, func(a, b schema.HostInputField) int { return strings.Compare(a.Field, b.Field) })
	return v, nil
}

// Values stay in their native host-order layout. In particular, this oracle
// does not use the product's host-to-disk filesec conversion.
func observeHostInputDarwinSecurity(filename string) (schema.HostInputSecurity, error) {
	result := schema.HostInputSecurity{Format: "darwin-filesec"}
	attrs := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_RETURNED_ATTRS | unix.ATTR_CMN_EXTENDED_SECURITY}
	buf, err := hostInputDarwinGetattrlist(filename, attrs, (64<<10)+32)
	if errors.Is(err, unix.ENOTSUP) {
		result.State, result.Reason = "unavailable", "filesystem cannot return extended security"
		return result, nil
	}
	if err != nil {
		return result, err
	}
	if len(buf) < 24 {
		return result, fmt.Errorf("truncated returned-attribute set")
	}
	if binary.NativeEndian.Uint32(buf[4:])&unix.ATTR_CMN_EXTENDED_SECURITY == 0 {
		capabilities := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Volattr: unix.ATTR_VOL_INFO | unix.ATTR_VOL_CAPABILITIES}
		cap, err := hostInputDarwinGetattrlist(filename, capabilities, 36)
		if errors.Is(err, unix.ENOTSUP) {
			result.State, result.Reason = "unavailable", "filesystem cannot report extended-security capability"
			return result, nil
		}
		if err != nil {
			return result, err
		}
		if len(cap) != 36 {
			return result, fmt.Errorf("invalid volume capability layout")
		}
		if binary.NativeEndian.Uint32(cap[24:])&0x400 == 0 || binary.NativeEndian.Uint32(cap[8:])&0x400 == 0 {
			result.State, result.Reason = "unavailable", "filesystem does not advertise extended-security support"
		} else {
			result.State = "absent"
		}
		return result, nil
	}
	if len(buf) < 32 {
		return result, fmt.Errorf("missing extended-security reference")
	}
	start := int64(24) + int64(int32(binary.NativeEndian.Uint32(buf[24:])))
	length := int64(binary.NativeEndian.Uint32(buf[28:]))
	if start < 32 || length < 44 || length > 64<<10 || start > int64(len(buf))-length {
		return result, fmt.Errorf("invalid extended-security bounds")
	}
	data := buf[start : start+length]
	count := binary.NativeEndian.Uint32(data[36:])
	if binary.NativeEndian.Uint32(data) != 0x012cc16d {
		return result, fmt.Errorf("unknown kauth_filesec magic")
	}
	result.State = "present"
	switch count {
	case ^uint32(0):
		result.State = "absent"
		count = 0
	case 0:
		result.State = "empty"
	}
	if count > 128 || length != 44+int64(count)*24 {
		return result, fmt.Errorf("invalid kauth_filesec entry bounds")
	}
	result.Values = []schema.HostInputValue{hostInputValue("kauth-filesec", data)}
	return result, nil
}

func hostInputDarwinGetattrlist(filename string, attrs unix.Attrlist, size int) ([]byte, error) {
	name, err := unix.BytePtrFromString(filename)
	if err != nil {
		return nil, err
	}
	buf := make([]byte, size)
	_, _, errno := syscall.Syscall6(syscall.SYS_GETATTRLIST, uintptr(unsafe.Pointer(name)), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), unix.FSOPT_NOFOLLOW|unix.FSOPT_REPORT_FULLSIZE, 0)
	if errno != 0 {
		return nil, errno
	}
	n := int(binary.NativeEndian.Uint32(buf))
	if n < 4 || n > len(buf) {
		return nil, fmt.Errorf("getattrlist result exceeds its bounded buffer")
	}
	return buf[:n], nil
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
		if name == "observed" {
			if err := unix.Lsetxattr(filename, "com.apple.ResourceFork", []byte("independent host resource fork\x00\xff"), 0); err != nil {
				return err
			}
			fd, err := unix.Open(filename, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				return err
			}
			if err := errors.Join(unix.Fchflags(fd, unix.UF_NODUMP), unix.Close(fd)); err != nil {
				return err
			}
		}
		// Ask the OS for this real owner's GUID, then set one non-inheritable
		// allow-read ACE. No guessed identity or product ACL codec is involved.
		owner, err := hostInputDarwinGetattrlist(filename, unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_UUID}, 20)
		if err != nil {
			return err
		}
		if len(owner) != 20 {
			return fmt.Errorf("invalid host owner GUID result")
		}
		value := make([]byte, 8+68)
		binary.NativeEndian.PutUint32(value, 8)
		binary.NativeEndian.PutUint32(value[4:], 68)
		security := value[8:]
		binary.NativeEndian.PutUint32(security, 0x012cc16d)
		binary.NativeEndian.PutUint32(security[36:], 1)
		copy(security[44:], owner[4:])
		binary.NativeEndian.PutUint32(security[60:], 1)
		binary.NativeEndian.PutUint32(security[64:], 2)
		attrs := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_EXTENDED_SECURITY}
		p, err := unix.BytePtrFromString(filename)
		if err != nil {
			return err
		}
		_, _, errno := syscall.Syscall6(syscall.SYS_SETATTRLIST, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&attrs)), uintptr(unsafe.Pointer(&value[0])), uintptr(len(value)), unix.FSOPT_NOFOLLOW, 0)
		if errno != 0 {
			return errno
		}
	}
	return nil
}

func TestHostInputPlatformCapturesDarwinACLAttributesAndHardLinkIdentity(t *testing.T) {
	root := t.TempDir()
	observed := filepath.Join(root, "observed")
	if err := os.WriteFile(observed, []byte("actual host bytes"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(observed, filepath.Join(root, "observed-alias")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(root, "metadata-dir"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "metadata-dir", "value"), []byte("child"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := configureHostInputMetadata(root); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(observed)
	if err != nil {
		t.Fatal(err)
	}
	first, err := observeHostInputPlatform(observed, info)
	if err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(root, "observed-alias")
	info, err = os.Lstat(alias)
	if err != nil {
		t.Fatal(err)
	}
	second, err := observeHostInputPlatform(alias, info)
	if err != nil {
		t.Fatal(err)
	}
	if first.Identity != second.Identity || first.SourceLinks != 2 || first.SourceFlags&unix.UF_NODUMP == 0 || len(first.Fields) != 14 {
		t.Fatal("native identity/flags/availability incomplete", first)
	}
	if first.Security.State != "present" || len(first.Security.Values) != 1 {
		t.Fatal("real ACL missing", first.Security)
	}
	var binaryValue, emptyValue, fork bool
	for _, value := range first.Attributes {
		switch value.Name {
		case "user.apfs.acceptance.binary":
			binaryValue = value.Hex == "00017f80ff00686f7374"
		case "user.apfs.acceptance.empty":
			emptyValue = value.Bytes == 0 && value.Hex == ""
		case "com.apple.ResourceFork":
			fork = value.Bytes > 0
		}
	}
	if !binaryValue || !emptyValue || !fork {
		t.Fatal("complete binary/empty/resource values missing", first.Attributes)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink("observed", link); err != nil {
		t.Fatal(err)
	}
	info, err = os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	literal, err := observeHostInputPlatform(link, info)
	if err != nil {
		t.Fatal(err)
	}
	if literal.Identity == first.Identity || literal.SourceMode&0170000 != 0120000 || literal.Security.State == "present" {
		t.Fatal("no-follow evidence selected the symlink target", literal)
	}
}
