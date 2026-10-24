package copyfile

import (
	"encoding/binary"
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/filesec"
	"golang.org/x/sys/unix"
	"syscall"
	"unsafe"
)

// hostSecurity reads the source link itself. A missing returned attribute is
// absence only when the filesystem independently advertises ACL support.
func hostSecurity(path string) ([]byte, *filesystem.MetadataOmission, error) {
	attrs := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Commonattr: unix.ATTR_CMN_RETURNED_ATTRS | unix.ATTR_CMN_EXTENDED_SECURITY}
	buf := make([]byte, 64<<10)
	if err := hostGetattrlist(path, &attrs, buf); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			return nil, securityUnavailable(), nil
		}
		return nil, nil, err
	}
	if len(buf) < 24 {
		return nil, nil, filesystem.ErrCorrupt
	}
	size := int(binary.LittleEndian.Uint32(buf))
	if size < 24 || size > len(buf) {
		return nil, nil, filesystem.ErrCorrupt
	}
	if binary.LittleEndian.Uint32(buf[4:])&unix.ATTR_CMN_EXTENDED_SECURITY == 0 {
		supported, err := hostACLCapability(path)
		if err != nil {
			return nil, nil, err
		}
		if !supported {
			return nil, securityUnavailable(), nil
		}
		return nil, nil, nil
	}
	if size < 32 {
		return nil, nil, filesystem.ErrCorrupt
	}
	start := int64(24) + int64(int32(binary.LittleEndian.Uint32(buf[24:])))
	length := int64(binary.LittleEndian.Uint32(buf[28:]))
	if length == 0 {
		return nil, nil, filesystem.ErrCorrupt
	}
	if start < 32 || length > filesec.MaxSize || start > int64(size)-length {
		return nil, nil, filesystem.ErrCorrupt
	}
	value, err := filesec.HostToDisk(buf[start:start+length], binary.LittleEndian)
	return value, nil, err
}

func hostGetattrlist(path string, attrs *unix.Attrlist, buf []byte) error {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return err
	}
	_, _, errno := syscall.Syscall6(syscall.SYS_GETATTRLIST, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(attrs)), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), unix.FSOPT_NOFOLLOW|unix.FSOPT_REPORT_FULLSIZE, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

func hostACLCapability(path string) (bool, error) {
	// attr.h: vol_capabilities_attr_t contains capabilities[4], valid[4];
	// interface index1, VOL_CAP_INT_EXTENDED_SECURITY=0x400.
	attrs := unix.Attrlist{Bitmapcount: unix.ATTR_BIT_MAP_COUNT, Volattr: unix.ATTR_VOL_INFO | unix.ATTR_VOL_CAPABILITIES}
	buf := make([]byte, 36)
	if err := hostGetattrlist(path, &attrs, buf); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			return false, nil
		}
		return false, err
	}
	if binary.LittleEndian.Uint32(buf) != 36 {
		return false, filesystem.ErrCorrupt
	}
	const security = 0x400
	return binary.LittleEndian.Uint32(buf[24:])&security != 0 && binary.LittleEndian.Uint32(buf[8:])&security != 0, nil
}

func securityUnavailable() *filesystem.MetadataOmission {
	return &filesystem.MetadataOmission{Field: "acl", SourceFormat: "darwin-filesec", Status: filesystem.MetadataUnavailable, Reason: "host filesystem does not report Darwin ACL support; destination ACL retained"}
}
