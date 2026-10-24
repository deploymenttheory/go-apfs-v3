package filesec

import (
	"encoding/binary"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// HostToDisk converts the host-order kauth_filesec returned by getattrlist to
// the network-order on-disk filesec. GUID bytes remain opaque. XNU's
// vfs_attrlist.c and kauth.h define the packed layout and NOACL sentinel.
func HostToDisk(value []byte, order binary.ByteOrder) ([]byte, error) {
	if len(value) < 44 || len(value) > MaxSize || order.Uint32(value) != Magic {
		return nil, filesystem.ErrCorrupt
	}
	count := order.Uint32(value[36:])
	n := count
	if n == ^uint32(0) {
		n = 0
	}
	if n > 128 || len(value) != 44+int(n)*24 {
		return nil, filesystem.ErrCorrupt
	}
	result := append([]byte(nil), value...)
	for _, off := range []int{0, 36, 40} {
		be.PutUint32(result[off:], order.Uint32(value[off:]))
	}
	for i := 0; i < int(n); i++ {
		off := 44 + 24*i
		be.PutUint32(result[off+16:], order.Uint32(value[off+16:]))
		be.PutUint32(result[off+20:], order.Uint32(value[off+20:]))
	}
	return result, Validate(result)
}
