package copyfile

import (
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"golang.org/x/sys/unix"
)

func hostSecurity(path string) ([]byte, *filesystem.MetadataOmission, error) {
	present := false
	for _, name := range []string{"system.posix_acl_access", "system.posix_acl_default"} {
		n, err := unix.Lgetxattr(path, name, nil)
		if errors.Is(err, unix.ENODATA) {
			continue
		}
		if errors.Is(err, unix.ENOTSUP) {
			return nil, &filesystem.MetadataOmission{Field: "acl", SourceFormat: "linux-posix-acl", Status: filesystem.MetadataUnavailable, Reason: "host filesystem cannot report POSIX ACLs; destination ACL retained"}, nil
		}
		if err != nil {
			return nil, nil, err
		}
		if n <= 0 || n > 64<<10 {
			return nil, nil, filesystem.ErrCorrupt
		}
		value := make([]byte, n)
		got, err := unix.Lgetxattr(path, name, value)
		if err != nil {
			return nil, nil, err
		}
		if got != n {
			return nil, nil, filesystem.ErrConflict
		}
		present = true
	}
	if !present {
		return nil, nil, nil
	}
	return nil, &filesystem.MetadataOmission{Field: "acl", SourceFormat: "linux-posix-acl", Status: filesystem.MetadataUnsupported, Reason: "captured POSIX ACLs cannot be converted to Darwin authorization; destination ACL retained"}, nil
}
