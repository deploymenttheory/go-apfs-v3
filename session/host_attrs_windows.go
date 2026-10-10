package session

import "github.com/deploymenttheory/go-apfs-v3/filesystem"

// NTFS alternate streams and Windows authorization data are not macOS xattrs.
// Windows host copies report unavailable macOS attributes in the copy report.
func hostAttributes(string) ([]string, error) { return nil, filesystem.ErrUnsupported }
func hostAttribute(string, string, int64) (filesystem.Value, error) {
	return nil, filesystem.ErrUnsupported
}
