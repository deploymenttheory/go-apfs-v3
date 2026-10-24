package copyfile

import (
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"runtime"
)

func hostAttributeOmission(err error) filesystem.MetadataOmission {
	format := "windows-named-streams"
	status := filesystem.MetadataUnavailable
	reason := "host filesystem cannot enumerate Windows named streams; destination attributes retained"
	if errors.Is(err, errHostAttributeConversion) {
		status = filesystem.MetadataUnsupported
		reason = "captured Windows named streams cannot be converted to macOS attributes; destination attributes retained"
	}
	switch runtime.GOOS {
	case "darwin":
		format = "darwin-xattrs"
		status = filesystem.MetadataUnavailable
		reason = "host filesystem cannot enumerate extended attributes; destination attributes retained"
	case "linux":
		format = "linux-xattrs"
		status = filesystem.MetadataUnavailable
		reason = "host filesystem cannot enumerate extended attributes; destination attributes retained"
	}
	return filesystem.MetadataOmission{Field: "attributes", SourceFormat: format, Status: status, Reason: reason}
}

func hostDefaultOmissions() []filesystem.MetadataOmission {
	switch runtime.GOOS {
	case "linux":
		return []filesystem.MetadataOmission{{Field: "bsdFlags", SourceFormat: "linux-inode-flags", Status: filesystem.MetadataUnsupported, Reason: "Linux inode flags are not Darwin BSD flags; logical defaults used"}}
	case "windows":
		return []filesystem.MetadataOmission{
			{Field: "bsdFlags", SourceFormat: "windows-file-attributes", Status: filesystem.MetadataUnsupported, Reason: "Windows file attributes are not Darwin BSD flags; logical defaults used"},
			{Field: "gid", SourceFormat: "windows-security-descriptor", Status: filesystem.MetadataUnsupported, Reason: "Windows group SIDs have no configured numeric GID mapping; logical default used"},
			{Field: "mode", SourceFormat: "windows-file-attributes", Status: filesystem.MetadataUnsupported, Reason: "Windows authorization is not a POSIX mode; logical default used"},
			{Field: "uid", SourceFormat: "windows-security-descriptor", Status: filesystem.MetadataUnsupported, Reason: "Windows owner SIDs have no configured numeric UID mapping; logical default used"},
		}
	}
	return nil
}
