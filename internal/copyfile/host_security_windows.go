package copyfile

import (
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"golang.org/x/sys/windows"
)

func hostSecurity(path string) (security []byte, omission *filesystem.MetadataOmission, err error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, nil, err
	}
	h, err := windows.CreateFile(p, windows.READ_CONTROL, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = errors.Join(err, windows.CloseHandle(h)) }()
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if errors.Is(err, windows.ERROR_NOT_SUPPORTED) {
		return nil, &filesystem.MetadataOmission{Field: "acl", SourceFormat: "windows-security-descriptor", Status: filesystem.MetadataUnavailable, Reason: "host filesystem cannot report a Windows security descriptor; destination ACL retained"}, nil
	}
	if err != nil {
		return nil, nil, err
	}
	if sd == nil {
		return nil, nil, filesystem.ErrCorrupt
	}
	_, _, err = sd.DACL()
	if errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, err
	}
	return nil, &filesystem.MetadataOmission{Field: "acl", SourceFormat: "windows-security-descriptor", Status: filesystem.MetadataUnsupported, Reason: "captured Windows DACL cannot be converted to Darwin authorization; destination ACL retained"}, nil
}
