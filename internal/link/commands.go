// Package link shares ordinary link-command admission across filesystem engines.
package link

import (
	"io/fs"
	"strings"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Target is stored literally; it is never resolved or normalized on the host.
func Target(target string) error {
	if target == "" || !utf8.ValidString(target) || strings.ContainsRune(target, 0) {
		return fs.ErrInvalid
	}
	if len(target) > 1023 {
		return filesystem.ErrLimit
	}
	return nil
}

func Validate(c filesystem.Change) error {
	if c.Operation != "ln" || c.Path == "" || c.Destination == "" || c.Name != "" || c.Parents || c.Recursive || c.NoClobber || c.Data != nil || c.ResourceFork || c.Mode != "" || c.Metadata != nil || c.Flags != "" || c.Attribute != "" || c.AttributeMode != "" || c.DeleteAttribute || c.NoCreate || c.Reference != "" || c.Access || c.Modify || c.Attributes != nil || len(c.RemoveAttributes) != 0 {
		return fs.ErrInvalid
	}
	if c.Symbolic {
		return Target(c.Path)
	}
	if strings.HasSuffix(c.Path, "/") {
		return fs.ErrInvalid
	}
	return nil
}
