// Package metadata shares portable command grammar and metadata admission.
package metadata

import (
	"io/fs"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const UserFlags uint32 = 0x800f

func Owner(owner string) (filesystem.Metadata, error) {
	m := filesystem.Metadata{}
	parts := strings.Split(owner, ":")
	if len(parts) > 2 || owner == "" || owner == ":" {
		return m, fs.ErrInvalid
	}
	for i, s := range parts {
		if s == "" {
			continue
		}
		v, e := strconv.ParseUint(s, 10, 32)
		if e != nil || v == math.MaxUint32 {
			return m, fs.ErrInvalid
		}
		if i == 0 {
			m.UID = filesystem.Observed(uint32(v))
		} else {
			m.GID = filesystem.Observed(uint32(v))
		}
	}
	return m, nil
}

func Flags(old uint32, expression string) (uint32, error) {
	if expression == "" {
		return old, fs.ErrInvalid
	}
	if expression[0] >= '0' && expression[0] <= '9' {
		v, e := strconv.ParseUint(expression, 8, 32)
		if e != nil || uint32(v)&^UserFlags != 0 {
			return old, filesystem.ErrUnsupported
		}
		return old&^UserFlags | uint32(v), nil
	}
	names := map[string]uint32{"nodump": 1, "uchg": 2, "uchange": 2, "uimmutable": 2, "uappnd": 4, "uappend": 4, "opaque": 8, "hidden": 0x8000}
	v := old
	for _, name := range strings.Split(expression, ",") {
		bit, ok := names[name]
		remove := false
		if !ok && strings.HasPrefix(name, "no") {
			bit, ok = names[name[2:]]
			remove = true
		}
		if !ok {
			return old, filesystem.ErrUnsupported
		}
		if remove {
			v &^= bit
		} else {
			v |= bit
		}
	}
	return v, nil
}

func AttributeName(name string) error {
	if !ValidAttributeName(name) {
		return fs.ErrInvalid
	}
	if name == filesystem.Decmpfs || name == "com.apple.system.Security" || strings.HasPrefix(name, "com.apple.fs.") || strings.HasPrefix(name, "system.") {
		return filesystem.ErrUnsupported
	}
	return nil
}

func ValidAttributeName(name string) bool {
	return name != "" && len(name) <= 127 && utf8.ValidString(name) && !strings.ContainsRune(name, 0)
}

func Ownership(p *filesystem.Metadata) error {
	if p == nil || (p.UID.State != filesystem.Present && p.GID.State != filesystem.Present) {
		return fs.ErrInvalid
	}
	if p.Mode.State != filesystem.Uncaptured || p.BSDFlags.State != filesystem.Uncaptured || p.BirthTime.State != filesystem.Uncaptured || p.AccessTime.State != filesystem.Uncaptured || p.ModifyTime.State != filesystem.Uncaptured || p.ChangeTime.State != filesystem.Uncaptured {
		return fs.ErrInvalid
	}
	for _, v := range []filesystem.Observation[uint32]{p.UID, p.GID} {
		if v.State != filesystem.Uncaptured && v.State != filesystem.Present || v.State == filesystem.Present && v.Value == math.MaxUint32 {
			return fs.ErrInvalid
		}
	}
	return nil
}

// ValidateChange prevents operation-specific fields being silently ignored.
func ValidateChange(c filesystem.Change) error {
	if (c.Access || c.Modify) && c.Operation != "touch" {
		return fs.ErrInvalid
	}
	if c.Path == "" || c.Name != "" || c.Destination != "" || c.Parents || c.Force || c.NoClobber || c.ResourceFork || c.Symbolic {
		return fs.ErrInvalid
	}
	if c.Recursive && c.Operation != "chown" && c.Operation != "chflags" && c.Operation != "chmod" {
		return fs.ErrInvalid
	}
	if c.NoCreate && c.Operation != "touch" || c.Reference != "" && c.Operation != "touch" || c.Mode != "" && c.Operation != "chmod" || c.Flags != "" && c.Operation != "chflags" || c.Metadata != nil && c.Operation != "chown" && c.Operation != "touch" || (c.Attribute != "" || c.AttributeMode != "" || c.DeleteAttribute || c.Data != nil) && c.Operation != "xattr" {
		return fs.ErrInvalid
	}
	switch c.Operation {
	case "chown":
		return Ownership(c.Metadata)
	case "chflags":
		_, err := Flags(0, c.Flags)
		return err
	case "chmod":
		if c.Mode == "" {
			return fs.ErrInvalid
		}
	case "touch":
		if c.Reference != "" && c.Metadata != nil {
			return fs.ErrInvalid
		}
		if c.Metadata != nil {
			p := c.Metadata
			if p.Mode.State != filesystem.Uncaptured || p.UID.State != filesystem.Uncaptured || p.GID.State != filesystem.Uncaptured || p.BSDFlags.State != filesystem.Uncaptured || p.BirthTime.State != filesystem.Uncaptured || p.ChangeTime.State != filesystem.Uncaptured {
				return fs.ErrInvalid
			}
			if p.AccessTime.State != filesystem.Uncaptured && p.AccessTime.State != filesystem.Present || p.ModifyTime.State != filesystem.Uncaptured && p.ModifyTime.State != filesystem.Present {
				return fs.ErrInvalid
			}
		}
	case "xattr":
		if err := AttributeName(c.Attribute); err != nil {
			return err
		}
		if c.AttributeMode != "" && c.AttributeMode != "create" && c.AttributeMode != "replace" {
			return fs.ErrInvalid
		}
		if c.DeleteAttribute {
			if c.Data != nil || c.AttributeMode != "" {
				return fs.ErrInvalid
			}
		} else if c.Data == nil || c.Data.Size() < 0 {
			return fs.ErrInvalid
		}
	default:
		return filesystem.ErrUnsupported
	}
	return nil
}

func Touch(c filesystem.Change, clock time.Time, reference *filesystem.Metadata) filesystem.Metadata {
	p := filesystem.Metadata{ModifyTime: filesystem.Observed(clock), AccessTime: filesystem.Observed(clock)}
	if c.Metadata != nil {
		p = *c.Metadata
	}
	if reference != nil {
		p = filesystem.Metadata{ModifyTime: reference.ModifyTime, AccessTime: reference.AccessTime}
	}
	if c.Access && !c.Modify {
		p.ModifyTime = filesystem.Observation[time.Time]{}
	}
	if c.Modify && !c.Access {
		p.AccessTime = filesystem.Observation[time.Time]{}
	}
	return p
}
