package edit

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"math"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/finderinfo"
)

// AttributeMode follows Apple's XATTR_CREATE / XATTR_REPLACE conditions. The
// zero value admits both creation and replacement of an ordinary attribute.
type AttributeMode string

const (
	AttributeUpsert  AttributeMode = ""
	AttributeCreate  AttributeMode = "create"
	AttributeReplace AttributeMode = "replace"
)

const userFlags uint32 = 0x800f // UF_NODUMP, UF_IMMUTABLE, UF_APPEND, UF_OPAQUE, UF_HIDDEN.

var MetadataFields = []string{"accessTime", "birthTime", "bsdFlags", "changeTime", "gid", "mode", "modifyTime", "uid"}

func copyNode(n filesystem.Node) filesystem.Node {
	n.MetadataDefaulted = slices.Clone(n.MetadataDefaulted)
	n.MetadataModified = slices.Clone(n.MetadataModified)
	n.AttributesModified = slices.Clone(n.AttributesModified)
	return n
}

func markField(fields []string, field string) []string {
	if slices.Contains(fields, field) {
		return fields
	}
	fields = append(slices.Clone(fields), field)
	slices.Sort(fields)
	return fields
}

func (o *editedObject) removeAttribute(name string) {
	if o.removed == nil {
		o.removed = map[string]bool{}
	}
	o.removed[name] = true
	delete(o.attributes, name)
}

func (o *editedObject) putAttribute(name string, data block.Source) {
	if o.attributes == nil {
		o.attributes = map[string]block.Source{}
	}
	o.attributes[name] = data
	delete(o.removed, name)
}

func (r *Tree) hasAttribute(ctx context.Context, id uint64, name string) (bool, error) {
	v, err := r.OpenAttribute(ctx, id, name)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, v.Close()
}

func validAttributeName(name string) bool {
	return name != "" && len(name) <= 127 && utf8.ValidString(name) && !strings.ContainsRune(name, 0)
}

func (r *Tree) editMetadata(ctx context.Context, c Change) error {
	id := r.Root()
	if c.Path != "." && c.Path != "/" {
		parent, name, err := r.parent(ctx, c.Path)
		if err != nil {
			return err
		}
		e, err := r.Lookup(ctx, parent, name)
		if err != nil {
			return err
		}
		id = e.Object
	}
	o, err := r.getNode(ctx, id)
	if err != nil {
		return err
	}
	if c.Op == SetMetadata {
		return r.setMetadata(ctx, o, *c.Metadata)
	}
	name := c.Attribute
	if c.Op == ReplaceResourceFork {
		name = filesystem.ResourceFork
	}
	if !validAttributeName(name) {
		return fs.ErrInvalid
	}
	// These values control decoding or native authorization, rather than an
	// ordinary opaque attribute. Preserve them; require a dedicated operation.
	if name == filesystem.Decmpfs || name == "com.apple.system.Security" || strings.HasPrefix(name, "com.apple.fs.") {
		return filesystem.ErrUnsupported
	}
	if name == filesystem.ResourceFork {
		if c.Op == SetAttribute {
			return fs.ErrInvalid
		}
		if o.node.Metadata.Mode.Value&0170000 != 0100000 {
			return fs.ErrInvalid
		}
		if o.node.Compression.State != filesystem.Absent || o.node.Metadata.BSDFlags.State != filesystem.Present || o.node.Metadata.BSDFlags.Value&32 != 0 {
			return filesystem.ErrUnsupported
		}
	}
	exists, err := r.hasAttribute(ctx, id, name)
	if err != nil {
		return err
	}
	if c.Op == RemoveAttribute || c.AttributeMode == AttributeReplace {
		if !exists {
			return fs.ErrNotExist
		}
	}
	if c.AttributeMode == AttributeCreate && exists {
		return fs.ErrExist
	}
	if !slices.Contains(o.node.AttributesModified, name) && len(o.node.AttributesModified) >= maxAttributes {
		return filesystem.ErrLimit
	}
	if c.Op == RemoveAttribute {
		o.removeAttribute(name)
		if name == filesystem.FinderInfo && r.NameRules().Format == "HFS+" {
			if err := finderFlags(o, false); err != nil {
				return err
			}
		}
	} else {
		// HFS_XATTR_MAXSIZE is INT32_MAX. Use that portable admission bound
		// for ordinary attributes; independent resource forks use Limits instead.
		if c.Op == SetAttribute && c.Data.Size() > math.MaxInt32 {
			return filesystem.ErrLimit
		}
		if err := r.supply(c.Data); err != nil {
			return err
		}
		if !exists {
			count := 0
			if err := r.ListAttributes(ctx, id, func(string) error { count++; return nil }); err != nil {
				return err
			}
			if count >= maxAttributes {
				return filesystem.ErrLimit
			}
		}
		switch name {
		case filesystem.FinderInfo:
			if c.Data.Size() != 32 {
				return fs.ErrInvalid
			}
			data := make([]byte, 32)
			if err := block.ReadFull(c.Data, data, 0); err != nil {
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			if r.NameRules().Format == "HFS+" {
				if o.node.Metadata.Mode.Value&0170000 != 0120000 && string(data[:4]) == "hlnk" {
					return filesystem.ErrUnsupported
				}
				data = finderinfo.HFS(data, o.node.Metadata.Mode.Value)
			}
			if err := finderFlags(o, data[8]&0x40 != 0); err != nil {
				return err
			}
			storeFinderInfo(o, data)
		case filesystem.ResourceFork:
			if c.Data.Size() == 0 {
				o.removeAttribute(name)
			} else {
				o.putAttribute(name, c.Data)
			}
		default:
			o.putAttribute(name, c.Data)
		}
	}
	o.node.AttributesModified = markField(o.node.AttributesModified, name)
	return nil
}

func finderFlags(o *editedObject, hidden bool) error {
	m := &o.node.Metadata
	if m.BSDFlags.State != filesystem.Present {
		return filesystem.ErrUnsupported
	}
	flags := m.BSDFlags.Value &^ uint32(0x8000)
	if hidden {
		flags |= 0x8000
	}
	if flags != m.BSDFlags.Value {
		m.BSDFlags.Value = flags
		o.node.MetadataModified = markField(o.node.MetadataModified, "bsdFlags")
	}
	return nil
}

func storeFinderInfo(o *editedObject, data []byte) {
	if bytes.Equal(data, make([]byte, 32)) {
		o.removeAttribute(filesystem.FinderInfo)
	} else {
		o.putAttribute(filesystem.FinderInfo, bytes.NewReader(data))
	}
}

func (r *Tree) setMetadata(ctx context.Context, o *editedObject, patch filesystem.Metadata) error {
	// Uncaptured is the patch's omitted state. Absent is invalid for these
	// fields. Explicit zero is Present, just as in captured metadata.
	for _, p := range []filesystem.Observation[uint32]{patch.Mode, patch.UID, patch.GID, patch.BSDFlags} {
		if p.State != filesystem.Present && (p.State != filesystem.Uncaptured || p.Value != 0) {
			return fs.ErrInvalid
		}
	}
	for _, p := range []filesystem.Observation[time.Time]{patch.BirthTime, patch.ModifyTime, patch.ChangeTime, patch.AccessTime} {
		if p.State != filesystem.Present && (p.State != filesystem.Uncaptured || !p.Value.IsZero()) {
			return fs.ErrInvalid
		}
	}
	if patch.ChangeTime.State != filesystem.Uncaptured {
		return filesystem.ErrUnsupported
	}
	m := o.node.Metadata
	fields := slices.Clone(o.node.MetadataModified)
	changed := false
	for _, p := range []struct {
		name   string
		input  filesystem.Observation[uint32]
		target *filesystem.Observation[uint32]
	}{
		{"mode", patch.Mode, &m.Mode}, {"uid", patch.UID, &m.UID}, {"gid", patch.GID, &m.GID}, {"bsdFlags", patch.BSDFlags, &m.BSDFlags},
	} {
		if p.input.State != filesystem.Present {
			continue
		}
		switch p.name {
		case "mode":
			if p.input.Value&0170000 != m.Mode.Value&0170000 || p.input.Value&^uint32(0177777) != 0 {
				return fs.ErrInvalid
			}
		case "uid", "gid":
			if p.input.Value == math.MaxUint32 {
				return fs.ErrInvalid
			}
		case "bsdFlags":
			if m.BSDFlags.State != filesystem.Present || (p.input.Value^m.BSDFlags.Value)&^userFlags != 0 {
				return filesystem.ErrUnsupported
			}
		}
		*p.target = p.input
		fields = markField(fields, p.name)
		o.node.MetadataDefaulted = slices.DeleteFunc(o.node.MetadataDefaulted, func(name string) bool { return name == p.name })
		changed = true
	}
	for _, p := range []struct {
		name   string
		input  filesystem.Observation[time.Time]
		target *filesystem.Observation[time.Time]
	}{
		{"birthTime", patch.BirthTime, &m.BirthTime}, {"modifyTime", patch.ModifyTime, &m.ModifyTime}, {"accessTime", patch.AccessTime, &m.AccessTime},
	} {
		if p.input.State != filesystem.Present {
			continue
		}
		v := p.input.Value.UTC()
		if v.Before(time.Unix(0, 0)) || v.After(time.Unix(0, math.MaxInt64)) {
			return filesystem.ErrUnsupported
		}
		if r.NameRules().Format == "HFS+" {
			if v.Unix() > math.MaxUint32-2082844800 {
				return filesystem.ErrUnsupported
			}
			v = v.Truncate(time.Second)
		}
		*p.target = filesystem.Observed(v)
		fields = markField(fields, p.name)
		o.node.MetadataDefaulted = slices.DeleteFunc(o.node.MetadataDefaulted, func(name string) bool { return name == p.name })
		changed = true
	}
	if !changed {
		return fs.ErrInvalid
	}
	// HFS+ stores the hidden flag in FinderInfo. APFS keeps the values separately
	// when chflags is used, though setting FinderInfo updates UF_HIDDEN on both.
	if patch.BSDFlags.State == filesystem.Present && r.NameRules().Format == "HFS+" {
		data := make([]byte, 32)
		v, err := r.OpenAttribute(ctx, o.node.Identity.Object, filesystem.FinderInfo)
		if err == nil {
			if v.Size() != 32 {
				return errors.Join(filesystem.ErrCorrupt, v.Close())
			}
			_, readErr := io.ReadFull(io.NewSectionReader(v, 0, 32), data)
			if err := errors.Join(readErr, v.Close()); err != nil {
				return err
			}
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		before := bytes.Clone(data)
		data[8] &^= 0x40
		if m.BSDFlags.Value&0x8000 != 0 {
			data[8] |= 0x40
		}
		if !bytes.Equal(before, data) {
			storeFinderInfo(o, data)
			o.node.AttributesModified = markField(o.node.AttributesModified, filesystem.FinderInfo)
		}
	}
	o.node.Metadata, o.node.MetadataModified = m, fields
	return ctx.Err()
}

func CopyNode(n filesystem.Node) filesystem.Node { return copyNode(n) }
func ValidAttributeName(s string) bool           { return validAttributeName(s) }
