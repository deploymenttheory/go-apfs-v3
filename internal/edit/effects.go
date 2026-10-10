package edit

import (
	"context"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/finderinfo"
	"io/fs"
	"math"
	"strings"
	"time"
	"unicode/utf8"
)

// NativeTime admits times supported by both the metadata API and the target format.
func NativeTime(rules filesystem.NameRules, t time.Time) (time.Time, error) {
	t = t.UTC()
	if t.Before(time.Unix(0, 0)) || t.After(time.Unix(0, math.MaxInt64)) {
		return t, filesystem.ErrUnsupported
	}
	if rules.Format == "HFS+" {
		if t.Unix() > math.MaxUint32-2082844800 {
			return t, filesystem.ErrUnsupported
		}
		t = t.Truncate(time.Second)
	}
	return t, nil
}

// Times records command-generated timestamp effects. In particular, change time
// cannot be supplied through the preservation API's SetMetadata patch.
func (r *Tree) Times(ctx context.Context, id uint64, access, modify, change *time.Time) error {
	o, err := r.getNode(ctx, id)
	if err != nil {
		return err
	}
	for _, field := range []struct {
		name   string
		input  *time.Time
		target *filesystem.Observation[time.Time]
	}{{"accessTime", access, &o.node.Metadata.AccessTime}, {"modifyTime", modify, &o.node.Metadata.ModifyTime}, {"changeTime", change, &o.node.Metadata.ChangeTime}} {
		if field.input == nil {
			continue
		}
		t, err := NativeTime(r.NameRules(), *field.input)
		if err != nil {
			return err
		}
		*field.target = filesystem.Observed(t)
		o.node.MetadataModified = markField(o.node.MetadataModified, field.name)
	}
	return nil
}

func (r *Tree) Defaults(ctx context.Context, id uint64, fields []string) error {
	o, err := r.getNode(ctx, id)
	if err != nil {
		return err
	}
	for _, field := range fields {
		o.node.MetadataDefaulted = markField(o.node.MetadataDefaulted, field)
	}
	return nil
}

// CopyAttributes transfers supplied opaque attributes with a file copy. It does
// not provide an unrestricted xattr edit: format-owned compression values must
// already have been removed by ReplacementNode before calling this method.
func (r *Tree) CopyAttributes(ctx context.Context, id uint64, values map[string]block.Source) error {
	o, err := r.getNode(ctx, id)
	if err != nil {
		return err
	}
	for name, value := range values {
		if !utf8.ValidString(name) || name == "" || strings.ContainsRune(name, 0) || len(name) > 1024 {
			return fs.ErrInvalid
		}
		if err = r.supply(value); err != nil {
			return err
		}
		if name == filesystem.FinderInfo {
			if value.Size() != 32 {
				return fs.ErrInvalid
			}
			data := make([]byte, 32)
			if err = block.ReadFull(value, data, 0); err != nil {
				return err
			}
			if r.NameRules().Format == "HFS+" {
				data = finderinfo.HFS(data, o.node.Metadata.Mode.Value)
			}
			if err = finderFlags(o, data[8]&0x40 != 0); err != nil {
				return err
			}
			storeFinderInfo(o, data)
		} else {
			o.putAttribute(name, value)
		}
		if validAttributeName(name) {
			o.node.AttributesModified = markField(o.node.AttributesModified, name)
		}
	}
	return nil
}

// AttributeAvailability retains the absence of a host observation separately
// from an observed empty attribute list.
func (r *Tree) AttributeAvailability(ctx context.Context, id uint64, unavailable bool) error {
	o, err := r.getNode(ctx, id)
	if err != nil {
		return err
	}
	o.node.AttributesUnavailable = o.node.AttributesUnavailable || unavailable
	return nil
}

// ApplyCommand allows sequential overwrites of a logical inode within one file
// command. The preservation batch API retains its duplicate-replacement guard.
func (r *Tree) ApplyCommand(ctx context.Context, change Change) error {
	clear(r.replaced)
	return r.Apply(ctx, change)
}
