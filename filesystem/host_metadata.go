package filesystem

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"unicode/utf8"
)

// MetadataOmissionStatus distinguishes an unavailable observation from a host
// representation which cannot be converted into logical macOS metadata.
type MetadataOmissionStatus string

const (
	MetadataUnavailable MetadataOmissionStatus = "unavailable"
	MetadataUnsupported MetadataOmissionStatus = "unsupported"
)

// MetadataOmission records a host field that was not transferred. It never means
// the field was observed absent. Reasons contain no source path or credentials.
type MetadataOmission struct {
	Field        string                 `json:"field"`
	SourceFormat string                 `json:"sourceFormat"`
	Status       MetadataOmissionStatus `json:"status"`
	Reason       string                 `json:"reason"`
}

// MetadataOmissionRecord locates durable provenance in a logical tree. A hard
// linked object is reported once, at its first byte-sorted path.
type MetadataOmissionRecord struct {
	// Command and ClockNS are used only by imageedit's COPY-call outcomes.
	// Command is the 1-based Editor call index; Path/Object identify that
	// copy plan, not a promise that the path survives later calls. Other
	// readers/reports describe current-tree state and leave both fields zero.
	Command uint64 `json:"command,omitempty"`
	ClockNS int64  `json:"clockNs,omitempty"`
	Object  uint64 `json:"object"`
	Path    string `json:"path"`
	Volume  string `json:"volume,omitempty"`
	MetadataOmission
}

var hostMetadataFormats = map[string][]string{
	"acl":        {"darwin-filesec", "linux-posix-acl", "windows-security-descriptor"},
	"attributes": {"darwin-xattrs", "linux-xattrs", "windows-named-streams"},
	"bsdFlags":   {"linux-inode-flags", "windows-file-attributes"},
	"uid":        {"windows-security-descriptor"}, "gid": {"windows-security-descriptor"},
	"mode": {"windows-file-attributes"},
}

func ValidateMetadataOmissions(values []MetadataOmission) error {
	if len(values) > 16 {
		return ErrLimit
	}
	for i, value := range values {

		if !slices.Contains(hostMetadataFormats[value.Field], value.SourceFormat) || value.Status != MetadataUnavailable && value.Status != MetadataUnsupported || i > 0 && values[i-1].Field >= value.Field || value.Reason == "" || len(value.Reason) > 1024 || !utf8.ValidString(value.Reason) || strings.ContainsAny(value.Reason, "\x00\r\n") {
			return fmt.Errorf("invalid host metadata omission: %w", ErrCorrupt)
		}
	}
	return nil
}

// CollectMetadataOmissions reads provenance without interpreting host security
// formats. The reader must remain stable, as for any filesystem traversal.
func CollectMetadataOmissions(ctx context.Context, r Reader) ([]MetadataOmissionRecord, error) {
	var result []MetadataOmissionRecord
	seen := map[uint64]bool{}
	entries, metadata := 0, 0
	var walk func(uint64, string, int) error
	walk = func(id uint64, path string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		metadata += len(path) + 256
		if entries > 100000 || depth > 256 || metadata > 64<<20 {
			return ErrLimit
		}
		if seen[id] {
			return nil
		}
		seen[id] = true
		n, err := r.Stat(ctx, id)
		if err != nil {
			return err
		}
		if err := ValidateMetadataOmissions(n.MetadataOmissions); err != nil {
			return err
		}
		for _, v := range n.MetadataOmissions {
			metadata += len(v.Reason) + len(v.SourceFormat) + 64
			if metadata > 64<<20 {
				return ErrLimit
			}
			result = append(result, MetadataOmissionRecord{Object: id, Path: path, MetadataOmission: v})
		}
		if n.Metadata.Mode.Value&0170000 != 0040000 {
			return nil
		}
		var children []DirEntry
		if err := r.ReadDir(ctx, id, func(e DirEntry) error {
			if len(children) >= 100000 {
				return ErrLimit
			}
			children = append(children, e)
			return nil
		}); err != nil {
			return err
		}
		slices.SortFunc(children, func(a, b DirEntry) int { return strings.Compare(a.Name, b.Name) })
		for _, e := range children {
			p := strings.TrimSuffix(path, "/") + "/" + e.Name
			if err := walk(e.Object, p, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if r == nil {
		return nil, ErrCorrupt
	}
	if err := walk(r.Root(), "/", 0); err != nil {
		return nil, err
	}
	return result, nil
}
