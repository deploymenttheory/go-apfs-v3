package edit

import (
	"fmt"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/names"
	"io/fs"
	"strings"
)

const maxAttributes = 4096

// Limits bound traversal and streamed storage. Zero fields use Defaults.
type Limits struct {
	Objects    int
	Entries    int
	Depth      int
	ValueBytes int64
	TotalBytes int64
}

func DefaultLimits() Limits { return Limits{100000, 200000, 128, 1 << 40, 1 << 40} }

func (l Limits) Normalize() (Limits, error) {
	d := DefaultLimits()
	for _, pair := range []struct {
		value    *int
		fallback int
	}{{&l.Objects, d.Objects}, {&l.Entries, d.Entries}, {&l.Depth, d.Depth}} {
		if *pair.value < 0 {
			return l, fs.ErrInvalid
		}
		if *pair.value == 0 {
			*pair.value = pair.fallback
		}
		if *pair.value > pair.fallback {
			return l, filesystem.ErrLimit
		}
	}
	if l.ValueBytes < 0 || l.TotalBytes < 0 {
		return l, fs.ErrInvalid
	}
	if l.ValueBytes == 0 {
		l.ValueBytes = d.ValueBytes
	}
	if l.TotalBytes == 0 {
		l.TotalBytes = d.TotalBytes
	}
	if l.ValueBytes > d.ValueBytes || l.TotalBytes > d.TotalBytes {
		return l, filesystem.ErrLimit
	}
	return l, nil
}

func NameKey(rules filesystem.NameRules) (func(string) string, error) {
	switch rules.Format {
	case "APFS":
		return func(s string) string { return names.APFS(s, rules.CaseSensitive, rules.NormalizationInsensitive) }, nil
	case "HFS+":
		if rules.NormalizationInsensitive {
			return func(s string) string { return names.HFS(s, rules.CaseSensitive) }, nil
		}
	}
	return nil, fmt.Errorf("workspace filename rules: %w", filesystem.ErrUnsupported)
}

func validComponent(s string) bool {
	return s != "" && s != "." && s != ".." && !strings.ContainsAny(s, "/\x00") && len(s) <= 1024
}
