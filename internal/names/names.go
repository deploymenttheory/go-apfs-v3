// Package names implements filesystem-frozen comparison keys. Keys are never
// exposed as filenames: enumeration retains the spelling stored by the volume.
package names

import (
	"context"
	"fmt"
	"io/fs"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type unit struct {
	char  rune
	class uint8
}

func APFS(s string, sensitive, normalized bool) string {
	if !normalized && sensitive {
		return s
	}
	table := apfsFolded
	if sensitive {
		table = apfsSensitive
	}
	var out []unit
	appendUnit := func(u unit) {
		out = append(out, u)
		for i := len(out) - 1; u.class != 0 && i > 0 && out[i-1].class > u.class; i-- {
			out[i], out[i-1] = out[i-1], out[i]
		}
	}
	for _, c := range s {
		if c >= 0xac00 && c <= 0xd7a3 {
			n := c - 0xac00
			appendUnit(unit{0x1100 + n/588, 0})
			appendUnit(unit{0x1161 + (n%588)/28, 0})
			if n%28 != 0 {
				appendUnit(unit{0x11a7 + n%28, 0})
			}
		} else if mapped, ok := table[c]; ok {
			for _, u := range mapped {
				appendUnit(u)
			}
		} else {
			appendUnit(unit{c, 0})
		}
	}
	var key strings.Builder
	for _, u := range out {
		key.WriteRune(u.char)
	}
	return key.String()
}

func HFS(s string, sensitive bool) string {
	// POSIX presents stored slashes as colons and stored NULs as U+2400.
	s = strings.ReplaceAll(strings.ReplaceAll(s, ":", "/"), "\u2400", "\x00")
	n := normalize([]rune(s), hfsDecomposition, hfsClass)
	units := utf16.Encode(n)
	var key strings.Builder
	for _, c := range units {
		x := rune(c)
		if !sensitive {
			if folded, ok := hfsFold[x]; ok {
				x = folded
			}
			if x == 0 {
				continue
			}
		}
		// Encode UTF-16 units as two bytes, preserving unpaired comparison units.
		key.WriteByte(byte(x >> 8))
		key.WriteByte(byte(x))
	}
	return key.String()
}

func normalize(input []rune, decomposition map[rune]string, class map[rune]uint8) []rune {
	var out []rune
	var add func(rune)
	add = func(c rune) {
		if c >= 0xac00 && c <= 0xd7a3 {
			n := c - 0xac00
			add(0x1100 + n/588)
			add(0x1161 + (n%588)/28)
			if n%28 != 0 {
				add(0x11a7 + n%28)
			}
			return
		}
		if parts, ok := decomposition[c]; ok {
			for _, part := range parts {
				add(part)
			}
			return
		}
		out = append(out, c)
		cc := class[c]
		for i := len(out) - 1; cc != 0 && i > 0 && class[out[i-1]] > cc; i-- {
			out[i], out[i-1] = out[i-1], out[i]
		}
	}
	for _, c := range input {
		add(c)
	}
	return out
}

// Lookup scans one directory, never a volume-wide index. Readers prune their
// B-trees by parent ID. Both names and work are bounded before normalization.
func Lookup(ctx context.Context, r filesystem.Reader, parent uint64, name string, key func(string) string) (filesystem.DirEntry, error) {
	if name == "" || name == "." || name == ".." || len(name) > 1024 || !utf8.ValidString(name) || strings.ContainsAny(name, "/\x00") {
		return filesystem.DirEntry{}, fs.ErrInvalid
	}
	want := key(name)
	var result filesystem.DirEntry
	err := r.ReadDir(ctx, parent, func(e filesystem.DirEntry) error {
		if len(e.Name) > 1024 {
			return filesystem.ErrLimit
		}
		if key(e.Name) == want {
			if result.Object != 0 {
				return fmt.Errorf("ambiguous native filename: %w", filesystem.ErrCorrupt)
			}
			result = e
		}
		return nil
	})
	if err == nil && result.Object == 0 {
		err = fs.ErrNotExist
	}
	return result, err
}

// Stored returns a new POSIX-visible filename using Apple's frozen HFS+
// decomposition. Both formats limit names to 255 UTF-16 units; HFS+ applies
// that limit after decomposition. APFS retains the supplied Unicode spelling.
func Stored(s, format string) (string, error) {
	if s == "" || s == "." || s == ".." || !utf8.ValidString(s) || strings.ContainsAny(s, "/\x00") {
		return "", fs.ErrInvalid
	}
	if len(s) > 1024 {
		return "", filesystem.ErrLimit
	}
	switch format {
	case "APFS":
	case "HFS+":
		s = string(normalize([]rune(s), hfsDecomposition, hfsClass))
	default:
		return "", filesystem.ErrUnsupported
	}
	units := 0
	for _, r := range s {
		units += utf16.RuneLen(r)
	}
	if units > 255 {
		return "", filesystem.ErrLimit
	}
	return s, nil
}
