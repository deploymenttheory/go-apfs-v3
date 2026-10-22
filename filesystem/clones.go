package filesystem

import (
	"context"
	"strings"
	"unicode/utf8"
)

// CloneStreams declares explicit raw-stream lineage, separately from inode
// identity and content equality. Empty tokens mean independent storage. Tokens
// are opaque, scoped logical identities; they are never payload digests or disk
// addresses. A hard link has the same Node rather than another clone member.
// Replacing data clears Data; changing an attribute clears only its token.
type CloneStreams struct {
	Data       string            `json:"data,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	// Partial identifies captured sharing that a whole-stream group cannot
	// represent. The empty name is raw data; other names are attributes.
	// Fresh APFS construction refuses these streams rather than flattening them.
	Partial []string `json:"partial,omitempty"`
}

// CloneSource optionally supplies a bounded metadata inventory for a subtree.
// Session capture requests it once; ordinary logical reads need not inspect
// unrelated ownership records. Entries use the source's object identifiers.
// Only independently established storage identity may produce native groups.
type CloneSource interface {
	CloneStreams(context.Context, uint64) (map[uint64]CloneStreams, error)
}

// ValidateCloneStreams bounds portable lineage metadata. It validates identity
// syntax only; readers and builders must separately reconcile repeated tokens
// against actual stream descriptors and values.
func ValidateCloneStreams(clones *CloneStreams) error {
	if clones == nil {
		return nil
	}
	valid := func(token string) bool {
		return token != "" && len(token) <= 256 && utf8.ValidString(token) && !strings.ContainsAny(token, "\x00\r\n")
	}
	if clones.Data == "" && len(clones.Attributes) == 0 && len(clones.Partial) == 0 || len(clones.Attributes) > 4096 || len(clones.Partial) > 4097 || clones.Data != "" && !valid(clones.Data) {
		return ErrCorrupt
	}
	for name, token := range clones.Attributes {
		if name == "" || len(name) > 1024 || !utf8.ValidString(name) || strings.ContainsRune(name, 0) || !valid(token) {
			return ErrCorrupt
		}
	}
	for i, name := range clones.Partial {
		if len(name) > 1024 || !utf8.ValidString(name) || strings.ContainsRune(name, 0) || i > 0 && clones.Partial[i-1] >= name || name == "" && clones.Data != "" || name != "" && clones.Attributes[name] != "" {
			return ErrCorrupt
		}
	}
	return nil
}
