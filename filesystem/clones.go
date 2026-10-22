package filesystem

// CloneStreams declares explicit raw-stream lineage, separately from inode
// identity and content equality. Empty tokens mean independent storage. Tokens
// are opaque, scoped logical identities; they are never payload digests or disk
// addresses. A hard link has the same Node rather than another clone member.
// Replacing data clears Data; changing an attribute clears only its token.
type CloneStreams struct {
	Data       string            `json:"data,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}
