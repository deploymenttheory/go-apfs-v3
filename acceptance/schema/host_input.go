package schema

// HostInputSchema versions the independent ordinary-host input inventory.
const HostInputSchema = 1

const (
	HostInputMaxBytes      = 2 << 20
	HostInputMaxEntries    = 64
	HostInputMaxAttributes = 32
	HostInputMaxValueBytes = 256 << 10
)

// HostInputInventory is captured before a product import and contains no
// product-reader observation. Host-native identities establish aliases only;
// their numeric values are not required to survive reconstruction.
type HostInputInventory struct {
	Schema  int              `json:"schema"`
	Host    string           `json:"host"`
	Arch    string           `json:"arch"`
	Go      string           `json:"go"`
	Commit  string           `json:"commit,omitempty"`
	Source  CaseRef          `json:"source"`
	Entries []HostInputEntry `json:"entries"`
}

// HostInputField records availability independently from zero/empty values.
// SourceFormat names the actual representation, not an asserted conversion.
type HostInputField struct {
	Field        string `json:"field"`
	State        string `json:"state"` // present, absent or unavailable
	SourceFormat string `json:"sourceFormat"`
	Reason       string `json:"reason,omitempty"`
}

// HostInputValue retains small complete values so their digests can be checked
// independently. An empty value remains a present inventory entry.
type HostInputValue struct {
	Name      string `json:"name"`
	NameUTF16 string `json:"nameUtf16,omitempty"`
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	Hex       string `json:"hex"`
}

// HostInputSecurity preserves the original opaque security representation.
// Linux POSIX ACLs and Windows security descriptors are never relabelled as
// Darwin filesec records. Empty and absent ACLs are distinct observations.
type HostInputSecurity struct {
	State  string           `json:"state"` // present, empty, null, absent, unavailable
	Format string           `json:"format"`
	Values []HostInputValue `json:"values,omitempty"`
	Reason string           `json:"reason,omitempty"`
}

// HostInputEntry contains lstat/data/link/xattr observations for one path.
// Entry.Path is relative, with "." naming the source root. Windows names also
// retain their UTF-16 encoding; NameBytes is the enumerated UTF-8 bridge.
type HostInputEntry struct {
	Entry        Entry             `json:"entry"`
	Identity     string            `json:"identity"`
	SourceLinks  uint64            `json:"sourceLinks"`
	SourceMode   uint32            `json:"sourceMode"`
	SourceFlags  uint64            `json:"sourceFlags"`
	NameUTF16    string            `json:"nameUtf16,omitempty"`
	Fields       []HostInputField  `json:"fields"`
	Attributes   []HostInputValue  `json:"attributes,omitempty"`
	NamedStreams []HostInputValue  `json:"namedStreams,omitempty"`
	Security     HostInputSecurity `json:"security"`
	// NativePath binds materialized logical payloads to an immutable Apple
	// entry in Source. Added host controls reuse those same native bytes.
	NativePath string `json:"nativePath,omitempty"`
}
