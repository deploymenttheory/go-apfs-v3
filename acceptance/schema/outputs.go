package schema

// OutputsSchema is the current outputs.json schema version.
const OutputsSchema = 1

// Outputs indexes every image and preservation export the suite produced on
// one host. The native verifier reads this file from each host's artifact:
// plaintext images must be byte-identical across hosts, encrypted images
// must decrypt to the same device bytes, and every output is then checked
// with Apple tools against the expectation it names. Preservation exports are
// independently checked on every host's copy against the native observation.
type Outputs struct {
	Schema int    `json:"schema"`
	Host   string `json:"host"` // linux, windows, darwin
	Arch   string `json:"arch"`
	Go     string `json:"go"`
	Commit string `json:"commit,omitempty"`
	Lock   string `json:"lockSHA256"` // digest of fixtures.lock.json used
	// Passwords maps the references outputs use to their public values, so
	// the verifier never needs the recipes.
	Passwords map[string]string `json:"passwords,omitempty"`
	Outputs   []Output          `json:"outputs"`
}

// Output is one produced image or preservation export and its expectation.
type Output struct {
	// Name is unique within the suite and identical on every host, so the
	// verifier can pair outputs across hosts.
	Name string `json:"name"`
	File string `json:"file"`
	// Operation is build, compress, container, encrypt, decrypt, repack,
	// edit, copy, change-password, delete-snapshot, recover-checkpoint, recover-journal, appledouble, or workspace-*.
	Operation string `json:"operation"`
	Format    string `json:"format"` // UDRO, UDZO, UDBZ, UDRW, raw, workspace, appledouble
	Bytes     int64  `json:"bytes"`
	SHA256    string `json:"sha256"`
	// HostInput binds an independently observed ordinary host tree. Only the
	// qualified HostImport consumer may use different host inputs; ordinary
	// plaintext output determinism remains unchanged.
	HostInput *HostInputReference `json:"hostInput,omitempty"`
	// Encrypted outputs carry fresh random material, so their digests
	// legitimately differ between hosts; Password names the recipe
	// password that unlocks them.
	Encrypted bool   `json:"encrypted,omitempty"`
	Password  string `json:"password,omitempty"`
	// Source identifies the fixture case the output was produced from.
	Source CaseRef `json:"source"`
	// Expect identifies the observation view the mounted output must match
	// (the source's own view, or a later stage's view after an edit) and
	// whether the device bytes must equal the source disk (repack).
	Expect Expectation `json:"expect"`
}

// CaseRef names a corpus case.
type CaseRef struct {
	Producer int    `json:"producer"`
	Recipe   string `json:"recipe"`
	Profile  string `json:"profile"`
	Stage    string `json:"stage"`
}

// Expectation tells the native verifier what to compare the output with.
type Expectation struct {
	// DeletedSnapshots removes only these exact identities from the original
	// Apple inventory/reference; all live and remaining history stays exact.
	DeletedSnapshots []SnapshotIdentity `json:"deletedSnapshots,omitempty"`
	// HostImport selects per-host validation against its original host inventory.
	HostImport *HostImportExpectation `json:"hostImport,omitempty"`
	// Container checks every source volume and each declared empty volume in a
	// fresh APFS construction, including native inventory and shared allocation.
	Container *ContainerExpectation `json:"container,omitempty"`
	// AppleDouble selects the retained serialized metadata control for this path.
	AppleDouble *AppleDoubleExpectation `json:"appleDouble,omitempty"`
	// Workspace selects independent manifest/blob verification for a portable
	// preservation archive, rather than attaching it as a disk image.
	Workspace *WorkspaceExpectation `json:"workspace,omitempty"`
	// View names the stage whose observation holds the expected entries;
	// empty means the source case's own observation.
	View string `json:"view,omitempty"`
	// Snapshot selects an exact retained historical view within that stage.
	Snapshot string `json:"snapshot,omitempty"`
	// Subtree is the observed path the output's root corresponds to, for
	// images built from part of a fixture (for example "Fixture").
	Subtree string `json:"subtree,omitempty"`
	// IgnoreTimes lists timestamp names (birth, modify, change, access)
	// that are not expected to match, for example change times that an
	// editor assigns from its own clock.
	IgnoreTimes []string `json:"ignoreTimes,omitempty"`
	// CommandClockNS is the explicit public edit clock for declared command
	// replay. The verifier binds it to the independent native stage inventory;
	// it never changes which clocks the declared operations affect.
	CommandClockNS int64 `json:"commandClockNs,omitempty"`
	// Volume selects the observed volume by name for multi-volume images.
	Volume string `json:"volume,omitempty"`
	// DiskSHA256 requires the attached raw device to hash to this value
	// (sector-preserving repacks).
	DiskSHA256 string `json:"diskSHA256,omitempty"`
	// SelectedXID requires Apple's checker to select this recovered APFS
	// transaction, independently of mounted file equality.
	SelectedXID uint64 `json:"selectedXID,omitempty"`
	// Codesign lists bundle paths that must verify after mounting.
	Codesign []string `json:"codesign,omitempty"`
	// Continuation asks the verifier to run the native write sequence and
	// a further product edit on a writable copy.
	Continuation bool `json:"continuation,omitempty"`
	// SystemMember names the volume the continuation must run on for
	// System/Data groups.
	SystemMember string `json:"systemMember,omitempty"`
	// FileCompression is the explicit storage policy of a build (zlib or
	// none): only compression-owned storage and UF_COMPRESSED may differ
	// from the source, and the outcome must be the policy's.
	FileCompression string `json:"fileCompression,omitempty"`
	// NewIdentities accepts any object identity for entries absent from
	// the source's view: an editor's allocator, not the kernel's, numbers
	// what it creates.
	NewIdentities bool `json:"newIdentities,omitempty"`
	// ContinuationRefusal is the error a tracked product limit makes the
	// continuation's product edit fail with. The native writes and their
	// fsck still run; the edit must fail with exactly this text, and an
	// edit that succeeds fails the check until the expectation is removed.
	ContinuationRefusal string `json:"continuationRefusal,omitempty"`
}

// HostInputReference binds a bounded sidecar in the same producer artifact.
type HostInputReference struct {
	File   string `json:"file"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// HostImportExpectation is a closed archive-import policy, shared across hosts.
// Availability and actual values belong to each host's independent inventory.
type HostImportExpectation struct {
	Route         string `json:"route"` // session-pack or image-copy
	Destination   string `json:"destination"`
	ClockNS       int64  `json:"clockNs"`
	UID           uint32 `json:"uid"`
	GID           uint32 `json:"gid"`
	PreserveLinks bool   `json:"preserveLinks"`
}

// ContainerExpectation records construction choices that differ from the native
// source. Names, case rules, roles, limits and group membership come from the
// retained native inventory; fresh UUIDs must be nonzero and independent.
type ContainerExpectation struct {
	CapacityBytes int64    `json:"capacityBytes"`
	EmptyVolumes  []string `json:"emptyVolumes,omitempty"`
}

// AppleDoubleExpectation binds an encoded metadata output to one native export.
type AppleDoubleExpectation struct {
	Path string `json:"path"`
}

// WorkspaceExpectation describes the public timestamp policy exercised by the
// producer. The native reference remains immutable; comparisons project only
// preserved clocks or the explicitly supplied command clock.
type WorkspaceExpectation struct {
	Policy  string `json:"policy"` // preserve or commands
	ClockNS int64  `json:"clockNs,omitempty"`
	// ParentOutput names the preceding exported workspace whose manifest
	// digest must be retained by this edit, independently on each host.
	ParentOutput string `json:"parentOutput,omitempty"`
}

// SnapshotIdentity binds an exact retained name and transaction together.
type SnapshotIdentity struct {
	Name string `json:"name"`
	XID  uint64 `json:"xid"`
}
