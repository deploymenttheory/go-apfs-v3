package schema

// ObservationSchema is the current observation schema version.
const ObservationSchema = 1

// Observation is what macOS reported about one captured image at one stage.
// It is produced only by the capture tool's observer (system calls and Apple
// tool output) and is the expected value for every portable and native
// assertion. Raw attribute bytes are retained as digests; disk bytes live in
// the referenced image file.
type Observation struct {
	Schema   int      `json:"schema"`
	Recipe   string   `json:"recipe"`
	Profile  string   `json:"profile"`
	Stage    string   `json:"stage"`
	Producer Producer `json:"producer"`
	Image    Image    `json:"image"`
	Volumes  []Volume `json:"volumes"`
	Views    []View   `json:"views"`
	Checks   Checks   `json:"checks"`
	// Commands is the complete transcript of every program the capture ran
	// for this case, in order, including failures the recipe expected.
	Commands []Command `json:"commands"`
}

// Image describes the retained image file and the whole disk behind it.
type Image struct {
	File         string `json:"file"`
	SHA256       string `json:"sha256"`
	Bytes        int64  `json:"bytes"`
	Format       string `json:"format"`       // UDZO, UDRO, UDBZ, UDRW, raw
	PartitionMap string `json:"partitionMap"` // GPT, APM, none
	SectorSize   int    `json:"sectorSize"`
	// DiskSHA256 is the SHA-256 of the attached raw device, which is what a
	// sector-preserving repack must reproduce.
	DiskSHA256 string `json:"diskSHA256"`
	DiskBytes  int64  `json:"diskBytes"`
	// Partitions is `diskutil list -plist` for the attached disk.
	Partitions map[string]any `json:"partitions,omitempty"`
	// Encryption is present for encrypted DMGs: the cipher, the key-wrap
	// algorithm the producer used, the password reference that unlocks and
	// the references that must be rejected.
	Encryption *ImageEncryption `json:"encryption,omitempty"`
	// Imageinfo is `hdiutil imageinfo -plist` for the retained file.
	Imageinfo map[string]any `json:"imageinfo,omitempty"`
}

// ImageEncryption records credentials by reference, never by value.
type ImageEncryption struct {
	Cipher   string   `json:"cipher"`
	KeyWrap  string   `json:"keyWrap"`
	Password string   `json:"password"`
	Rejected []string `json:"rejected"`
}

// Volume is one mounted filesystem's identity as diskutil and the kernel
// report it.
type Volume struct {
	Index        int            `json:"index"`
	Device       string         `json:"device"`
	MountOptions string         `json:"mountOptions"`
	Diskutil     map[string]any `json:"diskutil"`
	APFS         *APFSVolume    `json:"apfs,omitempty"`
	HFS          *HFSVolume     `json:"hfs,omitempty"`
	FreeBytes    int64          `json:"freeBytes"`
}

// APFSVolume holds container and volume facts from diskutil apfs.
type APFSVolume struct {
	ContainerUUID string     `json:"containerUUID"`
	VolumeUUID    string     `json:"volumeUUID"`
	CaseSensitive bool       `json:"caseSensitive"`
	Role          string     `json:"role,omitempty"`
	GroupUUID     string     `json:"groupUUID,omitempty"`
	ReserveBytes  int64      `json:"reserveBytes"`
	QuotaBytes    int64      `json:"quotaBytes"`
	Encrypted     bool       `json:"encrypted"`
	EncRolled     bool       `json:"encRolled,omitempty"`
	Password      string     `json:"password,omitempty"`
	Rejected      []string   `json:"rejected,omitempty"`
	Snapshots     []Snapshot `json:"snapshots"`
}

// Snapshot is one retained APFS snapshot as diskutil and the kernel list it.
type Snapshot struct {
	Name      string `json:"name"`
	XID       uint64 `json:"xid"`
	UUID      string `json:"uuid"`
	CreatedNS int64  `json:"createdNs"`
	ChangedNS int64  `json:"changedNs"`
}

// HFSVolume holds HFS+ facts that only the raw header exposes.
type HFSVolume struct {
	CaseSensitive    bool   `json:"caseSensitive"`
	Journaled        bool   `json:"journaled"`
	JournalInfoBlock uint32 `json:"journalInfoBlock,omitempty"`
	JournalSHA256    string `json:"journalSHA256,omitempty"`
	// VolumeHeader and AlternateHeader are the 512-byte sectors, hex.
	VolumeHeader    string `json:"volumeHeader,omitempty"`
	AlternateHeader string `json:"alternateHeader,omitempty"`
}

// View is the complete entry set of one volume at one historical point.
type View struct {
	Volume   int     `json:"volume"`
	Snapshot string  `json:"snapshot,omitempty"` // empty means live
	Entries  []Entry `json:"entries"`
	Lookups  []Probe `json:"lookups,omitempty"`
	// AppleDouble lists exported ._ files for entries with metadata.
	AppleDouble []AppleDoubleExport `json:"appleDouble,omitempty"`
}

// Entry is one filesystem object exactly as lstat, getxattr, readlink and
// full reads reported it. Directories omit Size and Links because those are
// synthetic on both filesystems.
type Entry struct {
	Path      string  `json:"path"`
	NameBytes string  `json:"nameBytes"` // hex of the final component as enumerated
	Kind      string  `json:"kind"`      // file, dir, symlink
	ID        uint64  `json:"id"`
	Links     uint32  `json:"links,omitempty"`
	Mode      uint32  `json:"mode"`
	UID       uint32  `json:"uid"`
	GID       uint32  `json:"gid"`
	Flags     uint32  `json:"flags"`
	Size      int64   `json:"size,omitempty"`
	Allocated int64   `json:"allocated,omitempty"`
	Times     Times   `json:"times"`
	SHA256    string  `json:"sha256,omitempty"`    // logical data
	RawSHA256 string  `json:"rawSHA256,omitempty"` // stored data fork when compressed
	Target    string  `json:"target,omitempty"`    // symlink target bytes, hex
	Xattrs    []Xattr `json:"xattrs,omitempty"`
	// Compression is present when UF_COMPRESSED is set.
	Compression *Compression `json:"compression,omitempty"`
	// Sparse lists [offset, length] ranges the kernel reports as holes.
	Sparse [][2]int64 `json:"sparse,omitempty"`
	// Extents lists [logical, physical, length] triples from F_LOG2PHYS_EXT
	// for the data and resource forks when the recipe asked for them.
	Extents *Extents `json:"extents,omitempty"`
	// Samples are reads crossing extent or block boundaries.
	Samples []Sample `json:"samples,omitempty"`
	// ACL is the textual ACL from `ls -le` style getattrlist output when
	// the entry carries one.
	ACL string `json:"acl,omitempty"`
}

// Times are nanoseconds since the Unix epoch at native precision.
type Times struct {
	Birth  int64 `json:"birth"`
	Modify int64 `json:"mtime"`
	Change int64 `json:"ctime"`
	Access int64 `json:"atime"`
	// Added is the date-added attribute when available (APFS).
	Added *int64 `json:"added,omitempty"`
}

// Xattr records an attribute's presence, size and digest; values are not
// retained because some are large and some are compression storage.
type Xattr struct {
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

// Compression describes active decmpfs storage and what the kernel did when
// asked to read it. KernelRead is "ok" or an errno name such as "EIO".
type Compression struct {
	Type       uint32 `json:"type"`
	Storage    string `json:"storage"` // attribute or resource
	KernelRead string `json:"kernelRead"`
}

// Extents groups per-fork physical mappings.
type Extents struct {
	Data     [][3]int64 `json:"data"`
	Resource [][3]int64 `json:"rsrc,omitempty"`
}

// Sample is one bounded read and its digest.
type Sample struct {
	Fork   string `json:"fork"`
	Offset int64  `json:"offset"`
	Length int    `json:"length"`
	SHA256 string `json:"sha256"`
}

// Probe is the outcome of a native lookup: the object ID found or an errno.
type Probe struct {
	Dir    string `json:"dir"`
	Query  string `json:"query"` // hex bytes
	Result string `json:"result"`
	ID     uint64 `json:"id,omitempty"`
}

// AppleDoubleExport points at a retained ._ file for an entry.
type AppleDoubleExport struct {
	Path   string `json:"path"`
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

// Checks records integrity verdicts on the detached image.
type Checks struct {
	Verify   *CommandResult   `json:"verify,omitempty"`
	Fsck     []CommandResult  `json:"fsck,omitempty"`
	Codesign []CodesignResult `json:"codesign,omitempty"`
	// SelectedXID is the checkpoint fsck_apfs selected for interruption
	// cases.
	SelectedXID uint64 `json:"selectedXID,omitempty"`
}

// CommandResult is an exit status with digests of its output.
type CommandResult struct {
	Argv         []string `json:"argv"`
	Status       int      `json:"status"`
	StdoutSHA256 string   `json:"stdoutSHA256,omitempty"`
	StderrSHA256 string   `json:"stderrSHA256,omitempty"`
}

// CodesignResult is one signature verification.
type CodesignResult struct {
	Path   string `json:"path"`
	Status int    `json:"status"`
}

// Command is one transcript entry. Status is the exit code, or "timeout",
// "launch-failed" when the program did not complete.
type Command struct {
	Label        string   `json:"label,omitempty"`
	Argv         []string `json:"argv"`
	Sudo         bool     `json:"sudo,omitempty"`
	Status       string   `json:"status"`
	Errno        string   `json:"errno,omitempty"`
	Expected     string   `json:"expected"`
	StdoutSHA256 string   `json:"stdoutSHA256,omitempty"`
	StderrSHA256 string   `json:"stderrSHA256,omitempty"`
	StdoutText   string   `json:"stdout,omitempty"` // retained when small and not binary
	StderrText   string   `json:"stderr,omitempty"`
	WallNS       int64    `json:"wallNs"`
}
