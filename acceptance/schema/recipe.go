package schema

import (
	"fmt"
	"regexp"
	"strings"
)

// RecipeSchema is the current recipe schema version.
const RecipeSchema = 1

// Recipe describes, declaratively, what the capture tool creates on a volume
// and what it observes. Recipes are data: the capture tool interprets them
// with Apple tools and system calls only, so the same recipe can be executed
// on every macOS version and compared.
type Recipe struct {
	Schema   int          `json:"schema"`
	Name     string       `json:"name"`
	Purpose  string       `json:"purpose"`
	Profiles []string     `json:"profiles"`
	Requires Requirements `json:"requires"`
	Image    ImageSpec    `json:"image"`
	// Passwords maps a reference name to a public fixture password. Steps
	// refer to passwords by name; observations record names, never bytes.
	Passwords map[string]string `json:"passwords,omitempty"`
	Stages    []Stage           `json:"stages"`
	// Derive produces additional images from a completed stage's image
	// (for example an encrypted DMG conversion) without a new mount.
	Derive []Derivation `json:"derive,omitempty"`
}

// Requirements declares what a recipe needs from the producing host.
type Requirements struct {
	Sudo         bool     `json:"sudo"`
	Entitlements []string `json:"entitlements,omitempty"`
	// Helpers names programs the capture tool must build from Apple open
	// source under acceptance/recipes/helpers before running the recipe,
	// for example "newfs_hfs_debug" (exposes allocation geometry flags the
	// shipping binary hides). They are Apple code compiled with xcrun.
	Helpers  []string `json:"helpers,omitempty"`
	MinMajor int      `json:"minMajor,omitempty"`
	// VersionNotes records expected behaviour differences between producers
	// (for example a decmpfs type only the newest kernel reads). The native
	// verifier's drift table must match these notes.
	VersionNotes map[string]string `json:"versionNotes,omitempty"`
}

// ImageSpec describes the disk image the recipe creates per profile.
type ImageSpec struct {
	// Create is "hdiutil" (hdiutil create -fs <profile>) or "raw-newfs"
	// (a sparse raw file attached as CRawDiskImage and formatted with the
	// Newfs arguments, which is how allocation geometry is controlled).
	Create string `json:"create"`
	// Newfs holds, per profile, the newfs_hfs/newfs_apfs arguments used
	// with raw-newfs; $RDEV and $VOLNAME are substituted. The program is
	// Helpers' newfs_hfs_debug when that helper is required.
	Newfs map[string]string `json:"newfs,omitempty"`
	// Size is the hdiutil size argument, for example "64m" or "1536m".
	// SizeByProfile overrides it for individual profiles.
	Size          string            `json:"size"`
	SizeByProfile map[string]string `json:"sizeByProfile,omitempty"`
	// Layout is the hdiutil -layout argument: GPTSPUD, SPUD, NONE.
	// LayoutByProfile overrides it per profile.
	Layout          string            `json:"layout"`
	LayoutByProfile map[string]string `json:"layoutByProfile,omitempty"`
	// FSArgs are passed through -fsargs, keyed by profile (for example
	// "-E -S $PASSWORD:primary" to create an encrypted APFS volume).
	FSArgs map[string]string `json:"fsargs,omitempty"`
	// Output is the hdiutil convert format of the retained image: UDZO,
	// UDRO, UDBZ, UDRW, or "raw" to retain the gzip-compressed raw device.
	// OutputByProfile overrides it per profile.
	Output          string            `json:"output"`
	OutputByProfile map[string]string `json:"outputByProfile,omitempty"`
	// VolumeName is the -volname; the default is the recipe name.
	VolumeName string `json:"volumeName,omitempty"`
	// MountOptions are passed to diskutil mount -mountOptions when set
	// (for example "owners,noatime"); otherwise hdiutil attach defaults.
	MountOptions string `json:"mountOptions,omitempty"`
}

// Stage is an ordered sequence of steps on the mounted volume followed by an
// observation. A recipe with several stages records before/after states;
// each stage's image is retained under its name.
type Stage struct {
	Name string `json:"name"`
	// From names the stage whose retained image this stage starts from;
	// the default is the previous stage. The first stage starts from the
	// freshly formatted volume.
	From string `json:"from,omitempty"`
	// Discard keeps the observation but does not retain this stage's
	// image, for intermediate states whose history is retained elsewhere
	// (for example inside snapshots).
	Discard bool        `json:"discard,omitempty"`
	Steps   []Step      `json:"steps"`
	Observe ObserveSpec `json:"observe"`
}

// Step is exactly one of: a host staging action, an Apple tool invocation,
// a filesystem operation on the mounted volume, or a capture-tool procedure.
// Exactly one field is set.
type Step struct {
	Host    *HostStep    `json:"host,omitempty"`
	Tool    *ToolStep    `json:"tool,omitempty"`
	FS      *FSStep      `json:"fs,omitempty"`
	Control *ControlStep `json:"control,omitempty"`
	// Only limits a step to some profiles; empty means every profile.
	Only []string `json:"only,omitempty"`
	// Note explains why the step exists; it is copied into the transcript.
	Note string `json:"note,omitempty"`
}

// HostStep generates content in the host staging directory ($STAGE). Go may
// write only there; Apple tools move bytes onto the fixture volume.
type HostStep struct {
	// Path is relative to $STAGE.
	Path string `json:"path"`
	// Pattern selects the generator: "zeros", "sequence" (deterministic
	// byte sequence seeded by Seed), "text" (Content), "payload" (a file
	// from recipes/payloads named by Payload), or "tree" (Count files of
	// Bytes each under Path, named <Prefix><index>).
	Pattern string `json:"pattern"`
	Bytes   int64  `json:"bytes,omitempty"`
	Seed    uint64 `json:"seed,omitempty"`
	Content string `json:"content,omitempty"`
	Payload string `json:"payload,omitempty"`
	Count   int    `json:"count,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
	// Label is appended to each 256-byte cycle of the sequence pattern.
	Label string `json:"label,omitempty"`
	// Mode applies to generated files; directories use 0755.
	Mode uint32 `json:"mode,omitempty"`
}

// ToolStep runs one Apple program. Arguments may reference $STAGE, $MOUNT,
// $DEVICE, $CONTAINER, $VOLUME, $IMAGE, $OUT, $MOUNT:<volume> for multi-volume
// recipes, and $HEX:<payload> for hex-encoded payload bytes.
type ToolStep struct {
	Program string   `json:"program"`
	Args    []string `json:"args"`
	// Stdin names password references fed on standard input, one per line.
	Stdin []string `json:"stdin,omitempty"`
	// StdinBytes feeds a payload's bytes instead.
	StdinBytes string `json:"stdinBytes,omitempty"`
	Sudo       bool   `json:"sudo,omitempty"`
	// Expect is the required exit status. "record" accepts any status and
	// records it with errno; it is for operations whose outcome is the
	// observation (pressure to ENOSPC, rejected credentials).
	Expect string `json:"expect"`
	// TimeoutSeconds bounds the command; the default is 120.
	TimeoutSeconds int `json:"timeoutSeconds,omitempty"`
	// Label names the step's transcript entry for consumers.
	Label string `json:"label,omitempty"`
}

// FSStep performs one POSIX operation on the mounted fixture volume through
// the kernel, exactly as the earlier Python collectors did. The capture tool
// never interprets on-disk structures; it asks the kernel. Apple CLIs remain
// the step of choice wherever the tool's own policy is the subject (cp -c,
// cp -p, ditto --hfsCompression, ln, mv, chmod +a, codesign).
//
// Op is one of: write (Content/Payload/Pattern bytes to Path, creating or
// replacing), append, pwrite (at Offset), truncate (to Bytes), mkdir,
// symlink (Target), link (Target is the new name), rename (to Target),
// unlink, rmdir, chmod (Mode), chflags (Flags), setxattr (Name, bytes as
// for write), removexattr (Name), settimes (Times), fullfsync, clone
// (clonefile Path to Target), fill (write Bytes-sized files under Path
// until ENOSPC or Count files, recording the errno and count), and
// thin (unlink every even-numbered file under Path, used to fragment free
// space after fill).
type FSStep struct {
	Op      string `json:"op"`
	Path    string `json:"path"`
	Target  string `json:"target,omitempty"`
	Name    string `json:"name,omitempty"`
	Offset  int64  `json:"offset,omitempty"`
	Bytes   int64  `json:"bytes,omitempty"`
	Count   int    `json:"count,omitempty"`
	Mode    uint32 `json:"mode,omitempty"`
	Flags   uint32 `json:"flags,omitempty"`
	Content string `json:"content,omitempty"`
	// Repeat writes Content that many times.
	Repeat  int    `json:"repeat,omitempty"`
	Payload string `json:"payload,omitempty"`
	// Pattern generates bytes: "sequence" (0..255 repeating, optionally
	// with Label appended each cycle), "zeros", or empty for Content.
	Pattern string `json:"pattern,omitempty"`
	Label   string `json:"label,omitempty"`
	// Option is "create" or "replace" for setxattr (XATTR_CREATE /
	// XATTR_REPLACE), whose refusals are observations.
	Option string `json:"option,omitempty"`
	// Times are nanoseconds since the epoch; zero fields are left as is.
	Times *TimeSpec `json:"times,omitempty"`
	// Expect is "0" or an errno name such as "ENOSPC" for operations whose
	// failure is the observation.
	Expect string `json:"expect,omitempty"`
}

// TimeSpec carries explicit timestamps for settimes.
type TimeSpec struct {
	Birth  int64 `json:"birth,omitempty"`
	Modify int64 `json:"mtime,omitempty"`
	Access int64 `json:"atime,omitempty"`
}

var fsOps = map[string]bool{
	"write": true, "append": true, "pwrite": true, "truncate": true, "mkdir": true,
	"symlink": true, "link": true, "rename": true, "unlink": true, "rmdir": true,
	"chmod": true, "chflags": true, "setxattr": true, "removexattr": true,
	"settimes": true, "fullfsync": true, "clone": true, "fill": true, "thin": true,
}

// ControlStep performs a capture-tool procedure that spans several
// programs and process signals and so cannot be one ToolStep:
//
//   - "asr-snapshot": replicate the mounted volume with asr to a disposable
//     target so Apple creates a com.apple.asr.* snapshot, observe it with
//     fs_snapshot_list, pause asr, pin the snapshot by mounting it, resume
//     asr and require success. Name labels the snapshot in observations.
//   - "pause-helper" / "resume-helper": stop and continue the image's
//     diskimages-helper after the transcript entry labelled After, for
//     interruption recipes.
//   - "retain-device": copy the raw backing device to $OUT/<Name>.raw.gz.
//   - "journal-window": for a volume attached with -nokernel, run a churn
//     workload and pause the image helper when the journal reaches the
//     shape in Params (shape: linear, wrapped, complete-tail,
//     incomplete-tail); retain the interrupted device as Name.
//   - "replay-journal": ask the HFS driver to replay the journal of the
//     attached raw device through the vfs.generic.hfs.replay_journal
//     sysctl and retain the result as Name.
//   - "checkpoint-window": like journal-window for APFS checkpoints
//     (window: data, mapping, committed, wrapped).
//   - "damage": derive a copy with one byte changed (kind: bad-mapping,
//     bad-object, disabled-latest) and retain it as Name.
//   - "settle-encryption": poll diskutil until CryptoMigrationOn is false
//     and FileVault equals Params["fileVault"].
//   - "snapshot-api": run the entitled fs_snapshot helper (op: create,
//     rename, revert) and record status/errno; EPERM is an accepted
//     outcome that the observation records.
//   - "free-space-sentinel": write 512 recognisable bytes into the first
//     Apple_Free partition of the detached raw image and record the
//     offset, proving a repack preserves sectors outside every filesystem.
type ControlStep struct {
	Action string            `json:"action"`
	After  string            `json:"after,omitempty"`
	Name   string            `json:"name,omitempty"`
	Params map[string]string `json:"params,omitempty"`
}

// ObserveSpec selects what the observer records beyond the default entry
// set (every object under the volume root with metadata, hashes, attributes
// and forks).
type ObserveSpec struct {
	// Snapshots observes every retained snapshot as a historical view in
	// addition to the live view, by mounting each read-only.
	Snapshots bool `json:"snapshots,omitempty"`
	// Extents lists glob patterns of paths whose physical extents are
	// recorded with F_LOG2PHYS_EXT.
	Extents []string `json:"extents,omitempty"`
	// Samples is the number of boundary-crossing reads recorded per file
	// with extents.
	Samples int `json:"samples,omitempty"`
	// Lookups records native lookup results for each query against a
	// directory: the inode found, or ENOENT.
	Lookups []Lookup `json:"lookups,omitempty"`
	// RawHeaders retains the volume header sectors (HFS) or the container
	// superblock range (APFS) read from the detached raw device.
	RawHeaders bool `json:"rawHeaders,omitempty"`
	// AppleDouble exports every entry's COPYFILE_PACK form by copying the
	// tree with cp -p onto a disposable ExFAT image and retaining the
	// resulting ._ files.
	AppleDouble bool `json:"appleDouble,omitempty"`
	// Checks lists integrity programs to run on the detached image: fsck,
	// verify (hdiutil verify), codesign (paths listed in Codesign).
	Checks   []string `json:"checks,omitempty"`
	Codesign []string `json:"codesign,omitempty"`
	// Unlock maps a volume name to the password reference that unlocks it
	// for observation; Rejected lists references that must be refused
	// first, leaving the volume locked. The key "*" means the only volume.
	Unlock   map[string]string   `json:"unlock,omitempty"`
	Rejected map[string][]string `json:"rejected,omitempty"`
	// Statistics runs apfs.util -S on each listed directory and records
	// its output verbatim.
	Statistics []string `json:"statistics,omitempty"`
}

// Lookup is a native name-comparison probe.
type Lookup struct {
	Dir   string `json:"dir"`
	Query string `json:"query"`
	// Expect is "found" (must resolve to the object at Target), "absent"
	// (must fail with ENOENT) or "record" (either outcome is legitimate
	// and the observation is the evidence, as for Unicode spellings whose
	// equivalence differs by filesystem). A found/absent mismatch fails
	// capture.
	Expect string `json:"expect"`
	Target string `json:"target,omitempty"`
}

// Derivation converts a completed stage image into another retained image.
type Derivation struct {
	Name  string     `json:"name"`
	From  string     `json:"from"`
	Only  []string   `json:"only,omitempty"`
	Steps []ToolStep `json:"steps"`
	// Observe re-observes the derived image's volumes when true (for
	// encrypted images the observer unlocks with Password).
	Observe  bool   `json:"observe,omitempty"`
	Password string `json:"password,omitempty"`
	// Expect encodes credential expectations for derived encrypted images:
	// references that must unlock and references that must be rejected.
	Rejected []string `json:"rejected,omitempty"`
}

var namePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// Validate checks structural rules that the decoder cannot express.
func (r *Recipe) Validate() error {
	if r.Schema != RecipeSchema {
		return fmt.Errorf("recipe %q: schema %d, want %d", r.Name, r.Schema, RecipeSchema)
	}
	if !namePattern.MatchString(r.Name) {
		return fmt.Errorf("recipe name %q must be lowercase kebab-case", r.Name)
	}
	if r.Purpose == "" {
		return fmt.Errorf("recipe %q: purpose is required", r.Name)
	}
	if len(r.Profiles) == 0 {
		return fmt.Errorf("recipe %q: at least one profile is required", r.Name)
	}
	seen := map[string]bool{}
	for _, id := range r.Profiles {
		if _, err := LookupProfile(id); err != nil {
			return fmt.Errorf("recipe %q: %w", r.Name, err)
		}
		if seen[id] {
			return fmt.Errorf("recipe %q: profile %s listed twice", r.Name, id)
		}
		seen[id] = true
	}
	switch r.Image.Layout {
	case "GPTSPUD", "SPUD", "NONE":
	default:
		return fmt.Errorf("recipe %q: unknown layout %q", r.Name, r.Image.Layout)
	}
	switch r.Image.Output {
	case "UDZO", "UDRO", "UDBZ", "UDRW", "raw":
	default:
		return fmt.Errorf("recipe %q: unknown output format %q", r.Name, r.Image.Output)
	}
	if r.Image.Size == "" {
		return fmt.Errorf("recipe %q: image size is required", r.Name)
	}
	switch r.Image.Create {
	case "hdiutil":
	case "raw-newfs":
		for _, id := range r.Profiles {
			if _, ok := r.Image.Newfs[id]; !ok {
				return fmt.Errorf("recipe %q: raw-newfs needs newfs arguments for profile %s", r.Name, id)
			}
		}
	default:
		return fmt.Errorf("recipe %q: image create must be hdiutil or raw-newfs", r.Name)
	}
	if len(r.Stages) == 0 {
		return fmt.Errorf("recipe %q: at least one stage is required", r.Name)
	}
	stages := map[string]bool{}
	for _, stage := range r.Stages {
		if !namePattern.MatchString(stage.Name) || stages[stage.Name] {
			return fmt.Errorf("recipe %q: stage name %q invalid or duplicated", r.Name, stage.Name)
		}
		if stage.From != "" && !stages[stage.From] {
			return fmt.Errorf("recipe %q: stage %s starts from unknown earlier stage %q", r.Name, stage.Name, stage.From)
		}
		stages[stage.Name] = true
		for i, step := range stage.Steps {
			if err := step.validate(r, stage.Name, i); err != nil {
				return err
			}
		}
		for _, lookup := range stage.Observe.Lookups {
			if lookup.Expect != "found" && lookup.Expect != "absent" && lookup.Expect != "record" {
				return fmt.Errorf("recipe %q: stage %s lookup %q expects %q", r.Name, stage.Name, lookup.Query, lookup.Expect)
			}
		}
	}
	for _, d := range r.Derive {
		if !namePattern.MatchString(d.Name) || stages[d.Name] {
			return fmt.Errorf("recipe %q: derivation name %q invalid or clashes with a stage", r.Name, d.Name)
		}
		if !stages[d.From] {
			return fmt.Errorf("recipe %q: derivation %s derives from unknown stage %q", r.Name, d.Name, d.From)
		}
		for i := range d.Steps {
			if err := d.Steps[i].validate(r); err != nil {
				return fmt.Errorf("recipe %q: derivation %s step %d: %w", r.Name, d.Name, i, err)
			}
		}
		for _, ref := range append([]string{d.Password}, d.Rejected...) {
			if ref != "" {
				if _, ok := r.Passwords[ref]; !ok && !strings.HasPrefix(ref, "literal:") {
					return fmt.Errorf("recipe %q: derivation %s references unknown password %q", r.Name, d.Name, ref)
				}
			}
		}
	}
	return nil
}

func (s *Step) validate(r *Recipe, stage string, index int) error {
	set := 0
	for _, present := range []bool{s.Host != nil, s.Tool != nil, s.FS != nil, s.Control != nil} {
		if present {
			set++
		}
	}
	if set != 1 {
		return fmt.Errorf("recipe %q: stage %s step %d must set exactly one of host, tool, fs, control", r.Name, stage, index)
	}
	for _, id := range s.Only {
		if _, err := LookupProfile(id); err != nil {
			return fmt.Errorf("recipe %q: stage %s step %d: %w", r.Name, stage, index, err)
		}
	}
	switch {
	case s.Host != nil:
		switch s.Host.Pattern {
		case "zeros", "sequence", "text", "payload", "tree":
		default:
			return fmt.Errorf("recipe %q: stage %s step %d: unknown host pattern %q", r.Name, stage, index, s.Host.Pattern)
		}
		if s.Host.Path == "" || strings.HasPrefix(s.Host.Path, "/") || strings.Contains(s.Host.Path, "..") {
			return fmt.Errorf("recipe %q: stage %s step %d: host path %q must be relative and inside the staging tree", r.Name, stage, index, s.Host.Path)
		}
	case s.Tool != nil:
		if err := s.Tool.validate(r); err != nil {
			return fmt.Errorf("recipe %q: stage %s step %d: %w", r.Name, stage, index, err)
		}
	case s.FS != nil:
		if !fsOps[s.FS.Op] {
			return fmt.Errorf("recipe %q: stage %s step %d: unknown fs op %q", r.Name, stage, index, s.FS.Op)
		}
		if s.FS.Path == "" {
			return fmt.Errorf("recipe %q: stage %s step %d: fs path is required", r.Name, stage, index)
		}
		if s.FS.Option != "" && s.FS.Option != "create" && s.FS.Option != "replace" {
			return fmt.Errorf("recipe %q: stage %s step %d: xattr option %q", r.Name, stage, index, s.FS.Option)
		}
	case s.Control != nil:
		switch s.Control.Action {
		case "asr-snapshot", "pause-helper", "resume-helper", "retain-device",
			"journal-window", "replay-journal", "checkpoint-window", "damage",
			"settle-encryption", "snapshot-api", "free-space-sentinel":
		default:
			return fmt.Errorf("recipe %q: stage %s step %d: unknown control action %q", r.Name, stage, index, s.Control.Action)
		}
	}
	return nil
}

// AllowedPrograms is the complete set of programs a recipe may invoke. The
// capture tool refuses anything else, which keeps "Apple tools only" a
// checkable property rather than a convention.
var AllowedPrograms = map[string]bool{
	"hdiutil": true, "diskutil": true, "newfs_hfs": true, "newfs_apfs": true,
	"fsck_hfs": true, "fsck_apfs": true, "asr": true, "mount_apfs": true,
	"ditto": true, "cp": true, "ln": true, "mv": true, "rm": true, "mkdir": true,
	"touch": true, "chmod": true, "chown": true, "chflags": true, "xattr": true,
	"dd": true, "codesign": true, "compression_tool": true, "xcrun": true,
	"apfs.util": true, "mount_hfs": true, "umount": true, "sync": true, "unzip": true,
}

func (t *ToolStep) validate(r *Recipe) error {
	if !AllowedPrograms[t.Program] {
		return fmt.Errorf("program %q is not an allowed Apple tool", t.Program)
	}
	switch t.Expect {
	case "0", "record":
	default:
		if _, err := fmt.Sscanf(t.Expect, "%d", new(int)); err != nil {
			return fmt.Errorf("expect %q must be an exit status or \"record\"", t.Expect)
		}
	}
	for _, ref := range t.Stdin {
		if _, ok := r.Passwords[ref]; !ok {
			return fmt.Errorf("stdin references unknown password %q", ref)
		}
	}
	return nil
}
