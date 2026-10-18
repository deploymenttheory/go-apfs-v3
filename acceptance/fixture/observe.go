package fixture

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// ObserveInput is everything the observer needs for one retained image
// that is attached read-only.
type ObserveInput struct {
	Recipe   *schema.Recipe
	Profile  schema.Profile
	Stage    string
	Spec     schema.ObserveSpec
	Image    string // retained image path
	Format   string
	Password []byte // image password for encrypted DMGs
	Att      *Attachment
	Disk     Disk
	Vol      Volume
	Vars     *Vars
	T        *Transcript
	Work     string // scratch directory for mounts and exports
	Out      string // directory receiving exported files
	Prefix   string // "<profile>.<stage>" for exported file names
	Producer schema.Producer
}

// rootExclusions are directories macOS creates on every mounted volume; they
// are not fixture content.
var rootExclusions = map[string]bool{
	".fseventsd": true, ".Spotlight-V100": true, ".Trashes": true, ".TemporaryItems": true,
	".DocumentRevisions-V100": true, ".DS_Store": true, ".journal": true, ".journal_info_block": true,
	".hotfiles.btree": true, ".HFS+ Private Directory Data\r": true, "\x00\x00\x00\x00HFS+ Private Data": true,
	".PKInstallSandboxManager-SystemSoftware": true, ".metadata_never_index": true, ".apdisk": true,
}

// resourceTypes are decmpfs types whose storage is the resource fork.
var resourceTypes = map[uint32]bool{4: true, 8: true, 10: true, 12: true, 14: true, 16: true}

// Observe records the kernel's view of every volume on the attachment.
func Observe(ctx context.Context, in ObserveInput) (*schema.Observation, error) {
	obs := &schema.Observation{Schema: schema.ObservationSchema, Recipe: in.Recipe.Name, Profile: in.Profile.ID, Stage: in.Stage, Producer: in.Producer}
	if err := observeImage(ctx, in, obs); err != nil {
		return nil, err
	}
	for i, vol := range in.Att.Volumes {
		if err := observeVolume(ctx, in, obs, i, vol); err != nil {
			return nil, fmt.Errorf("volume %s: %w", vol.Name, err)
		}
	}
	if err := observeChecks(ctx, in, obs); err != nil {
		return nil, err
	}
	obs.Commands = in.T.Commands
	return obs, nil
}

func observeImage(ctx context.Context, in ObserveInput, obs *schema.Observation) error {
	sum, err := schema.FileDigest(in.Image)
	if err != nil {
		return err
	}
	info, err := os.Stat(in.Image)
	if err != nil {
		return err
	}
	obs.Image = schema.Image{File: filepath.Base(in.Image), SHA256: sum, Bytes: info.Size(), Format: in.Format, SectorSize: 512}
	if in.Format != "raw" {
		imageinfo, err := in.Disk.Imageinfo(ctx, in.Image, in.Password)
		if err != nil {
			return err
		}
		obs.Image.Imageinfo = imageinfo
	}
	disk, err := in.Disk.Info(ctx, in.Att.Dev)
	if err != nil {
		return err
	}
	size := int64(number(disk["TotalSize"]))
	if content, _ := disk["Content"].(string); strings.Contains(content, "GUID") {
		obs.Image.PartitionMap = "GPT"
	} else if strings.Contains(content, "Apple_partition") {
		obs.Image.PartitionMap = "APM"
	} else {
		obs.Image.PartitionMap = "none"
	}
	if size > 0 {
		digest, err := in.Disk.DeviceDigest(ctx, in.Att.RDev, size, "")
		if err != nil {
			return err
		}
		obs.Image.DiskSHA256, obs.Image.DiskBytes = digest, size
	}
	listing, err := in.Disk.List(ctx, in.Att.Dev)
	if err != nil {
		return err
	}
	obs.Image.Partitions = listing
	if in.Password != nil {
		obs.Image.Encryption = &schema.ImageEncryption{}
	}
	return nil
}

func observeVolume(ctx context.Context, in ObserveInput, obs *schema.Observation, index int, vol *AttachedVolume) error {
	info, err := in.Disk.Info(ctx, vol.Dev)
	if err != nil {
		return err
	}
	v := schema.Volume{Index: index, Device: vol.Dev, Diskutil: info}
	locked, _ := info["Locked"].(bool)
	fileVault, _ := info["FileVault"].(bool)
	if fileVault && !locked {
		// macOS may reuse an earlier unlock when the image is re-attached.
		// Lock explicitly so the credential checks and the recorded locked
		// state are genuine.
		cmd := Command{Label: "lock", Argv: []string{"diskutil", "apfs", "lockVolume", vol.Dev}, Expected: "0"}
		if err := in.T.Record(cmd, in.Disk.(*HostDisk).C.Run(ctx, cmd)); err != nil {
			return err
		}
		info, err = in.Disk.Info(ctx, vol.Dev)
		if err != nil {
			return err
		}
		locked, _ = info["Locked"].(bool)
		if !locked {
			return fmt.Errorf("volume %s did not lock", vol.Name)
		}
	}
	ref := in.Spec.Unlock[vol.Name]
	if ref == "" {
		ref = in.Spec.Unlock["*"]
	}
	if locked {
		if ref == "" {
			return fmt.Errorf("volume %s is locked and the recipe names no unlock password", vol.Name)
		}
		rejected := in.Spec.Rejected[vol.Name]
		if rejected == nil {
			rejected = in.Spec.Rejected["*"]
		}
		for _, bad := range rejected {
			if err := unlockVolume(ctx, in, vol, bad, false); err != nil {
				return err
			}
			again, err := in.Disk.Info(ctx, vol.Dev)
			if err != nil {
				return err
			}
			if still, _ := again["Locked"].(bool); !still {
				return fmt.Errorf("volume %s unlocked with rejected credential %q", vol.Name, bad)
			}
		}
		if err := unlockVolume(ctx, in, vol, ref, true); err != nil {
			return err
		}
	}
	// The image is attached read-only, so the mount is read-only without
	// the readOnly verb, which diskutil refuses for a just-unlocked volume.
	// An unlocked volume is mounted where diskutil chooses with owners
	// only, the sequence Apple's own tools accept.
	mount := filepath.Join(in.Work, "observe", sanitize(vol.Name))
	options := "owners,noatime"
	if locked {
		mount, options = "", "owners"
	}
	if err := in.Disk.Mount(ctx, vol, options, mount, false); err != nil {
		return err
	}
	mount = vol.Mount
	defer func() { _ = in.Disk.Unmount(ctx, vol) }()
	info, err = in.Disk.Info(ctx, vol.Dev)
	if err != nil {
		return err
	}
	v.Diskutil = info
	v.MountOptions = "rdonly,owners,noatime"
	free, err := in.Vol.FreeBytes(mount)
	if err != nil {
		return err
	}
	v.FreeBytes = free
	fsName, _ := info["FilesystemName"].(string)
	sensitive := strings.Contains(strings.ToLower(fsName), "case-sensitive")
	if fsType, _ := info["FilesystemType"].(string); fsType == "apfs" {
		a := &schema.APFSVolume{CaseSensitive: sensitive}
		a.ContainerUUID, _ = info["APFSContainerUUID"].(string)
		a.VolumeUUID, _ = info["VolumeUUID"].(string)
		a.GroupUUID, _ = info["APFSVolumeGroupID"].(string)
		if roles, _ := info["APFSVolumeRoles"].([]any); len(roles) > 0 {
			a.Role, _ = roles[0].(string)
		}
		a.ReserveBytes = int64(number(info["CapacityReserve"]))
		a.QuotaBytes = int64(number(info["CapacityQuota"]))
		a.Encrypted, _ = info["FileVault"].(bool)
		if locked || a.Encrypted {
			a.Password = ref
			a.Rejected = in.Spec.Rejected[vol.Name]
			if a.Rejected == nil {
				a.Rejected = in.Spec.Rejected["*"]
			}
		}
		snaps, err := in.Disk.Snapshots(ctx, vol.Dev)
		if err != nil {
			return err
		}
		a.Snapshots = []schema.Snapshot{}
		for _, s := range snaps {
			name, _ := s["SnapshotName"].(string)
			uuid, _ := s["SnapshotUUID"].(string)
			xid := number(s["SnapshotXID"])
			if xid == 0 {
				xid = number(s["XID"])
			}
			a.Snapshots = append(a.Snapshots, schema.Snapshot{Name: name, UUID: uuid, XID: uint64(xid)})
		}
		if in.Spec.RawHeaders {
			raw, err := in.Disk.ReadRange(ctx, in.Att.RDev, 0, 4096)
			if err != nil {
				return err
			}
			v.RawHeader = hex.EncodeToString(raw)
		}
		v.APFS = a
	} else {
		h := &schema.HFSVolume{CaseSensitive: sensitive}
		// diskutil describes the mount, and a read-only mount of a journaled
		// volume is reported without its journal; the volume header's
		// attribute bit and journal info block are the volume's own facts.
		head, err := in.Disk.ReadRange(ctx, vol.RDev, 1024, 512)
		if err != nil {
			return err
		}
		if len(head) == 512 && (string(head[0:2]) == "H+" || string(head[0:2]) == "HX") {
			attributes := binary.BigEndian.Uint32(head[4:8])
			h.Journaled = attributes&(1<<13) != 0
			if h.Journaled {
				blockSize := int64(binary.BigEndian.Uint32(head[40:44]))
				infoBlock := int64(binary.BigEndian.Uint32(head[12:16]))
				info, err := in.Disk.ReadRange(ctx, vol.RDev, infoBlock*blockSize, 512)
				if err != nil {
					return err
				}
				if len(info) == 512 {
					h.JournalOffset = int64(binary.BigEndian.Uint64(info[36:44]))
					h.JournalBytes = int64(binary.BigEndian.Uint64(info[44:52]))
				}
			}
		}
		if in.Spec.RawHeaders {
			total := int64(number(info["TotalSize"]))
			h.VolumeHeader = hex.EncodeToString(head)
			if total >= 2048 {
				alt, err := in.Disk.ReadRange(ctx, vol.RDev, total-1024, 512)
				if err != nil {
					return err
				}
				h.AlternateHeader = hex.EncodeToString(alt)
			}
		}
		if h.JournalBytes > 0 && h.JournalBytes <= 64<<20 {
			journal, err := in.Disk.ReadRange(ctx, vol.RDev, h.JournalOffset, int(h.JournalBytes))
			if err != nil {
				return err
			}
			sum := sha256.Sum256(journal)
			h.JournalSHA256 = hex.EncodeToString(sum[:])
		}
		v.HFS = h
	}
	obs.Volumes = append(obs.Volumes, v)

	view, err := observeView(ctx, in, index, "", mount)
	if err != nil {
		return err
	}
	obs.Views = append(obs.Views, *view)
	// Signatures are verified while the volume is mounted: an encrypted
	// volume locks again when unmounted.
	for _, rel := range in.Spec.Codesign {
		target := filepath.Join(mount, filepath.FromSlash(rel))
		if _, err := in.Vol.Lstat(target); err != nil {
			continue
		}
		cmd := Command{Label: "codesign:" + rel, Argv: []string{"codesign", "--verify", "--deep", "--strict", target}, Expected: "record"}
		result := in.Disk.(*HostDisk).C.Run(ctx, cmd)
		_ = in.T.Record(cmd, result)
		obs.Checks.Codesign = append(obs.Checks.Codesign, schema.CodesignResult{Path: rel, Status: result.Status})
		if result.Status != 0 {
			return fmt.Errorf("codesign %s on %s: exit %d: %s", rel, vol.Name, result.Status, strings.TrimSpace(string(result.Stderr)))
		}
	}
	if in.Spec.Snapshots && v.APFS != nil {
		for _, s := range v.APFS.Snapshots {
			pin := filepath.Join(in.Work, "snapshot", sanitize(vol.Name), sanitize(s.Name))
			if err := in.Disk.MountSnapshot(ctx, s.Name, mount, pin); err != nil {
				return err
			}
			sv, err := observeView(ctx, in, index, s.Name, pin)
			uerr := in.Disk.UnmountPath(ctx, pin)
			if err != nil {
				return err
			}
			if uerr != nil {
				return uerr
			}
			obs.Views = append(obs.Views, *sv)
		}
	}
	return nil
}

func unlockVolume(ctx context.Context, in ObserveInput, vol *AttachedVolume, ref string, expectSuccess bool) error {
	password, ok := in.Vars.Passwords[ref]
	if !ok {
		return fmt.Errorf("unknown password reference %q", ref)
	}
	expected := "0"
	if !expectSuccess {
		expected = "record"
	}
	cmd := Command{Label: "unlock:" + ref, Argv: []string{"diskutil", "apfs", "unlockVolume", vol.Dev, "-stdinpassphrase", "-nomount"}, Stdin: []byte(password + "\n"), Expected: expected}
	result := in.Disk.(*HostDisk).C.Run(ctx, cmd)
	if err := in.T.Record(cmd, result); err != nil {
		return err
	}
	if !expectSuccess && result.Status == 0 {
		return fmt.Errorf("rejected credential %q unlocked %s", ref, vol.Name)
	}
	return nil
}

func observeView(ctx context.Context, in ObserveInput, volume int, snapshot, mount string) (*schema.View, error) {
	view := &schema.View{Volume: volume, Snapshot: snapshot, Entries: []schema.Entry{}}
	var walk func(dir, rel string) error
	walk = func(dir, rel string) error {
		names, err := in.Vol.Readdir(dir)
		if err != nil {
			return err
		}
		sort.Strings(names)
		for _, name := range names {
			if rel == "" && rootExclusions[name] {
				continue
			}
			childRel := name
			if rel != "" {
				childRel = rel + "/" + name
			}
			entry, err := observeEntry(in, filepath.Join(dir, name), childRel)
			if err != nil {
				return fmt.Errorf("%s: %w", childRel, err)
			}
			view.Entries = append(view.Entries, *entry)
			if entry.Kind == "dir" {
				if err := walk(filepath.Join(dir, name), childRel); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(mount, ""); err != nil {
		return nil, err
	}
	for _, lookup := range in.Spec.Lookups {
		probe := schema.Probe{Dir: lookup.Dir, Query: hex.EncodeToString([]byte(lookup.Query))}
		st, err := in.Vol.Lstat(filepath.Join(mount, filepath.FromSlash(lookup.Dir), lookup.Query))
		switch {
		case err == nil:
			probe.Result, probe.ID = "found", st.Ino
		case errors.Is(err, syscall.ENOENT):
			probe.Result = "ENOENT"
		default:
			return nil, fmt.Errorf("lookup %s/%s: %w", lookup.Dir, lookup.Query, err)
		}
		if (lookup.Expect == "found" && probe.Result != "found") || (lookup.Expect == "absent" && probe.Result == "found") {
			return nil, fmt.Errorf("lookup %s/%q expected %s, got %s", lookup.Dir, lookup.Query, lookup.Expect, probe.Result)
		}
		view.Lookups = append(view.Lookups, probe)
	}
	for _, dir := range in.Spec.Statistics {
		if view.Statistics == nil {
			view.Statistics = map[string]string{}
		}
		if _, err := in.Vol.Lstat(filepath.Join(mount, filepath.FromSlash(dir))); err != nil {
			view.Statistics[dir] = "absent"
			continue
		}
		cmd := Command{Label: "statistics:" + dir, Argv: []string{"apfs.util", "-S", filepath.Join(mount, filepath.FromSlash(dir))}, Expected: "0"}
		result := in.Disk.(*HostDisk).C.Run(ctx, cmd)
		if err := in.T.Record(cmd, result); err != nil {
			return nil, err
		}
		view.Statistics[dir] = string(result.Stdout)
	}
	if in.Spec.AppleDouble && snapshot == "" {
		exports, err := exportAppleDouble(ctx, in, mount)
		if err != nil {
			return nil, err
		}
		view.AppleDouble = exports
	}
	return view, nil
}

func observeEntry(in ObserveInput, full, rel string) (*schema.Entry, error) {
	st, err := in.Vol.Lstat(full)
	if err != nil {
		return nil, err
	}
	e := &schema.Entry{Path: rel, NameBytes: hex.EncodeToString([]byte(path.Base(rel))), Kind: st.Kind, ID: st.Ino, Mode: st.Mode, UID: st.UID, GID: st.GID, Flags: st.Flags,
		Times: schema.Times{Birth: st.Birth, Modify: st.Modify, Change: st.Change, Access: st.Access}}
	if st.Kind != "dir" {
		e.Links, e.Size, e.Allocated = st.Nlink, st.Size, st.Allocated
	}
	visible := map[string]bool{}
	if names, err := in.Vol.Listxattr(full, false); err == nil {
		for _, n := range names {
			visible[n] = true
		}
	}
	names, err := in.Vol.Listxattr(full, true)
	if err != nil {
		return nil, fmt.Errorf("listxattr: %w", err)
	}
	sort.Strings(names)
	var decmpfs []byte
	for _, name := range names {
		data, err := in.Vol.Getxattr(full, name, true)
		if err != nil {
			return nil, fmt.Errorf("getxattr %s: %w", name, err)
		}
		sum := sha256.Sum256(data)
		e.Xattrs = append(e.Xattrs, schema.Xattr{Name: name, Bytes: int64(len(data)), SHA256: hex.EncodeToString(sum[:]), Hidden: !visible[name]})
		if name == "com.apple.decmpfs" {
			decmpfs = data
		}
	}
	switch st.Kind {
	case "symlink":
		target, err := in.Vol.Readlink(full)
		if err != nil {
			return nil, err
		}
		e.Target = hex.EncodeToString(target)
	case "file":
		sum, _, readErr := in.Vol.Hash(full)
		if readErr == nil {
			e.SHA256 = sum
		}
		if st.Flags&0x20 != 0 {
			c := &schema.Compression{KernelRead: "ok"}
			if len(decmpfs) >= 16 {
				c.Type = binary.LittleEndian.Uint32(decmpfs[4:8])
			}
			c.Storage = "attribute"
			if resourceTypes[c.Type] {
				c.Storage = "resource"
			}
			if readErr != nil {
				var errno syscall.Errno
				if errors.As(readErr, &errno) {
					c.KernelRead = errnoName(errno)
				} else {
					c.KernelRead = readErr.Error()
				}
			}
			e.Compression = c
		} else if readErr != nil {
			return nil, fmt.Errorf("read: %w", readErr)
		}
		if holes, err := in.Vol.Holes(full); err == nil && len(holes) > 0 {
			e.Sparse = holes
		}
		for _, pattern := range in.Spec.Extents {
			if ok, _ := path.Match(pattern, rel); ok {
				ext := &schema.Extents{}
				runs, err := in.Vol.Extents(full, "data")
				if err != nil {
					return nil, fmt.Errorf("extents: %w", err)
				}
				ext.Data = runs
				if rsrc, err := in.Vol.Extents(full, "rsrc"); err == nil {
					ext.Resource = rsrc
				}
				e.Extents = ext
				samples := in.Spec.Samples
				for fork, forkRuns := range map[string][][3]int64{"data": ext.Data, "rsrc": ext.Resource} {
					forkPath := full
					if fork == "rsrc" {
						forkPath = filepath.Join(full, "..namedfork", "rsrc")
					}
					for i, run := range forkRuns {
						if i == 0 || (samples > 0 && len(e.Samples) >= samples*2) {
							continue
						}
						offset := run[0] - 17
						if offset < 0 {
							offset = 0
						}
						data, err := in.Vol.Pread(forkPath, offset, 34)
						if err != nil {
							return nil, fmt.Errorf("sample: %w", err)
						}
						sum := sha256.Sum256(data)
						e.Samples = append(e.Samples, schema.Sample{Fork: fork, Offset: offset, Length: len(data), SHA256: hex.EncodeToString(sum[:])})
					}
				}
				break
			}
		}
	}
	if acl, err := in.Vol.ACL(full); err == nil && len(acl) > 0 {
		e.ACL = hex.EncodeToString(acl)
	}
	return e, nil
}

// exportAppleDouble asks Apple's copyfile, through ditto's sequestered
// resource mode, to pack every entry's metadata, then retains the ._ files.
func exportAppleDouble(ctx context.Context, in ObserveInput, mount string) ([]schema.AppleDoubleExport, error) {
	src := filepath.Join(mount, "Fixture")
	if _, err := in.Vol.Lstat(src); err != nil {
		return nil, nil
	}
	work := filepath.Join(in.Work, "appledouble")
	if err := os.MkdirAll(work, 0o755); err != nil {
		return nil, err
	}
	archive := filepath.Join(work, "fixture.zip")
	_ = os.Remove(archive)
	c := in.Disk.(*HostDisk).C
	for _, argv := range [][]string{
		{"ditto", "-c", "-k", "--sequesterRsrc", "--keepParent", src, archive},
		{"unzip", "-q", "-o", archive, "-d", filepath.Join(work, "unpacked")},
	} {
		cmd := Command{Label: "appledouble", Argv: argv, Expected: "0"}
		if err := in.T.Record(cmd, c.Run(ctx, cmd)); err != nil {
			return nil, err
		}
	}
	outDir := filepath.Join(in.Out, in.Prefix+".appledouble")
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	var exports []schema.AppleDoubleExport
	root := filepath.Join(work, "unpacked", "__MACOSX")
	err := filepath.Walk(root, func(p string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasPrefix(info.Name(), "._") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		entryPath := filepath.ToSlash(filepath.Join(filepath.Dir(rel), strings.TrimPrefix(info.Name(), "._")))
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		name := fmt.Sprintf("%04d.bin", len(exports))
		if err := os.WriteFile(filepath.Join(outDir, name), data, 0o644); err != nil {
			return err
		}
		exports = append(exports, schema.AppleDoubleExport{Path: entryPath, File: filepath.ToSlash(filepath.Join(in.Prefix+".appledouble", name)), SHA256: hex.EncodeToString(sum[:])})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return exports, nil
}

func observeChecks(ctx context.Context, in ObserveInput, obs *schema.Observation) error {
	for _, check := range in.Spec.Checks {
		switch check {
		case "verify":
			if in.Format == "raw" || in.Format == "UDRW" {
				continue // no checksum to verify in a writable or raw image
			}
			if err := in.Disk.Verify(ctx, in.Image, in.Password); err != nil {
				return err
			}
			obs.Checks.Verify = lastCommandResult(in.T, "verify")
		case "fsck":
			for _, vol := range in.Att.Volumes {
				if vol.FS == "apfs" && obs.Volumes[0].APFS != nil && obs.Volumes[0].APFS.Encrypted {
					continue
				}
				rdev := vol.RDev
				if vol.FS == "apfs" {
					rdev = in.Att.RDev
				}
				out, err := in.Disk.Fsck(ctx, vol.FS, rdev)
				if err != nil {
					return err
				}
				if result := lastCommandResult(in.T, "fsck"); result != nil {
					obs.Checks.Fsck = append(obs.Checks.Fsck, *result)
				}
				if xid := SelectedXID(out); xid != 0 {
					obs.Checks.SelectedXID = xid
				}
				if vol.FS == "apfs" {
					break
				}
			}
		case "codesign":
		default:
			return fmt.Errorf("unknown check %q", check)
		}
	}
	return nil
}

func number(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int64:
		return float64(n)
	case int:
		return float64(n)
	}
	return 0
}

func sanitize(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r == '/' || r == 0 || r == ' ' {
			r = '_'
		}
		b.WriteRune(r)
	}
	if b.Len() == 0 {
		return "volume"
	}
	return b.String()
}

// lastCommandResult finds the most recent transcript entry with a label.
func lastCommandResult(t *Transcript, label string) *schema.CommandResult {
	for i := len(t.Commands) - 1; i >= 0; i-- {
		c := t.Commands[i]
		if c.Label == label {
			status := 0
			if c.Status != "0" {
				status = 1
			}
			return &schema.CommandResult{Argv: c.Argv, Status: status, StdoutSHA256: c.StdoutSHA256, StderrSHA256: c.StderrSHA256}
		}
	}
	return nil
}
