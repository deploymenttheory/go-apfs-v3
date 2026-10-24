package fixture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// Attachment is an attached disk image and the volumes macOS found in it.
type Attachment struct {
	Image     string
	Dev       string // /dev/diskN for the whole disk
	RDev      string
	Container string // APFS container reference (diskN) when present
	Volumes   []*AttachedVolume
	// partitioned retains hdiutil's whole-disk topology while diskutil's
	// partition inventory catches up. A partition scheme is never a bare volume.
	partitioned bool
}

// AttachedVolume is one filesystem on an attachment.
type AttachedVolume struct {
	Name   string
	Dev    string
	RDev   string
	Mount  string // mount point when mounted
	FS     string // apfs or hfs
	Locked bool
	UUID   string
	Role   string
}

// Volume finds an attached volume by name.
func (a *Attachment) Volume(name string) *AttachedVolume {
	for _, v := range a.Volumes {
		if v.Name == name {
			return v
		}
	}
	return nil
}

// AttachOptions select how hdiutil attaches an image.
type AttachOptions struct {
	ReadOnly bool
	Raw      bool // CRawDiskImage
	NoKernel bool
	Password []byte
	Shadow   string
	// Mount lets hdiutil mount the volumes where it chooses instead of
	// attaching with -nomount; asr wants its target mounted that way.
	Mount bool
	// NoInventory skips volume discovery for callers that read only the
	// raw device, which saves several diskutil calls per attach.
	NoInventory bool
}

// ConvertOptions distinguish bare disk sectors from a recognized image and
// select the output envelope. Raw is declared by the caller, never by a suffix.
type ConvertOptions struct {
	Raw        bool
	Encryption string
	Password   []byte
}

// Disk is the hdiutil/diskutil surface the interpreter and observer use.
// HostDisk implements it over a Commander; tests use a fake.
type Disk interface {
	CreateImage(ctx context.Context, path, size, layout, fs, fsargs, volname string) error
	CreateRaw(ctx context.Context, path string, bytes int64) error
	Attach(ctx context.Context, path string, opts AttachOptions) (*Attachment, error)
	Refresh(ctx context.Context, a *Attachment) error
	Detach(ctx context.Context, a *Attachment) error
	Mount(ctx context.Context, v *AttachedVolume, options, dir string, readOnly bool) error
	Unmount(ctx context.Context, v *AttachedVolume) error
	Convert(ctx context.Context, src, format, out string, opts ConvertOptions) error
	Chpass(ctx context.Context, image string, oldPassword, newPassword []byte) error
	// DeviceDigest hashes a raw device to its end (optionally writing a
	// gzip copy) and returns the digest and the bytes read. The size comes
	// from the device itself: diskutil can report a stale size for a
	// device number another image held moments earlier.
	DeviceDigest(ctx context.Context, rdev, out string) (string, int64, error)
	Info(ctx context.Context, dev string) (map[string]any, error)
	List(ctx context.Context, dev string) (map[string]any, error)
	// APFSList is diskutil apfs list -plist for every container, the only
	// listing that carries per-volume reserve and quota sizes.
	APFSList(ctx context.Context) (map[string]any, error)
	Imageinfo(ctx context.Context, image string, password []byte) (map[string]any, error)
	Snapshots(ctx context.Context, dev string) ([]map[string]any, error)
	MountSnapshot(ctx context.Context, name, mount, pin string) error
	UnmountPath(ctx context.Context, path string) error
	Verify(ctx context.Context, image string, password []byte) error
	Fsck(ctx context.Context, fs, rdev string) (string, error)
	ReadRange(ctx context.Context, rdev string, offset int64, length int) ([]byte, error)
}

// TranscriptUser is a Disk that records the programs it runs into the
// case transcript the interpreter hands it.
type TranscriptUser interface {
	SetTranscript(*Transcript)
}

// HostDisk drives the real tools.
type HostDisk struct {
	C Commander
	T *Transcript
	// Tests replace this per instance; private mount cleanup never needs a global
	// probe override or a real host mount to exercise ownership decisions.
	mountProbe func(string) (mountIdentity, error)
	// Resolves validated native image paths and caller host paths to complete
	// comparable identities. Nil uses the actual host filesystem; portable
	// tests inject explicit native-to-host or virtual identity mappings.
	imagePathResolver func(string) (string, error)
}

// SetTranscript records subsequent programs into t.
func (d *HostDisk) SetTranscript(t *Transcript) { d.T = t }

func (d *HostDisk) run(ctx context.Context, label string, sudo bool, stdin []byte, argv ...string) ([]byte, error) {
	cmd := Command{Label: label, Argv: argv, Sudo: sudo, Stdin: stdin, Expected: "0"}
	result := d.C.Run(ctx, cmd)
	if err := d.T.Record(cmd, result); err != nil {
		return result.Stdout, err
	}
	return result.Stdout, nil
}

// plist converts plist output to a Go map through plutil.
func (d *HostDisk) plist(ctx context.Context, data []byte) (map[string]any, error) {
	cmd := Command{Label: "plutil", Argv: []string{"plutil", "-convert", "json", "-o", "-", "-"}, Stdin: data, Expected: "0"}
	result := d.C.Run(ctx, cmd)
	if result.Err != nil {
		return nil, fmt.Errorf("plutil: %w", result.Err)
	}
	if result.Status != 0 {
		return nil, fmt.Errorf("plutil: %s", strings.TrimSpace(string(result.Stderr)))
	}
	var out map[string]any
	if err := json.Unmarshal(result.Stdout, &out); err != nil {
		return nil, fmt.Errorf("plutil json: %w", err)
	}
	return out, nil
}

func (d *HostDisk) CreateImage(ctx context.Context, path, size, layout, fs, fsargs, volname string) error {
	argv := []string{"hdiutil", "create", "-size", size, "-layout", layout, "-fs", fs}
	if fsargs != "" {
		argv = append(argv, "-fsargs", fsargs)
	}
	argv = append(argv, "-volname", volname, "-type", "UDIF", path)
	// hdiutil can report the disk-image framework busy for a moment after
	// the previous image detached; every attempt stays in the transcript.
	return Settle(ctx, d.T, "image-framework-busy", BusyWait, func() (bool, string, error) {
		_, err := d.run(ctx, "create-image", false, nil, argv...)
		switch {
		case err == nil:
			return true, "", nil
		case strings.Contains(err.Error(), "Resource busy"):
			_ = os.Remove(path) // a refused create leaves nothing worth keeping
			return false, err.Error(), nil
		default:
			return false, "", err
		}
	})
}

func (d *HostDisk) CreateRaw(_ context.Context, path string, bytes int64) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if err := f.Truncate(bytes); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func (d *HostDisk) Attach(ctx context.Context, path string, opts AttachOptions) (attachment *Attachment, resultErr error) {
	argv := []string{"hdiutil", "attach", "-plist", "-nobrowse", "-noautoopen", "-owners", "on"}
	if !opts.Mount {
		argv = append(argv, "-nomount")
	}
	if opts.Raw {
		argv = append(argv, "-imagekey", "diskimage-class=CRawDiskImage", "-noautofsck")
	}
	if opts.ReadOnly {
		argv = append(argv, "-readonly")
	}
	if opts.NoKernel {
		argv = append(argv, "-nokernel", "-noautofsck")
	}
	if opts.Shadow != "" {
		argv = append(argv, "-shadow", opts.Shadow)
	}
	var stdin []byte
	if opts.Password != nil {
		argv = append(argv, "-stdinpass")
		stdin = append(append([]byte(nil), opts.Password...), 0)
	}
	argv = append(argv, path)
	attempts := 0
	result, err := d.imageOperation(ctx, "attach-busy", func() (Command, bool, error) {
		if attempts > 0 {
			if err := d.confirmAttachRetry(ctx, path); err != nil {
				return Command{}, false, err
			}
		}
		attempts++
		return Command{Label: "attach", Argv: argv, Stdin: stdin}, false, nil
	})
	if err != nil {
		return nil, err
	}
	info, err := d.plist(ctx, result.Stdout)
	if err != nil {
		return nil, err
	}
	a := &Attachment{Image: path}
	entities, _ := info["system-entities"].([]any)
	var devEntries []diskEntity
	mountable := 0
	for _, e := range entities {
		entity, _ := e.(map[string]any)
		if dev, _ := entity["dev-entry"].(string); dev != "" {
			hint, _ := entity["content-hint"].(string)
			devEntries = append(devEntries, diskEntity{dev, hint})
		}
		if m, _ := entity["potentially-mountable"].(bool); m {
			mountable++
		}
	}
	whole, ok := wholeDisk(devEntries)
	if !ok {
		return nil, fmt.Errorf("attach %s: no whole-disk device among %v", path, devEntries)
	}
	a.Dev = whole
	a.RDev = strings.Replace(a.Dev, "/dev/disk", "/dev/rdisk", 1)
	// Once the native attachment identifies its whole device, do not lose
	// its handle if later discovery fails. Detach verifies exact current
	// ownership before any action; failure and cancellation remain fatal.
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, d.Detach(ctx, a))
		}
	}()
	for _, e := range devEntries {
		if e.dev == whole && isPartitionScheme(e.contentHint) {
			a.partitioned = true
		}
	}
	if opts.NoInventory {
		return a, nil
	}
	// hdiutil names the mountable volumes it attached; diskutil can lag
	// behind it, so discovery is repeated until it finds them all. Zero
	// volumes is the lag that matters (an observer would see an empty
	// image); a partial count gets a short grace period. A spent budget is
	// not an error here: callers that need a volume refuse an empty list.
	checks := 0
	err = Settle(ctx, d.T, "volume-discovery", ShortWait, func() (bool, string, error) {
		checks++
		if err := d.Refresh(ctx, a); err != nil {
			return false, "", err
		}
		if len(a.Volumes) >= mountable || (len(a.Volumes) > 0 && checks >= 3) {
			return true, "", nil
		}
		return false, fmt.Sprintf("%d of %d mountable volumes discovered", len(a.Volumes), mountable), nil
	})
	var notSettled *NotSettledError
	if err != nil && !errors.As(err, &notSettled) {
		return nil, err
	}
	if opts.Mount {
		for _, e := range entities {
			entity, _ := e.(map[string]any)
			dev, _ := entity["dev-entry"].(string)
			mount, _ := entity["mount-point"].(string)
			if vol := a.volumeByDev(dev); vol != nil && mount != "" {
				vol.Mount = mount
			}
		}
	}
	return a, nil
}

// diskEntity is one device hdiutil attach reported for an image.
type diskEntity struct{ dev, contentHint string }

// wholeDisk picks the image's own disk from hdiutil's device entries. An
// APFS image also lists the container macOS synthesizes from it, another
// whole disk; neither the entries' order nor their numbers identify the
// image's own (device numbers are reused lowest-free, so the container can
// take a lower number while other images detach). The image's disk is the
// one whose content is a partition scheme. Without a partition map there is
// one physical store, and a synthesized container passes its bytes through,
// so the lowest-numbered disk without a slice serves.
func wholeDisk(entries []diskEntity) (string, bool) {
	best, bestN := "", -1
	for _, e := range entries {
		digits, ok := strings.CutPrefix(e.dev, "/dev/disk")
		if !ok || digits == "" {
			continue
		}
		n, err := strconv.Atoi(digits)
		if err != nil {
			continue // a slice such as disk12s1
		}
		if isPartitionScheme(e.contentHint) {
			return e.dev, true
		}
		if bestN < 0 || n < bestN {
			best, bestN = e.dev, n
		}
	}
	return best, bestN >= 0
}

func isPartitionScheme(content string) bool {
	return strings.HasSuffix(content, "_partition_scheme")
}

func (a *Attachment) volumeByDev(dev string) *AttachedVolume {
	for _, v := range a.Volumes {
		if v.Dev == dev {
			return v
		}
	}
	return nil
}

// Refresh re-reads the volume inventory: APFS containers through
// diskutil apfs list, everything else through diskutil list.
func (d *HostDisk) Refresh(ctx context.Context, a *Attachment) error {
	out, err := d.run(ctx, "list", false, nil, "diskutil", "list", "-plist", a.Dev)
	if err != nil {
		return err
	}
	listing, err := d.plist(ctx, out)
	if err != nil {
		return err
	}
	existing := map[string]*AttachedVolume{}
	for _, v := range a.Volumes {
		existing[v.Dev] = v
	}
	a.Volumes = nil
	a.Container = ""
	var devs []string
	disks, _ := listing["AllDisksAndPartitions"].([]any)
	// Every candidate device is classified through diskutil info: a
	// synthesized APFS container reference means the device is a container
	// or its physical store; a filesystem type means a mountable volume;
	// neither means an unformatted or free region.
	classify := func(id string, bare bool, contentHint string) error {
		info, err := d.Info(ctx, "/dev/"+id)
		if err != nil {
			return err
		}
		if ref, _ := info["APFSContainerReference"].(string); ref != "" {
			if content, _ := info["Content"].(string); content == "Apple_APFS" || strings.HasPrefix(ref, "disk") && a.Container == "" {
				a.Container = ref
			}
			return nil
		}
		content, _ := info["Content"].(string)
		if isPartitionScheme(content) || isPartitionScheme(contentHint) || (bare && "/dev/"+id == a.Dev && a.partitioned) {
			// A temporarily missing partition list is not evidence of a bare
			// filesystem. Keep it absent so Attach's existing discovery wait
			// can observe the actual slices; never mount the scheme itself.
			return nil
		}
		if fsType, _ := info["FilesystemType"].(string); fsType != "" && fsType != "apfs" {
			devs = append(devs, "/dev/"+id)
			return nil
		}
		if bare {
			// A bare disk that is not a container is the volume, formatted
			// or not; diskutil reports no filesystem type until it mounts.
			devs = append(devs, "/dev/"+id)
		}
		return nil
	}
	for _, dsk := range disks {
		disk, _ := dsk.(map[string]any)
		id, _ := disk["DeviceIdentifier"].(string)
		hint, _ := disk["Content"].(string)
		parts, _ := disk["Partitions"].([]any)
		if len(parts) == 0 {
			if err := classify(id, true, hint); err != nil {
				return err
			}
			continue
		}
		for _, p := range parts {
			part, _ := p.(map[string]any)
			id, _ := part["DeviceIdentifier"].(string)
			hint, _ := part["Content"].(string)
			if err := classify(id, false, hint); err != nil {
				return err
			}
		}
	}
	if a.Container != "" {
		out, err := d.run(ctx, "apfs-list", false, nil, "diskutil", "apfs", "list", "-plist", a.Container)
		if err != nil {
			return err
		}
		apfs, err := d.plist(ctx, out)
		if err != nil {
			return err
		}
		containers, _ := apfs["Containers"].([]any)
		for _, c := range containers {
			container, _ := c.(map[string]any)
			vols, _ := container["Volumes"].([]any)
			for _, vv := range vols {
				vol, _ := vv.(map[string]any)
				id, _ := vol["DeviceIdentifier"].(string)
				devs = append(devs, "/dev/"+id)
			}
		}
	}
	for _, dev := range devs {
		v := existing[dev]
		if v == nil {
			v = &AttachedVolume{Dev: dev, RDev: strings.Replace(dev, "/dev/disk", "/dev/rdisk", 1)}
		}
		info, err := d.Info(ctx, dev)
		if err != nil {
			return err
		}
		v.Name, _ = info["VolumeName"].(string)
		v.UUID, _ = info["VolumeUUID"].(string)
		v.Mount, _ = info["MountPoint"].(string)
		v.Locked, _ = info["Locked"].(bool)
		if fsType, _ := info["FilesystemType"].(string); fsType == "apfs" {
			v.FS = "apfs"
			if roles, _ := info["APFSVolumeRoles"].([]any); len(roles) > 0 {
				v.Role, _ = roles[0].(string)
			}
		} else {
			v.FS = "hfs"
		}
		a.Volumes = append(a.Volumes, v)
	}
	// No volume is legitimate right after attaching an unformatted raw
	// disk; callers that need one check for it.
	return nil
}

// Mount mounts a volume at dir, or where diskutil chooses when dir is
// empty; v.Mount is set to the actual mount point either way.
func (d *HostDisk) Mount(ctx context.Context, v *AttachedVolume, options, dir string, readOnly bool) error {
	argv := []string{"diskutil", "mount"}
	if readOnly {
		argv = append(argv, "readOnly")
	}
	if options != "" {
		argv = append(argv, "-mountOptions", options)
	}
	if dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
		argv = append(argv, "-mountPoint", dir)
	}
	argv = append(argv, v.Dev)
	if _, err := d.run(ctx, "mount", false, nil, argv...); err != nil {
		return err
	}
	// The kernel, not diskutil, says where the volume is: diskutil info can
	// report the mount point of the device number's previous occupant, an
	// empty directory, while DiskArbitration catches up.
	err := Settle(ctx, d.T, "mount-confirmation", ShortWait, func() (bool, string, error) {
		point := dir
		if point == "" {
			info, err := d.Info(ctx, v.Dev)
			if err != nil {
				return false, "", err
			}
			point, _ = info["MountPoint"].(string)
			if point == "" {
				return false, "diskutil reports no mount point yet", nil
			}
		}
		from, err := mountedFrom(point)
		if err == nil && from == v.Dev {
			v.Mount = point
			return true, "", nil
		}
		return false, fmt.Sprintf("%s is mounted from %q (%v)", point, from, err), nil
	})
	if err != nil {
		return fmt.Errorf("mount %s: %w", v.Dev, err)
	}
	return nil
}

func (d *HostDisk) Convert(ctx context.Context, src, format, out string, opts ConvertOptions) error {
	argv := []string{"hdiutil", "convert", src, "-format", format}
	if opts.Raw {
		argv = append(argv, "-srcimagekey", "diskimage-class=CRawDiskImage")
	}
	var stdin []byte
	if opts.Encryption != "" {
		argv = append(argv, "-encryption", opts.Encryption, "-stdinpass")
		stdin = append(append([]byte(nil), opts.Password...), 0)
	}
	argv = append(argv, "-o", out)
	_, err := d.run(ctx, "convert", false, stdin, argv...)
	return err
}

func (d *HostDisk) Chpass(ctx context.Context, image string, oldPassword, newPassword []byte) error {
	stdin := append(append(append(append([]byte(nil), oldPassword...), 0), newPassword...), 0)
	_, err := d.run(ctx, "chpass", false, stdin, "hdiutil", "chpass", image, "-oldstdinpass", "-newstdinpass")
	return err
}

// DeviceDigest hashes bytes of the raw device and, when out is not empty,
// streams them gzip-compressed to out.
func (d *HostDisk) DeviceDigest(_ context.Context, rdev, out string) (string, int64, error) {
	f, err := os.Open(rdev)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = f.Close() }()
	sink := io.Writer(io.Discard)
	var closer func() error
	if out != "" {
		w, err := newGzipFile(out)
		if err != nil {
			return "", 0, err
		}
		sink, closer = w, w.Close
	}
	digest := sha256.New()
	n, err := io.CopyBuffer(io.MultiWriter(digest, sink), f, make([]byte, 1<<20))
	if err != nil {
		if closer != nil {
			_ = closer()
		}
		return "", n, fmt.Errorf("read %s: %w", rdev, err)
	}
	if closer != nil {
		if err := closer(); err != nil {
			return "", n, err
		}
	}
	return hex.EncodeToString(digest.Sum(nil)), n, nil
}

func (d *HostDisk) Info(ctx context.Context, dev string) (map[string]any, error) {
	out, err := d.run(ctx, "info", false, nil, "diskutil", "info", "-plist", dev)
	if err != nil {
		return nil, err
	}
	return d.plist(ctx, out)
}

func (d *HostDisk) List(ctx context.Context, dev string) (map[string]any, error) {
	out, err := d.run(ctx, "list", false, nil, "diskutil", "list", "-plist", dev)
	if err != nil {
		return nil, err
	}
	return d.plist(ctx, out)
}

func (d *HostDisk) APFSList(ctx context.Context) (map[string]any, error) {
	out, err := d.run(ctx, "apfs-list", false, nil, "diskutil", "apfs", "list", "-plist")
	if err != nil {
		return nil, err
	}
	return d.plist(ctx, out)
}

func (d *HostDisk) Imageinfo(ctx context.Context, image string, password []byte) (map[string]any, error) {
	argv := []string{"hdiutil", "imageinfo", "-plist"}
	var stdin []byte
	if password != nil {
		argv = append(argv, "-stdinpass")
		stdin = append(append([]byte(nil), password...), 0)
	}
	out, err := d.run(ctx, "imageinfo", false, stdin, append(argv, image)...)
	if err != nil {
		return nil, err
	}
	return d.plist(ctx, out)
}

func (d *HostDisk) Snapshots(ctx context.Context, dev string) ([]map[string]any, error) {
	// Read the complete native inventory independently of the volume owner.
	// This is one privileged read; any native failure remains fatal.
	out, err := d.run(ctx, "list-snapshots", true, nil, "diskutil", "apfs", "listSnapshots", "-plist", dev)
	if err != nil {
		return nil, err
	}
	info, err := d.plist(ctx, out)
	if err != nil {
		return nil, err
	}
	raw, _ := info["Snapshots"].([]any)
	var snaps []map[string]any
	for _, s := range raw {
		if m, ok := s.(map[string]any); ok {
			snaps = append(snaps, m)
		}
	}
	return snaps, nil
}

func (d *HostDisk) MountSnapshot(ctx context.Context, name, mount, pin string) error {
	if err := os.MkdirAll(pin, 0o755); err != nil {
		return err
	}
	_, err := d.run(ctx, "mount-snapshot", false, nil, "/System/Library/Filesystems/apfs.fs/Contents/Resources/mount_apfs", "-o", "rdonly,owners,nobrowse,noatime", "-s", name, mount, pin)
	return err
}

func (d *HostDisk) UnmountPath(ctx context.Context, path string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	// Keep the actual argv bound to this canonical pin even if an input alias
	// is retargeted while the normal unmount settles.
	pin, err := canonicalMountPath(path)
	if err != nil {
		return d.T.RecordFS("snapshot-mount-path", []string{"canonicalize", path}, err, "0")
	}
	identity, _, err := d.snapshotMountIdentity(ctx, pin, nil)
	if err != nil {
		return err
	}
	var previousBusy error
	// Only an actual busy unmount result permits bounded cleanup settling.
	// Keep every failed command and wait; never retry a checker or observation.
	return Settle(ctx, d.T, "snapshot-unmount-busy", BusyWait, func() (bool, string, error) {
		if err := ctx.Err(); err != nil {
			return false, "", errors.Join(previousBusy, err)
		}
		if previousBusy != nil {
			_, gone, err := d.snapshotMountIdentity(ctx, pin, &identity)
			if err != nil {
				return false, "", errors.Join(previousBusy, err)
			}
			if gone {
				return true, "", nil
			}
		}
		if err := ctx.Err(); err != nil {
			return false, "", errors.Join(previousBusy, err)
		}
		cmd := Command{Label: "umount", Argv: []string{"/sbin/umount", pin}, Expected: "0"}
		result := d.C.Run(ctx, cmd)
		err := d.T.Record(cmd, result)
		if ctx.Err() != nil {
			return false, "", errors.Join(err, ctx.Err())
		}
		switch {
		case result.Err != nil:
			return false, "", err
		case err == nil:
			return true, "", nil
		case result.Status == 1 && strings.Contains(string(result.Stderr), "Resource busy"):
			previousBusy = err
			return false, err.Error(), nil
		default:
			return false, "", err
		}
	})
}

func (d *HostDisk) Verify(ctx context.Context, image string, password []byte) error {
	argv := []string{"hdiutil", "verify"}
	var stdin []byte
	if password != nil {
		argv = append(argv, "-stdinpass")
		stdin = append(append([]byte(nil), password...), 0)
	}
	_, err := d.run(ctx, "verify", false, stdin, append(argv, image)...)
	return err
}

var checkpointPattern = regexp.MustCompile(`Checking the checkpoint with transaction ID (\d+)`)

// Fsck runs the filesystem checker without repair and returns its output.
func (d *HostDisk) Fsck(ctx context.Context, fs, rdev string) (string, error) {
	var out []byte
	var err error
	switch fs {
	case "apfs":
		out, err = d.run(ctx, "fsck", false, nil, "/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs", "-n", rdev)
	default:
		out, err = d.run(ctx, "fsck", true, nil, "/sbin/fsck_hfs", "-fn", rdev)
	}
	return string(out), err
}

// SelectedXID extracts fsck_apfs's chosen checkpoint from its output.
func SelectedXID(fsckOutput string) uint64 {
	m := checkpointPattern.FindStringSubmatch(fsckOutput)
	if len(m) != 2 {
		return 0
	}
	n, _ := strconv.ParseUint(m[1], 10, 64)
	return n
}

func (d *HostDisk) ReadRange(_ context.Context, rdev string, offset int64, length int) ([]byte, error) {
	f, err := os.Open(rdev)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, length)
	n, err := f.ReadAt(buf, offset)
	if err != nil && err != io.EOF {
		return nil, err
	}
	return buf[:n], nil
}
