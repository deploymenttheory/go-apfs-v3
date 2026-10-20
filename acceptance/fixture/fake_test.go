package fixture

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// fakeImage is what a fake image file holds: the serialised volume tree.
type fakeImage struct {
	Volume string         `json:"volume"`
	Format string         `json:"format"`
	Tree   []snapshotNode `json:"tree"`
}

func readFakeImage(path string) (fakeImage, error) {
	var img fakeImage
	data, err := os.ReadFile(path)
	if err != nil {
		return img, err
	}
	return img, json.Unmarshal(data, &img)
}

func writeFakeImage(path string, img fakeImage) error {
	data, _ := json.Marshal(img)
	return os.WriteFile(path, data, 0o644)
}

// fakeCommander answers every program with a canned result and records
// what was asked.
type fakeCommander struct {
	calls    [][]string
	results  map[string]Result   // keyed by program name; default success
	sequence map[string][]Result // consumed in order before results
	fail     map[string]bool
}

func (f *fakeCommander) Run(_ context.Context, cmd Command) Result {
	f.calls = append(f.calls, cmd.Argv)
	if queue := f.sequence[cmd.Argv[0]]; len(queue) > 0 {
		f.sequence[cmd.Argv[0]] = queue[1:]
		return queue[0]
	}
	if r, ok := f.results[cmd.Argv[0]]; ok {
		return r
	}
	if f.fail[cmd.Argv[0]] {
		return Result{Status: 1, Stderr: []byte("failed")}
	}
	return Result{Status: 0}
}

// fakeDisk simulates attachments over a MemoryVolume: the "image" is a
// file on the host, the volume is the memory tree rooted at the mount dir.
type fakeDisk struct {
	t        *Transcript
	vol      *MemoryVolume
	attached map[string]*Attachment
	calls    []string
	pending  map[string][]snapshotNode // attachment dev -> tree awaiting mount or detach
	locked   bool
}

func newFakeDisk(vol *MemoryVolume) *fakeDisk {
	return &fakeDisk{vol: vol, attached: map[string]*Attachment{}, pending: map[string][]snapshotNode{}}
}

func (d *fakeDisk) note(format string, args ...any) {
	d.calls = append(d.calls, fmt.Sprintf(format, args...))
}

func (d *fakeDisk) CreateImage(_ context.Context, path, size, layout, fs, fsargs, volname string) error {
	d.note("create %s %s %s %s", filepath.Base(path), size, layout, fs)
	return writeFakeImage(path, fakeImage{Volume: volname})
}

func (d *fakeDisk) CreateRaw(_ context.Context, path string, bytes int64) error {
	d.note("raw %s %d", filepath.Base(path), bytes)
	return writeFakeImage(path, fakeImage{Volume: "raw"})
}

func (d *fakeDisk) Attach(_ context.Context, path string, opts AttachOptions) (*Attachment, error) {
	d.note("attach %s ro=%v", filepath.Base(path), opts.ReadOnly)
	img, err := readFakeImage(path)
	if err != nil {
		return nil, err
	}
	a := &Attachment{Image: path, Dev: "/dev/disk9", RDev: "/dev/rdisk9", Volumes: []*AttachedVolume{{Name: "Primary", Dev: "/dev/disk9s1", RDev: "/dev/rdisk9s1", FS: "apfs", Locked: d.locked}}}
	d.attached[a.Dev] = a
	d.pending[a.Dev] = img.Tree
	return a, nil
}

func (d *fakeDisk) Refresh(_ context.Context, a *Attachment) error { return nil }

func (d *fakeDisk) Detach(_ context.Context, a *Attachment) error {
	d.note("detach %s", filepath.Base(a.Image))
	for _, v := range a.Volumes {
		if v.Mount != "" {
			d.pending[a.Dev] = d.vol.Snapshot(v.Mount)
			v.Mount = ""
		}
	}
	img, err := readFakeImage(a.Image)
	if err != nil {
		return err
	}
	img.Tree = d.pending[a.Dev]
	delete(d.attached, a.Dev)
	delete(d.pending, a.Dev)
	return writeFakeImage(a.Image, img)
}

func (d *fakeDisk) Mount(_ context.Context, v *AttachedVolume, options, dir string, readOnly bool) error {
	d.note("mount %s %s ro=%v", v.Name, options, readOnly)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	// Every mount of the volume exposes the same memory tree under a new
	// host path; alias it by renaming the tree root.
	_ = d.vol.MkdirAll(dir)
	for dev, a := range d.attached {
		for _, av := range a.Volumes {
			if av == v {
				d.vol.Restore(dir, d.pending[dev])
			}
		}
	}
	v.Mount = dir
	return nil
}

func (d *fakeDisk) Unmount(_ context.Context, v *AttachedVolume) error {
	d.note("unmount %s", v.Name)
	for dev, a := range d.attached {
		for _, av := range a.Volumes {
			if av == v && v.Mount != "" {
				d.pending[dev] = d.vol.Snapshot(v.Mount)
			}
		}
	}
	v.Mount = ""
	return nil
}

func (d *fakeDisk) Convert(_ context.Context, src, format, out, encryption string, password []byte) error {
	d.note("convert %s %s enc=%s", filepath.Base(src), format, encryption)
	img, err := readFakeImage(src)
	if err != nil {
		return err
	}
	img.Format = format
	return writeFakeImage(out, img)
}

func (d *fakeDisk) Chpass(context.Context, string, []byte, []byte) error { return nil }

func (d *fakeDisk) DeviceDigest(_ context.Context, rdev, out string) (string, int64, error) {
	if out != "" {
		if err := os.WriteFile(out, []byte("device"), 0o644); err != nil {
			return "", 0, err
		}
	}
	return strings.Repeat("ab", 32), 64 << 20, nil
}

func (d *fakeDisk) Info(_ context.Context, dev string) (map[string]any, error) {
	return map[string]any{"TotalSize": float64(64 << 20), "FilesystemType": "apfs", "FilesystemName": "APFS", "VolumeName": "Primary", "VolumeUUID": "UUID-1", "Locked": d.locked, "Content": "GUID_partition_scheme"}, nil
}

func (d *fakeDisk) List(context.Context, string) (map[string]any, error) {
	return map[string]any{"AllDisksAndPartitions": []any{}}, nil
}

func (d *fakeDisk) APFSList(context.Context) (map[string]any, error) {
	return map[string]any{"Containers": []any{map[string]any{"Volumes": []any{map[string]any{"APFSVolumeUUID": "uuid-1", "CapacityReserve": float64(33554432), "CapacityQuota": float64(67108864)}}}}}, nil
}

func (d *fakeDisk) Imageinfo(context.Context, string, []byte) (map[string]any, error) {
	return map[string]any{"Format": "UDZO"}, nil
}

func (d *fakeDisk) Snapshots(context.Context, string) ([]map[string]any, error) { return nil, nil }
func (d *fakeDisk) MountSnapshot(context.Context, string, string, string) error { return nil }
func (d *fakeDisk) UnmountPath(context.Context, string) error                   { return nil }
func (d *fakeDisk) Verify(_ context.Context, image string, _ []byte) error {
	d.note("verify %s", filepath.Base(image))
	d.record("verify", "hdiutil", "verify", image)
	return nil
}
func (d *fakeDisk) Fsck(_ context.Context, fs, rdev string) (string, error) {
	d.note("fsck %s %s", fs, rdev)
	d.record("fsck", "fsck_"+fs, "-n", rdev)
	return "Checking the checkpoint with transaction ID 42\n", nil
}
func (d *fakeDisk) ReadRange(context.Context, string, int64, int) ([]byte, error) {
	return make([]byte, 512), nil
}

func (d *fakeDisk) SetTranscript(t *Transcript) { d.t = t }

func (d *fakeDisk) record(label string, argv ...string) {
	if d.t != nil {
		d.t.Commands = append(d.t.Commands, schema.Command{Label: label, Argv: argv, Expected: "0", Status: "0"})
	}
}
