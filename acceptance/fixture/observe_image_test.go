package fixture

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

type digestObservationDisk struct {
	*fakeDisk
	digestCalls int
	digestErr   error
}

func (d *digestObservationDisk) DeviceDigest(ctx context.Context, rdev, out string) (string, int64, error) {
	d.digestCalls++
	if d.digestErr != nil {
		return "", 0, d.digestErr
	}
	return d.fakeDisk.DeviceDigest(ctx, rdev, out)
}

func TestTransientReadbackRetainsFileIntegrityInventoryAndNativeChecks(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	image := filepath.Join(root, "source.dmg")
	source := NewMemoryVolume("/source")
	if err := source.MkdirAll("/source/Fixture"); err != nil {
		t.Fatal(err)
	}
	if err := source.WriteFile("/source/Fixture/data", []byte("retained content"), false); err != nil {
		t.Fatal(err)
	}
	if err := source.Setxattr("/source/Fixture/data", "org.go-apfs.attribute", []byte("retained metadata"), ""); err != nil {
		t.Fatal(err)
	}
	tree := source.Snapshot("/source")
	if err := writeFakeImage(image, fakeImage{Volume: "Primary", Format: "UDZO", Tree: tree}); err != nil {
		t.Fatal(err)
	}
	fileDigest, err := schema.FileDigest(image)
	if err != nil {
		t.Fatal(err)
	}
	var observed []*schema.Observation
	for _, omit := range []bool{false, true} {
		vol := NewMemoryVolume("/")
		disk := &digestObservationDisk{fakeDisk: newFakeDisk(vol)}
		transcript := &Transcript{}
		disk.t = transcript
		att, err := disk.Attach(ctx, image, AttachOptions{ReadOnly: true})
		if err != nil {
			t.Fatal(err)
		}
		obs, err := Observe(ctx, ObserveInput{
			Recipe: &schema.Recipe{Name: "file-corpus"}, Profile: schema.Profile{ID: "apfs"}, Stage: "readback",
			Spec: schema.ObserveSpec{Checks: []string{"verify", "fsck"}}, Image: image, Format: "UDZO",
			Att: att, Disk: disk, Vol: vol, Vars: &Vars{}, T: transcript, Work: root,
			OmitDeviceDigest: omit,
		})
		if err != nil {
			t.Fatalf("omit device digest %v: %v", omit, err)
		}
		wantCalls, wantDigest := 1, strings.Repeat("ab", 32)
		if omit {
			wantCalls, wantDigest = 0, ""
		}
		if disk.digestCalls != wantCalls || obs.Image.DiskSHA256 != wantDigest {
			t.Fatalf("omit %v: device reads %d, SHA %q", omit, disk.digestCalls, obs.Image.DiskSHA256)
		}
		if obs.Image.SHA256 != fileDigest || obs.Image.DiskBytes != 64<<20 || obs.Image.PartitionMap != "GPT" || obs.Image.Partitions == nil || obs.Image.Imageinfo == nil {
			t.Fatalf("omit %v lost image integrity, size or inventory: %+v", omit, obs.Image)
		}
		if obs.Checks.Verify == nil || len(obs.Checks.Fsck) != 1 || obs.Checks.SelectedXID != 42 || len(obs.Views) != 1 || len(obs.Views[0].Entries) != 2 {
			t.Fatalf("omit %v lost a native verdict or mounted entries: %+v", omit, obs)
		}
		observed = append(observed, obs)
	}
	if !reflect.DeepEqual(observed[0].Volumes, observed[1].Volumes) || !reflect.DeepEqual(observed[0].Views, observed[1].Views) || !reflect.DeepEqual(observed[0].Checks, observed[1].Checks) {
		t.Fatal("omitting an unasserted device digest changed mounted metadata or native verdicts")
	}
	if after, err := schema.FileDigest(image); err != nil || after != fileDigest {
		t.Fatalf("observation changed the retained source: %s, %v", after, err)
	}
}

func TestCapturePropagatesDeviceReadFailuresAndTransientReadbackStillHashesTheImage(t *testing.T) {
	root := t.TempDir()
	image := filepath.Join(root, "source.dmg")
	if err := os.WriteFile(image, []byte("source image"), 0o644); err != nil {
		t.Fatal(err)
	}
	deviceErr := errors.New("device read failed")
	disk := &digestObservationDisk{fakeDisk: newFakeDisk(NewMemoryVolume("/")), digestErr: deviceErr}
	in := ObserveInput{Image: image, Format: "UDZO", Disk: disk, Att: &Attachment{Dev: "/dev/disk9", RDev: "/dev/rdisk9"}}
	if err := observeImage(context.Background(), in, &schema.Observation{}); !errors.Is(err, deviceErr) {
		t.Fatalf("capture swallowed raw-device failure: %v", err)
	}
	in.OmitDeviceDigest = true
	if err := observeImage(context.Background(), in, &schema.Observation{}); err != nil {
		t.Fatalf("transient readback attempted the unused raw-device read: %v", err)
	}
	in.Image = filepath.Join(root, "missing.dmg")
	if err := observeImage(context.Background(), in, &schema.Observation{}); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("transient readback omitted the retained-image integrity read: %v", err)
	}
}
