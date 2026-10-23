package native

import (
	"compress/gzip"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

type fixtureImageDisk struct {
	fixture.Disk
	image, device        string
	attachErr, detachErr error
	detaches             int
}

func (d *fixtureImageDisk) Attach(_ context.Context, image string, _ fixture.AttachOptions) (*fixture.Attachment, error) {
	d.image = image
	if _, err := os.Stat(image); err != nil {
		return nil, err
	}
	if d.attachErr != nil {
		return nil, d.attachErr
	}
	return &fixture.Attachment{Image: image, RDev: d.device}, nil
}

func (d *fixtureImageDisk) Detach(context.Context, *fixture.Attachment) error {
	d.detaches++
	if _, err := os.Stat(d.image); err != nil {
		return err
	}
	return d.detachErr
}

// These are ordinary compressed control bytes, never a filesystem or disk.
func leasedNativeFixture(t *testing.T) (*corpus.Corpus, corpus.Case) {
	t.Helper()
	dir := t.TempDir()
	file, err := os.Create(filepath.Join(dir, "ordinary.raw.gz"))
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(file)
	_, err = z.Write([]byte("ordinary fixture lifetime control"))
	if err = errors.Join(err, z.Close(), file.Close()); err != nil {
		t.Fatal(err)
	}
	digest, err := schema.FileDigest(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	return &corpus.Corpus{ExpandDir: t.TempDir()}, corpus.Case{Dir: dir, Observation: &schema.Observation{Image: schema.Image{File: filepath.Base(file.Name()), SHA256: digest, Format: "raw"}}}
}

func TestFixtureObservationReleasesClosedBackingDespiteAnObservationFailure(t *testing.T) {
	c, k := leasedNativeFixture(t)
	disk := &fixtureImageDisk{}
	v := &Verifier{Corpus: c, Disk: disk, Work: t.TempDir()}
	_, err := v.observeFixture(context.Background(), k, "ordinary-control", nil, schema.ObserveSpec{}, schema.Recipe{})
	if err == nil || disk.detaches != 1 {
		t.Fatalf("missing-volume failure or its cleanup was lost: %v", err)
	}
	if _, err := os.Stat(disk.image); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("closed source backing was retained: %v", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestFixtureObservationPinsItsOriginalPathWhenAttachmentCleanupIsUncertain(t *testing.T) {
	for _, phase := range []string{"attach", "detach"} {
		t.Run(phase, func(t *testing.T) {
			c, k := leasedNativeFixture(t)
			failure := errors.New("native cleanup is uncertain")
			disk := &fixtureImageDisk{}
			if phase == "attach" {
				disk.attachErr = failure
			} else {
				disk.detachErr = failure
			}
			v := &Verifier{Corpus: c, Disk: disk, Work: t.TempDir()}
			_, err := v.observeFixture(context.Background(), k, "ordinary-control", nil, schema.ObserveSpec{}, schema.Recipe{})
			if !errors.Is(err, failure) {
				t.Fatalf("lost uncertain cleanup cause: %v", err)
			}
			if _, err := os.Stat(disk.image); err != nil {
				t.Fatalf("uncertain backing path was deleted or moved: %v", err)
			}
			if err := c.Close(); !errors.Is(err, failure) {
				t.Fatalf("run close falsely released an uncertain image: %v", err)
			}
			if _, err := os.Stat(disk.image); err != nil {
				t.Fatal("run close deleted an uncertain backing", err)
			}
		})
	}
}

func TestFixtureBlockReadReleasesOnlyAfterGuardedDeviceCleanup(t *testing.T) {
	for _, phase := range []string{"success", "read failure", "detach failure"} {
		t.Run(phase, func(t *testing.T) {
			c, k := leasedNativeFixture(t)
			device := filepath.Join(t.TempDir(), "ordinary-device-bytes")
			if phase != "read failure" {
				if err := os.WriteFile(device, []byte("ordinary bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			disk := &fixtureImageDisk{device: device}
			if phase == "detach failure" {
				disk.detachErr = errors.New("detach refused")
			}
			_, err := (&Verifier{Corpus: c, Disk: disk}).fixtureBlockDigests(context.Background(), k, nil)
			if (err != nil) != (phase != "success") || disk.detaches != 1 {
				t.Fatalf("unexpected read/cleanup outcome: %v", err)
			}
			_, statErr := os.Stat(disk.image)
			if phase == "detach failure" {
				if !errors.Is(err, disk.detachErr) || statErr != nil || !errors.Is(c.Close(), disk.detachErr) {
					t.Fatalf("failed cleanup did not retain its backing and cause: %v %v", err, statErr)
				}
			} else {
				if !errors.Is(statErr, os.ErrNotExist) {
					t.Fatalf("completed cleanup retained its backing: %v", statErr)
				}
				if err := c.Close(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
