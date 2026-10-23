package native

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

type cleanupCauseDisk struct {
	fixture.Disk
	readErr, detachErr, fsckErr, unmountErr error
	device                                  string
	detaches                                int
	detachAt                                int
}

func (d *cleanupCauseDisk) Attach(_ context.Context, image string, _ fixture.AttachOptions) (*fixture.Attachment, error) {
	return &fixture.Attachment{Image: image, RDev: d.device, Volumes: []*fixture.AttachedVolume{{Name: "selected", FS: "apfs"}}}, nil
}
func (d *cleanupCauseDisk) Imageinfo(context.Context, string, []byte) (map[string]any, error) {
	return nil, nil
}
func (d *cleanupCauseDisk) Detach(context.Context, *fixture.Attachment) error {
	d.detaches++
	if d.detachAt == 0 || d.detaches == d.detachAt {
		return d.detachErr
	}
	return nil
}
func (d *cleanupCauseDisk) DeviceDigest(_ context.Context, _, out string) (string, int64, error) {
	if d.readErr != nil {
		return "", 0, d.readErr
	}
	file, err := os.Create(out)
	if err != nil {
		return "", 0, err
	}
	z := gzip.NewWriter(file)
	_, writeErr := z.Write(make([]byte, 512))
	return "", 512, errors.Join(writeErr, z.Close(), file.Close())
}
func (d *cleanupCauseDisk) Fsck(context.Context, string, string) (string, error) {
	return "", d.fsckErr
}
func (d *cleanupCauseDisk) Mount(_ context.Context, vol *fixture.AttachedVolume, _, mount string, _ bool) error {
	vol.Mount = mount
	return nil
}
func (d *cleanupCauseDisk) Unmount(context.Context, *fixture.AttachedVolume) error {
	return d.unmountErr
}

func TestNativeBlockReadPreservesGuardedCleanupOnSuccessAndFailure(t *testing.T) {
	for _, missing := range []bool{false, true} {
		t.Run(map[bool]string{false: "read-success", true: "read-failure"}[missing], func(t *testing.T) {
			device := filepath.Join(t.TempDir(), "ordinary-bytes")
			if !missing {
				if err := os.WriteFile(device, []byte("ordinary control bytes"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			cleanup := errors.New("device cleanup refused")
			disk := &cleanupCauseDisk{device: device, detachErr: cleanup}
			_, err := (&Verifier{Disk: disk}).blockDigests(context.Background(), "fake.raw", nil)
			if !errors.Is(err, cleanup) || missing && !errors.Is(err, os.ErrNotExist) || disk.detaches != 1 {
				t.Fatalf("block read lost a primary/cleanup cause: %v", err)
			}
		})
	}
}

func TestNativeReadAndCheckerFailuresPreserveCleanupCause(t *testing.T) {
	for _, phase := range []string{"container", "continuation", "checker", "final-copy"} {
		t.Run(phase, func(t *testing.T) {
			primary, cleanup := errors.New("native primary failed"), errors.New("native cleanup refused")
			disk := &cleanupCauseDisk{readErr: primary, fsckErr: primary, detachErr: cleanup}
			v := &Verifier{Disk: disk, Work: t.TempDir()}
			var err error
			switch phase {
			case "container":
				_, err = v.verifyContainer(context.Background(), schema.Output{}, "fake.raw", nil, nil, false)
			case "continuation":
				_, err = v.Continuation(context.Background(), Paired{Output: schema.Output{Name: "control"}, ByHost: map[string]schema.Output{}}, schemaCase{})
			case "checker":
				err = v.fsckRaw(context.Background(), "fake.raw", "apfs")
			case "final-copy":
				_, err = v.nativeWriteAfterEdit(context.Background(), schema.Output{}, "fake.raw", t.TempDir(), "selected", nil, schema.Recipe{}, continuationEnvelope{})
			}
			if !errors.Is(err, primary) || !errors.Is(err, cleanup) || disk.detaches != 1 {
				t.Fatalf("%s lost a primary/cleanup cause or repeated cleanup: %v", phase, err)
			}
		})
	}
}

type cleanupCauseVolume struct {
	fixture.Volume
	writeErr error
}

func (v cleanupCauseVolume) WriteFile(string, []byte, bool) error { return v.writeErr }

func TestFinalNativeWritePreservesWriteUnmountAndDetachCauses(t *testing.T) {
	write, unmount, detach := errors.New("write failed"), errors.New("unmount failed"), errors.New("detach refused")
	disk := &cleanupCauseDisk{detachErr: detach, detachAt: 2, unmountErr: unmount}
	v := &Verifier{Disk: disk, Vol: cleanupCauseVolume{writeErr: write}}
	_, err := v.nativeWriteAfterEdit(context.Background(), schema.Output{}, "fake.raw", t.TempDir(), "selected", nil, schema.Recipe{}, continuationEnvelope{})
	if !errors.Is(err, write) || !errors.Is(err, unmount) || !errors.Is(err, detach) || disk.detaches != 2 {
		t.Fatalf("final allocation lost an operation/cleanup cause: %v", err)
	}
}

func TestTrackedLimitJoinedWithCleanupFailureRetainsFailureEvidence(t *testing.T) {
	work := t.TempDir()
	disk := &continuationCommandDisk{}
	v := &Verifier{Disk: disk}
	finish := v.recordContinuationCommands(work)
	v.setTranscript(&fixture.Transcript{})
	disk.record("cleanup-refused", "1")
	cause := errors.New("cleanup did not release the image")
	err := errors.Join(KnownLimit{Refusal: "tracked input"}, cause)
	finish(&err)
	if !errors.Is(err, cause) {
		t.Fatal("cleanup cause was discarded", err)
	}
	data, readErr := os.ReadFile(filepath.Join(work, "continuation-commands.json"))
	if readErr != nil || !strings.Contains(string(data), "cleanup-refused") {
		t.Fatalf("a tracked limit masked actual failed-cleanup evidence: %v", readErr)
	}
}

func TestTrackedLimitPolicyRejectsJoinedCleanupAndCancellation(t *testing.T) {
	limit := KnownLimit{Refusal: "tracked input"}
	for _, result := range []error{limit, fmt.Errorf("continuation: %w", limit), errors.Join(limit, nil)} {
		if !onlyKnownLimit(result) {
			t.Fatal("a pure tracked refusal lost its existing policy", result)
		}
	}
	for _, result := range []error{nil, errors.New("cleanup failed"), errors.Join(limit, errors.New("cleanup failed")), errors.Join(limit, context.Canceled), fmt.Errorf("continuation: %w", errors.Join(limit, os.ErrNotExist))} {
		if onlyKnownLimit(result) {
			t.Fatal("a tracked refusal masked an independent failure", result)
		}
	}
}
