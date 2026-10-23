package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// No operation in this disk launches native tools or touches native devices.
type captureCleanupDisk struct {
	Disk
	createErr, detachErr, infoErr      error
	creates, detaches, infos, unmounts int
	targetMount                        string
	transcript                         *Transcript
}

func (d *captureCleanupDisk) SetTranscript(t *Transcript) { d.transcript = t }
func (d *captureCleanupDisk) record(label string, err error) {
	if d.transcript != nil {
		entry := schema.Command{Label: label, Status: "0"}
		if err != nil {
			entry.Status, entry.StderrText = "1", err.Error()
		}
		d.transcript.Commands = append(d.transcript.Commands, entry)
	}
}
func (d *captureCleanupDisk) CreateImage(context.Context, string, string, string, string, string, string) error {
	d.creates++
	d.record("format", d.createErr)
	return d.createErr
}
func (d *captureCleanupDisk) Attach(_ context.Context, image string, _ AttachOptions) (*Attachment, error) {
	return &Attachment{Image: image, Dev: "/dev/fake-target", Volumes: []*AttachedVolume{{Name: "target", Mount: d.targetMount}}}, nil
}
func (d *captureCleanupDisk) Detach(context.Context, *Attachment) error {
	d.detaches++
	d.record("cleanup", d.detachErr)
	return d.detachErr
}

func TestCaptureFailureReceiptIncludesEarlyFormatAndDeferredCleanup(t *testing.T) {
	primary, cleanup := errors.New("format failed"), errors.New("cleanup refused")
	disk := &captureCleanupDisk{createErr: primary, detachErr: cleanup}
	c := &Capture{Recipe: &schema.Recipe{Name: "capture-evidence", Image: schema.ImageSpec{Create: "hdiutil"}}, Profile: schema.Profile{ID: "apfs"}, Disk: disk, Work: t.TempDir(), Out: t.TempDir(), att: &Attachment{Image: "existing"}}
	err := c.Run(context.Background())
	if !errors.Is(err, primary) || !errors.Is(err, cleanup) {
		t.Fatal("operation/cleanup cause missing", err)
	}
	data, readErr := os.ReadFile(filepath.Join(c.Out, "apfs.format.failure.json"))
	if readErr != nil {
		t.Fatal("early capture failure has no receipt", readErr)
	}
	var report struct {
		Stage, Error string
		Commands     []schema.Command
	}
	if err := json.Unmarshal(data, &report); err != nil {
		t.Fatal(err)
	}
	if report.Stage != "format" || !strings.Contains(report.Error, primary.Error()) || !strings.Contains(report.Error, cleanup.Error()) || len(report.Commands) != 2 || report.Commands[0].Label != "format" || report.Commands[1].Label != "cleanup" || disk.detaches != 1 {
		t.Fatalf("failure receipt preceded or repeated cleanup: %+v", report)
	}
	files, readErr := filepath.Glob(filepath.Join(c.Out, "*.failure.json"))
	if readErr != nil || len(files) != 1 {
		t.Fatalf("capture produced duplicate failure reports: %v %v", files, readErr)
	}
}

func TestCaptureFailureReceiptWriteErrorPreservesThePrimaryCause(t *testing.T) {
	primary := errors.New("format failed")
	disk := &captureCleanupDisk{createErr: primary}
	c := &Capture{Recipe: &schema.Recipe{Image: schema.ImageSpec{Create: "hdiutil"}}, Profile: schema.Profile{ID: "apfs"}, Disk: disk, Work: t.TempDir(), Out: t.TempDir(), att: &Attachment{Image: "existing"}}
	receipt := filepath.Join(c.Out, "apfs.format.failure.json")
	if err := os.Mkdir(receipt, 0o700); err != nil {
		t.Fatal(err)
	}
	err := c.Run(context.Background())
	var retention *os.PathError
	if !errors.Is(err, primary) || !errors.As(err, &retention) || retention.Path != receipt || disk.detaches != 1 {
		t.Fatalf("failed evidence publication hid its cause or repeated cleanup: %v", err)
	}
}
func (d *captureCleanupDisk) Info(context.Context, string) (map[string]any, error) {
	d.infos++
	if d.infos == 2 {
		return nil, d.infoErr
	}
	return map[string]any{}, nil
}
func (d *captureCleanupDisk) Mount(_ context.Context, vol *AttachedVolume, _, mount string, _ bool) error {
	vol.Mount = mount
	return nil
}
func (d *captureCleanupDisk) Unmount(context.Context, *AttachedVolume) error {
	d.unmounts++
	return d.detachErr
}

func TestCaptureFailurePreservesDeferredCleanupCause(t *testing.T) {
	primary, cleanup := errors.New("format failed"), errors.New("owned cleanup refused")
	disk := &captureCleanupDisk{createErr: primary, detachErr: cleanup}
	c := &Capture{Recipe: &schema.Recipe{Image: schema.ImageSpec{Create: "hdiutil"}}, Disk: disk, Work: t.TempDir(), Out: t.TempDir(), att: &Attachment{Image: "existing"}}
	err := c.Run(context.Background())
	if !errors.Is(err, primary) || !errors.Is(err, cleanup) || disk.detaches != 1 {
		t.Fatalf("capture lost a primary/cleanup cause or repeated cleanup: %v", err)
	}
}

func TestVolumeObservationFailurePreservesUnmountCause(t *testing.T) {
	primary, cleanup := errors.New("volume inventory failed"), errors.New("volume unmount refused")
	disk := &captureCleanupDisk{infoErr: primary, detachErr: cleanup}
	err := observeVolume(context.Background(), ObserveInput{Disk: disk, Work: t.TempDir()}, &schema.Observation{}, 0, &AttachedVolume{Name: "volume"})
	if !errors.Is(err, primary) || !errors.Is(err, cleanup) || disk.unmounts != 1 {
		t.Fatalf("volume observation lost a primary/cleanup cause: %v", err)
	}
}

func TestJournalReplayFailurePreservesGuardedCleanupCause(t *testing.T) {
	primary, cleanup := errors.New("replay helper failed"), errors.New("replay image cleanup refused")
	disk := &captureCleanupDisk{detachErr: cleanup}
	commander := &fakeCommander{results: map[string]Result{"fake-replay-helper": {Status: -1, Err: primary}}}
	c := &Capture{Disk: disk, C: commander, Helpers: map[string]string{"hfs-journal-replay": "fake-replay-helper"}, t: &Transcript{}}
	_, err := c.replayJournal(context.Background(), "fake.raw", "replayed")
	if !errors.Is(err, primary) || !errors.Is(err, cleanup) || disk.detaches != 1 {
		t.Fatalf("journal replay lost a primary/cleanup cause: %v", err)
	}
}

func TestASRCleanupRefusalIsFatalWithoutForcedCommandsOrAnotherAttempt(t *testing.T) {
	for _, cleanup := range []error{nil, errors.New("foreign target is not released")} {
		t.Run(map[bool]string{true: "cleanup-refused", false: "prior-attempt-failure"}[cleanup != nil], func(t *testing.T) {
			disk := &captureCleanupDisk{detachErr: cleanup}
			commander := &fakeCommander{}
			c := &Capture{Disk: disk, C: commander, Work: t.TempDir(), t: &Transcript{}, att: &Attachment{Volumes: []*AttachedVolume{{Mount: "/Volumes/source"}}}}
			err := c.asrSnapshot(context.Background(), "snapshot")
			want := 3
			if cleanup != nil {
				want = 1
			}
			if err == nil || !strings.Contains(err.Error(), "asr target did not mount") || cleanup != nil && !errors.Is(err, cleanup) {
				t.Fatalf("ASR lost its original or guarded cleanup refusal: %v", err)
			}
			if disk.creates != want || disk.detaches != want || len(commander.calls) != 0 {
				t.Fatalf("cleanup was bypassed or retried: creates=%d detaches=%d commands=%v", disk.creates, disk.detaches, commander.calls)
			}
		})
	}
}

type asrCleanupLister struct {
	listErr, closeErr error
	closes            int
}

func (l *asrCleanupLister) List() ([]string, error) { return nil, l.listErr }
func (l *asrCleanupLister) Close() error            { l.closes++; return l.closeErr }

type asrCleanupVolume struct {
	Volume
	lister SnapshotLister
}

func (v asrCleanupVolume) SnapshotLister(string) (SnapshotLister, error) { return v.lister, nil }

func TestASRSourceAndTargetCleanupCausesAreRetainedWithoutAnotherAttempt(t *testing.T) {
	primary, sourceClose, targetClose := errors.New("snapshot listing failed"), errors.New("source descriptor close failed"), errors.New("target release refused")
	disk := &captureCleanupDisk{detachErr: targetClose, targetMount: "/Volumes/target"}
	lister := &asrCleanupLister{listErr: primary, closeErr: sourceClose}
	commander := &fakeCommander{}
	c := &Capture{Disk: disk, Vol: asrCleanupVolume{lister: lister}, C: commander, Work: t.TempDir(), t: &Transcript{}, att: &Attachment{Volumes: []*AttachedVolume{{Mount: "/Volumes/source"}}}}
	err := c.asrSnapshot(context.Background(), "snapshot")
	if !errors.Is(err, primary) || !errors.Is(err, sourceClose) || !errors.Is(err, targetClose) || disk.creates != 1 || disk.detaches != 1 || lister.closes != 1 || len(commander.calls) != 0 {
		t.Fatalf("ASR lost a failure or bypassed/retried its release: %v", err)
	}
}
