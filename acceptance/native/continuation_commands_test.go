package native

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

type continuationCommandDisk struct {
	fixture.Disk
	t         *fixture.Transcript
	detaches  int
	detachErr error
}

func (d *continuationCommandDisk) SetTranscript(t *fixture.Transcript) { d.t = t }

func (d *continuationCommandDisk) record(label, status string) {
	d.t.Commands = append(d.t.Commands, schema.Command{Label: label, Status: status})
}

func (d *continuationCommandDisk) Attach(_ context.Context, image string, _ fixture.AttachOptions) (*fixture.Attachment, error) {
	d.record("attach", "0")
	return &fixture.Attachment{Image: image, Volumes: []*fixture.AttachedVolume{{Name: "selected"}}}, nil
}

func (d *continuationCommandDisk) DeviceDigest(_ context.Context, _, out string) (string, int64, error) {
	d.record("device-digest", "0")
	f, err := os.Create(out)
	if err != nil {
		return "", 0, err
	}
	z := gzip.NewWriter(f)
	_, writeErr := z.Write(make([]byte, 512))
	err = errors.Join(writeErr, z.Close(), f.Close())
	return "", 512, err
}

func (d *continuationCommandDisk) Detach(context.Context, *fixture.Attachment) error {
	d.detaches++
	if d.detaches == 2 {
		d.record("hdiutil-info", "0")
		d.record("detach", "16")
		return d.detachErr
	}
	d.record("detach", "0")
	return nil
}

func (d *continuationCommandDisk) Mount(_ context.Context, v *fixture.AttachedVolume, _, dir string, _ bool) error {
	d.record("mount", "0")
	v.Mount = dir
	return nil
}

func (d *continuationCommandDisk) Unmount(context.Context, *fixture.AttachedVolume) error {
	d.record("unmount", "0")
	return nil
}

type continuationCommandVolume struct{ fixture.Volume }

func (continuationCommandVolume) WriteFile(string, []byte, bool) error { return nil }
func (continuationCommandVolume) Fullfsync(string) error               { return nil }

func TestContinuationFailureRetainsFinalCloseAfterObservationTranscriptReplacement(t *testing.T) {
	work := t.TempDir()
	cause := errors.New("final detach remains busy")
	disk := &continuationCommandDisk{detachErr: cause}
	v := &Verifier{Disk: disk, Vol: continuationCommandVolume{}}
	finish := v.recordContinuationCommands(work)
	initial := &fixture.Transcript{}
	v.setTranscript(initial)
	disk.record("initial-native-check", "0")
	observed := &fixture.Transcript{}
	v.setTranscript(observed)
	disk.record("observed-native-state", "0")
	// observeImage serializes this transcript before the final allocation.
	snapshot, err := json.Marshal(observed.Commands)
	if err != nil {
		t.Fatal(err)
	}
	_, err = v.nativeWriteAfterEdit(context.Background(), schema.Output{}, "edited.dmg", work, "selected", nil, schema.Recipe{}, continuationEnvelope{})
	if !errors.Is(err, cause) {
		t.Fatalf("final native close failure changed: %v", err)
	}
	finish(&err)
	if !errors.Is(err, cause) || v.Disk != disk || v.continuationLog != nil {
		t.Fatalf("recorder changed the failure, disk or recording scope: %v", err)
	}
	var serialized []schema.Command
	if err := json.Unmarshal(snapshot, &serialized); err != nil {
		t.Fatal(err)
	}
	if len(initial.Commands) != 1 || len(serialized) != 1 || serialized[0].Label != "observed-native-state" {
		t.Fatalf("the fixture did not reproduce independent, already-serialized transcripts: %s", snapshot)
	}
	data, err := os.ReadFile(filepath.Join(work, "continuation-commands.json"))
	if err != nil {
		t.Fatal(err)
	}
	var commands []schema.Command
	if err := json.Unmarshal(data, &commands); err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range commands {
		got = append(got, c.Label+":"+c.Status)
	}
	want := []string{"initial-native-check:0", "observed-native-state:0", "attach:0", "device-digest:0", "detach:0", "attach:0", "mount:0", "unmount:0", "hdiutil-info:0", "detach:16"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("failure evidence omitted or reordered native phases: got %v, want %v", got, want)
	}
}

func TestContinuationCommandHandoffDoesNotDuplicateAReusedTranscript(t *testing.T) {
	c := &continuationCommands{positions: map[*fixture.Transcript]int{}}
	a, b := &fixture.Transcript{}, &fixture.Transcript{}
	c.follow(a)
	a.Commands = append(a.Commands, schema.Command{Label: "first"})
	c.follow(b)
	b.Commands = append(b.Commands, schema.Command{Label: "second"})
	c.follow(a)
	a.Commands = append(a.Commands, schema.Command{Label: "last"})
	c.flush()
	var labels []string
	for _, cmd := range c.commands {
		labels = append(labels, cmd.Label)
	}
	if !reflect.DeepEqual(labels, []string{"first", "second", "last"}) {
		t.Fatalf("reused transcript corrupted chronological evidence: %v", labels)
	}
}

func TestContinuationCommandRetentionKeepsTheNativeErrorWhenWritingEvidenceFails(t *testing.T) {
	disk := &continuationCommandDisk{}
	v := &Verifier{Disk: disk}
	finish := v.recordContinuationCommands(filepath.Join(t.TempDir(), "missing-directory"))
	cause := errors.New("native close failed")
	err := cause
	finish(&err)
	if !errors.Is(err, cause) || !errors.Is(err, os.ErrNotExist) || v.Disk != disk || v.continuationLog != nil {
		t.Fatalf("evidence failure hid native failure or failed to restore disk: %v", err)
	}
}

func TestSuccessfulContinuationDoesNotRecreateRemovedWork(t *testing.T) {
	for _, result := range []error{nil, KnownLimit{Refusal: "tracked refusal"}} {
		v := &Verifier{Disk: &continuationCommandDisk{}}
		work := filepath.Join(t.TempDir(), "removed-work")
		finish := v.recordContinuationCommands(work)
		finish(&result)
		if _, err := os.Stat(work); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("successful cleanup was undone: %v", err)
		}
	}
}
