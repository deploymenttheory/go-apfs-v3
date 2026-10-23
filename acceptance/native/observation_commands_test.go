package native

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

type observationCommandDisk struct {
	fixture.Disk
	t          *fixture.Transcript
	attachErr  error
	observeErr error
	detachErr  error
}

func (d *observationCommandDisk) SetTranscript(t *fixture.Transcript) { d.t = t }

func (d *observationCommandDisk) record(label string, err error) {
	cmd := schema.Command{Label: label, Status: "0"}
	if err != nil {
		cmd.Status, cmd.StderrText = "1", err.Error()
	}
	d.t.Commands = append(d.t.Commands, cmd)
}

func (d *observationCommandDisk) Attach(context.Context, string, fixture.AttachOptions) (*fixture.Attachment, error) {
	d.record("attach", d.attachErr)
	if d.attachErr != nil {
		return nil, d.attachErr
	}
	return &fixture.Attachment{Volumes: []*fixture.AttachedVolume{{Name: "native-control"}}}, nil
}

func (d *observationCommandDisk) Info(context.Context, string) (map[string]any, error) {
	d.record("info", d.observeErr)
	return nil, d.observeErr
}

func (d *observationCommandDisk) Detach(context.Context, *fixture.Attachment) error {
	d.record("detach", d.detachErr)
	return d.detachErr
}

func failedObservationInput(t *testing.T) string {
	t.Helper()
	image := filepath.Join(t.TempDir(), "source.raw")
	if err := os.WriteFile(image, make([]byte, 512), 0600); err != nil {
		t.Fatal(err)
	}
	return image
}

func recordedCommands(t *testing.T, file string) []schema.Command {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var commands []schema.Command
	if err := json.Unmarshal(b, &commands); err != nil {
		t.Fatal(err)
	}
	return commands
}

func TestObservationFailureWithoutObservationRetainsPhaseAndContinuationCommands(t *testing.T) {
	work := t.TempDir()
	disk := &observationCommandDisk{observeErr: errors.New("native inventory failed"), detachErr: errors.New("native cleanup failed")}
	v := &Verifier{Disk: disk, Work: work}
	finish := v.recordContinuationCommands(work)
	initial := &fixture.Transcript{}
	v.setTranscript(initial)
	disk.record("initial-native-phase", nil)
	obs, err := v.observeImage(context.Background(), "failed-native-readback", failedObservationInput(t), "raw", nil, schema.ObserveSpec{}, schema.Recipe{})
	if obs != nil || !errors.Is(err, disk.observeErr) || !errors.Is(err, disk.detachErr) {
		t.Errorf("native inventory or cleanup failure lost: observation %v, error %v", obs, err)
	}
	phase := recordedCommands(t, filepath.Join(work, "observe", "failed-native-readback", "observation-commands.json"))
	if len(phase) != 3 || phase[1].Label != "info" || phase[1].StderrText != disk.observeErr.Error() || phase[2].Label != "detach" || phase[2].StderrText != disk.detachErr.Error() {
		t.Fatalf("failed nil-observation phase lost native receipts: %+v", phase)
	}
	if _, err := os.Stat(filepath.Join(work, "observe", "failed-native-readback", "observation.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed inventory fabricated an observation: %v", err)
	}
	// Later native calls still belong to the complete continuation transcript,
	// while the already-retained phase remains an immutable snapshot.
	disk.record("final-native-phase", errors.New("final close failure"))
	finish(&err)
	all := recordedCommands(t, filepath.Join(work, "continuation-commands.json"))
	var labels []string
	for _, cmd := range all {
		labels = append(labels, cmd.Label)
	}
	if !reflect.DeepEqual(labels, []string{"initial-native-phase", "attach", "info", "detach", "final-native-phase"}) || len(initial.Commands) != 1 {
		t.Fatalf("failed observation interrupted or reordered continuation handoffs: %v", labels)
	}
	if again := recordedCommands(t, filepath.Join(work, "observe", "failed-native-readback", "observation-commands.json")); !reflect.DeepEqual(again, phase) {
		t.Fatal("later continuation calls changed retained phase commands")
	}
}

func TestObservationAttachFailureRetainsCommands(t *testing.T) {
	disk := &observationCommandDisk{attachErr: errors.New("native attach failed")}
	v := &Verifier{Disk: disk, Work: t.TempDir()}
	if _, err := v.observeImage(context.Background(), "attach-failed", failedObservationInput(t), "raw", nil, schema.ObserveSpec{}, schema.Recipe{}); !errors.Is(err, disk.attachErr) {
		t.Fatalf("attach error changed: %v", err)
	}
	commands := recordedCommands(t, filepath.Join(v.Work, "observe", "attach-failed", "observation-commands.json"))
	if len(commands) != 1 || commands[0].Label != "attach" || commands[0].StderrText != disk.attachErr.Error() {
		t.Fatalf("failed attach receipt missing: %+v", commands)
	}
}

func TestObservationEvidenceWriteFailurePreservesNativeError(t *testing.T) {
	work := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(work, nil, 0600); err != nil {
		t.Fatal(err)
	}
	disk := &observationCommandDisk{observeErr: errors.New("native inventory failed")}
	v := &Verifier{Disk: disk, Work: work}
	_, err := v.observeImage(context.Background(), "failed-native-readback", failedObservationInput(t), "raw", nil, schema.ObserveSpec{}, schema.Recipe{})
	if !errors.Is(err, disk.observeErr) || !errors.Is(err, syscall.ENOTDIR) || !strings.Contains(err.Error(), "retain failed observation commands") {
		t.Fatalf("diagnostic IO failure was hidden or masked native error: %v", err)
	}
}
