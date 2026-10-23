package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
)

func busyDetachCommander(t *testing.T, att *Attachment) *fakeCommander {
	t.Helper()
	info, err := json.Marshal(map[string]any{"images": []any{attachedImage(att.Image, att.Dev)}})
	if err != nil {
		t.Fatal(err)
	}
	var queue []Result
	for range BusyWait.Attempts {
		queue = append(queue, Result{Stdout: []byte("native image inventory")}, Result{Status: 16, Stderr: []byte("Resource busy")})
	}
	// The final inventory is read-only evidence after the close budget failed.
	queue = append(queue, Result{Stdout: []byte("native image inventory")})
	return &fakeCommander{sequence: map[string][]Result{"hdiutil": queue}, results: map[string]Result{
		"plutil": {Stdout: info}, "/usr/sbin/lsof": {Status: 1},
	}}
}

func TestExhaustedDetachRetainsScopedEvidenceWithoutAnotherClose(t *testing.T) {
	instantWaits(t)
	att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42", RDev: "/dev/rdisk42"}
	commander := busyDetachCommander(t, att)
	disk := imageTestDisk(commander)
	err := disk.Detach(context.Background(), att)
	var failed *NotSettledError
	if !errors.As(err, &failed) || failed.Checks != BusyWait.Attempts || detachCalls(commander) != BusyWait.Attempts {
		t.Fatalf("failure evidence changed the detach verdict or close budget: %v, calls=%v", err, commander.calls)
	}
	commands := disk.T.Commands
	last := commands[len(commands)-3:]
	want := [][]string{{"hdiutil", "info", "-plist"}, {"diskutil", "info", "-plist", att.Dev}, {"/usr/sbin/lsof", "-nP", "--", att.Image, att.Dev, att.RDev}}
	for i := range last {
		if !reflect.DeepEqual(last[i].Argv, want[i]) {
			t.Fatalf("busy evidence escaped the exact failed attachment: %+v", last)
		}
	}
	if !last[2].Sudo || last[2].Status != "1" || last[2].Expected != "record" {
		t.Fatalf("no-open-files result was not retained: %+v", last[2])
	}
}

func TestBusyDetachEvidencePreservesDiagnosticAndOriginalFailures(t *testing.T) {
	instantWaits(t)
	att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42"}
	commander := busyDetachCommander(t, att)
	cause := errors.New("holder query unavailable")
	commander.results["/usr/sbin/lsof"] = Result{Status: -1, Err: cause}
	disk := imageTestDisk(commander)
	err := disk.Detach(context.Background(), att)
	var failed *NotSettledError
	if !errors.As(err, &failed) || !errors.Is(err, cause) || detachCalls(commander) != BusyWait.Attempts {
		t.Fatalf("diagnostic failure masked the native result: %v", err)
	}
}

func TestBusyDetachEvidenceLeavesReassignedDeviceAlone(t *testing.T) {
	instantWaits(t)
	att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42"}
	commander := busyDetachCommander(t, att)
	original := commander.results["plutil"]
	var inventory []Result
	for range BusyWait.Attempts {
		inventory = append(inventory, original)
	}
	other := detachImage(t, t.TempDir())
	changed, err := json.Marshal(map[string]any{"images": []any{attachedImage(other, att.Dev)}})
	if err != nil {
		t.Fatal(err)
	}
	commander.sequence["plutil"] = append(inventory, Result{Stdout: changed})
	disk := imageTestDisk(commander)
	err = disk.Detach(context.Background(), att)
	var failed *NotSettledError
	if !errors.As(err, &failed) || detachCalls(commander) != BusyWait.Attempts {
		t.Fatalf("device reassignment changed the original failure: %v", err)
	}
	for _, cmd := range disk.T.Commands {
		if cmd.Label == "busy-detach-device" || cmd.Label == "busy-detach-open-files" {
			t.Fatalf("queried a device after ownership changed: %+v", cmd)
		}
	}
}
