package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

func busyDetachCommander(t *testing.T, att *Attachment) *fakeCommander {
	t.Helper()
	info, err := json.Marshal(map[string]any{"images": []any{attachedImage(att.Image, att.Dev)}})
	if err != nil {
		t.Fatal(err)
	}
	var queue []Result
	for range BusyWait.Attempts - 1 {
		queue = append(queue, Result{Stdout: []byte("native image inventory")}, Result{Status: 16, Stderr: []byte("Resource busy")})
	}
	// Bind the final normal eject, then retain the exhausted-action inventory.
	queue = append(queue, Result{Stdout: []byte("native image inventory")}, Result{Stdout: []byte("native image inventory")})
	return &fakeCommander{sequence: map[string][]Result{"hdiutil": queue, "diskutil": {{Status: 16, Stderr: []byte("Resource busy")}}}, results: map[string]Result{
		"hdiutil": {Stdout: info}, "plutil": {Stdout: info}, "/usr/sbin/lsof": {Status: 1},
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
	var holderFound bool
	for _, cmd := range disk.T.Commands {
		if cmd.Label == "busy-detach-open-files" {
			holderFound = true
			if !cmd.Sudo || cmd.Status != "1" || cmd.Expected != "record" || !slices.Contains(cmd.Argv, att.Image) || !slices.Contains(cmd.Argv, att.Dev) || !slices.Contains(cmd.Argv, att.RDev) {
				t.Fatalf("exact scoped holder result was not retained: %+v", cmd)
			}
		}
	}
	if !holderFound {
		t.Fatal("missing holder evidence")
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
