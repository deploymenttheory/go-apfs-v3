package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type priorUnmountCommander struct {
	mu        sync.Mutex
	calls     [][]string
	inventory []byte
	infoErr   error
	detachOK  bool
}

func (c *priorUnmountCommander) Run(_ context.Context, cmd Command) Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, append([]string(nil), cmd.Argv...))
	switch cmd.Argv[0] {
	case "hdiutil":
		if cmd.Argv[1] == "detach" {
			if c.detachOK {
				return Result{}
			}
			return Result{Status: 16, Stderr: []byte("hdiutil: couldn't eject disk42 - Resource busy\n")}
		}
		return Result{Stdout: c.inventory}
	case "plutil":
		return Result{Stdout: append([]byte(nil), cmd.Stdin...)}
	case "diskutil":
		if cmd.Argv[1] == "unmount" {
			return Result{Stdout: []byte("Volume Reserved on disk42s1 unmounted\n")}
		}
		if c.infoErr != nil {
			return Result{Status: -1, Err: c.infoErr}
		}
		data, _ := json.Marshal(map[string]any{"DeviceNode": cmd.Argv[len(cmd.Argv)-1], "Mounted": false})
		return Result{Stdout: data}
	case "/usr/sbin/ioreg":
		return Result{Stdout: []byte("empty diagnostic-only scope")}
	case "/usr/sbin/lsof":
		return Result{Status: 1}
	}
	return Result{}
}

func priorUnmountDisk(t *testing.T) (*HostDisk, *Attachment, *priorUnmountCommander, mountIdentity) {
	t.Helper()
	volume := &AttachedVolume{Name: "Reserved", UUID: "E7A841BD-6244-485B-BDEF-587971DA5FE6", Dev: "/dev/disk42s1", Mount: t.TempDir()}
	pin, err := canonicalMountPath(volume.Mount)
	if err != nil {
		t.Fatal(err)
	}
	att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42", RDev: "/dev/rdisk42", Volumes: []*AttachedVolume{volume}}
	owner := attachedImage(att.Image, att.Dev)
	owner["system-entities"] = []any{map[string]any{"dev-entry": att.Dev}, map[string]any{"dev-entry": volume.Dev}}
	data, err := json.Marshal(map[string]any{"images": []any{owner}})
	if err != nil {
		t.Fatal(err)
	}
	cmd := &priorUnmountCommander{inventory: data}
	return imageTestDisk(cmd), att, cmd, mountIdentity{MountPoint: pin, Source: volume.Dev, FSID: [2]int32{41, 7}}
}

func priorUnmountActions(c *priorUnmountCommander) (unmounts, detaches int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, argv := range c.calls {
		if len(argv) > 1 && argv[0] == "hdiutil" && argv[1] == "detach" {
			detaches++
		}
		if len(argv) > 1 && argv[0] == "diskutil" && argv[1] == "unmount" {
			unmounts++
		}
	}
	return unmounts, detaches
}

func TestBusyDetachObservesPriorPrivatePinAfterExplicitUnmountSuccess(t *testing.T) {
	instantWaits(t)
	disk, att, cmd, identity := priorUnmountDisk(t)
	var probes atomic.Int32
	disk.mountProbe = func(pin string) (mountIdentity, error) {
		probes.Add(1)
		if pin != identity.MountPoint {
			return mountIdentity{}, fmt.Errorf("unexpected diagnostic pin %q", pin)
		}
		return identity, nil
	}
	if err := disk.Unmount(context.Background(), att.Volumes[0]); err != nil || att.Volumes[0].Mount != "" {
		t.Fatal("explicit native success must retain its current mounted-state semantics", err)
	}
	err := disk.Detach(context.Background(), att)
	var failed *NotSettledError
	unmounts, detaches := priorUnmountActions(cmd)
	if !errors.As(err, &failed) || failed.Checks != BusyWait.Attempts || detaches != BusyWait.Attempts || unmounts != 1 {
		t.Fatalf("evidence changed the original fatal cleanup or action budget: %v, unmounts=%d detaches=%d", err, unmounts, detaches)
	}
	var observed bool
	for _, command := range disk.T.Commands {
		observed = observed || command.Label == "busy-detach-prior-unmount"
	}
	if probes.Load() != 2 || !observed {
		t.Fatalf("prior private pin was not independently observed after explicit unmount success and Mounted=false: statfs calls=%d, evidence=%t", probes.Load(), observed)
	}
	row := priorUnmountRow(t, disk)
	if row.Expected != identity || row.Actual != identity || row.Outcome != "same" || row.CanonicalPin != identity.MountPoint || row.Error != "" || row.UnmountTranscript != "current" {
		t.Fatalf("prior-pin observation lost the unchanged kernel facts: %+v", row)
	}
	command := disk.T.Commands[row.UnmountCommand]
	if command.Label != "unmount" || command.Status != "0" || command.StdoutText != "Volume Reserved on disk42s1 unmounted\n" {
		t.Fatalf("memento does not identify the original explicit native success: %+v", command)
	}
	started, err := time.Parse(time.RFC3339Nano, row.Started)
	if err != nil {
		t.Fatal(err)
	}
	returned, err := time.Parse(time.RFC3339Nano, row.Returned)
	if err != nil || returned.Before(started) {
		t.Fatalf("invalid caller observation interval: %+v (%v)", row, err)
	}
}

func priorUnmountRow(t *testing.T, disk *HostDisk) priorUnmountObservation {
	t.Helper()
	var rows []priorUnmountObservation
	for _, command := range disk.T.Commands {
		if command.Label == "busy-detach-prior-unmount" {
			var row priorUnmountObservation
			if err := json.Unmarshal([]byte(command.StdoutText), &row); err != nil {
				t.Fatal(err)
			}
			rows = append(rows, row)
		}
	}
	if len(rows) != 1 {
		t.Fatalf("want exactly one failure-only prior-pin observation, got %d", len(rows))
	}
	return rows[0]
}

func TestPriorUnmountEvidenceNeverChangesCleanupAuthority(t *testing.T) {
	probeFailure := errors.New("statfs observation unavailable")
	infoFailure := fmt.Errorf("timeout after 10s: %w", context.DeadlineExceeded)
	for _, tc := range []struct {
		name              string
		outcome           string
		actual            func(mountIdentity) mountIdentity
		probeErr, infoErr error
	}{
		{name: "enclosing filesystem", outcome: "enclosing", actual: func(v mountIdentity) mountIdentity {
			return mountIdentity{MountPoint: filepath.Dir(v.MountPoint), Source: "host-filesystem", FSID: [2]int32{8, 9}}
		}},
		{name: "foreign filesystem at pin", outcome: "changed", actual: func(v mountIdentity) mountIdentity { v.Source, v.FSID = "/dev/foreign", [2]int32{8, 9}; return v }},
		{name: "different fsid at pin", outcome: "changed", actual: func(v mountIdentity) mountIdentity { v.FSID = [2]int32{8, 9}; return v }},
		{name: "unrelated mount point", outcome: "unavailable", actual: func(v mountIdentity) mountIdentity {
			v.MountPoint = filepath.Join(filepath.Dir(v.MountPoint), "unrelated")
			return v
		}},
		{name: "malformed kernel result", outcome: "unavailable", actual: func(v mountIdentity) mountIdentity { v.Source = ""; return v }},
		{name: "failed probe", outcome: "unavailable", probeErr: probeFailure},
		{name: "diskutil information timeout", outcome: "same", infoErr: infoFailure},
	} {
		t.Run(tc.name, func(t *testing.T) {
			instantWaits(t)
			disk, att, cmd, identity := priorUnmountDisk(t)
			cmd.infoErr = tc.infoErr
			var calls atomic.Int32
			disk.mountProbe = func(string) (mountIdentity, error) {
				if calls.Add(1) == 1 {
					return identity, nil
				}
				actual := identity
				if tc.actual != nil {
					actual = tc.actual(actual)
				}
				return actual, tc.probeErr
			}
			if err := disk.Unmount(context.Background(), att.Volumes[0]); err != nil {
				t.Fatal(err)
			}
			err := disk.Detach(context.Background(), att)
			var failed *NotSettledError
			unmounts, detaches := priorUnmountActions(cmd)
			if !errors.As(err, &failed) || failed.Checks != BusyWait.Attempts || detaches != BusyWait.Attempts || unmounts != 1 || calls.Load() != 2 {
				t.Fatalf("diagnostic changed cleanup authority or omitted the saved pin: %v, unmounts=%d detaches=%d statfs=%d", err, unmounts, detaches, calls.Load())
			}
			for _, cause := range []error{tc.probeErr, tc.infoErr} {
				if cause != nil && !errors.Is(err, cause) {
					t.Fatalf("diagnostic lost a known error cause %v: %v", cause, err)
				}
			}
			row := priorUnmountRow(t, disk)
			if row.Outcome != tc.outcome || row.Expected != identity || att.Volumes[0].Mount != "" {
				t.Fatalf("prior-pin facts changed successful-unmount state: %+v", row)
			}
			if (row.Error != "") != (tc.outcome == "unavailable") {
				t.Fatalf("unknown observation lost its failure: %+v", row)
			}
			for _, argv := range cmd.calls {
				if argv[0] == "/usr/sbin/lsof" {
					for _, arg := range argv {
						if arg == identity.MountPoint {
							t.Fatal("historical pin expanded the holder-query scope")
						}
					}
				}
			}
		})
	}
}

func TestBlockedPriorUnmountObservationPreservesCancellationAndCannotRecordLate(t *testing.T) {
	instantWaits(t)
	disk, att, cmd, identity := priorUnmountDisk(t)
	entered, release, returned := make(chan struct{}), make(chan struct{}), make(chan struct{})
	releaseProbe := sync.OnceFunc(func() { close(release) })
	defer releaseProbe()
	var calls atomic.Int32
	disk.mountProbe = func(string) (mountIdentity, error) {
		if calls.Add(1) == 1 {
			return identity, nil
		}
		close(entered)
		<-release
		close(returned)
		return identity, nil
	}
	if err := disk.Unmount(context.Background(), att.Volumes[0]); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- disk.Detach(ctx, att) }()
	<-entered
	cancel()
	err := <-done
	var failed *NotSettledError
	unmounts, detaches := priorUnmountActions(cmd)
	if !errors.Is(err, context.Canceled) || !errors.As(err, &failed) || failed.Checks != BusyWait.Attempts || unmounts != 1 || detaches != BusyWait.Attempts {
		t.Fatalf("blocked evidence changed the original error or cleanup budget: %v", err)
	}
	row := priorUnmountRow(t, disk)
	if row.Outcome != "unavailable" || row.Error == "" {
		t.Fatalf("cancelled observer claimed a mount state: %+v", row)
	}
	if row.Started == "" || row.Deadline == "" || row.Returned != "" {
		t.Fatalf("unfinished kernel observation lost its known start/deadline or invented a return: %+v", row)
	}
	before := len(disk.T.Commands)
	releaseProbe()
	<-returned
	if len(disk.T.Commands) != before {
		t.Fatal("a late kernel-probe answer mutated the final transcript")
	}
}

func TestPriorUnmountObservationRetainsAnExpiredDeadlineWithoutStartingAProbe(t *testing.T) {
	disk, att, _, identity := priorUnmountDisk(t)
	disk.mountProbe = func(string) (mountIdentity, error) { return identity, nil }
	if err := disk.Unmount(context.Background(), att.Volumes[0]); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Time{})
	defer cancel()
	disk.mountProbe = func(string) (mountIdentity, error) {
		t.Error("expired diagnostic invoked statfs")
		return identity, nil
	}
	row, err := probePriorUnmount(ctx, disk.mountProbe, *att.Volumes[0].priorUnmount, &diagnosticInvocationGate{})
	if !errors.Is(err, context.DeadlineExceeded) || row.Outcome != "unavailable" || row.Error == "" || row.Deadline == "" || row.Started != "" || row.Returned != "" {
		t.Fatalf("expired evidence deadline lost its cause: %+v (%v)", row, err)
	}
}

func TestPriorUnmountObservationCannotStartAfterForegroundSeal(t *testing.T) {
	gate := &diagnosticInvocationGate{}
	gate.seal()
	called := false
	row, err := probePriorUnmount(context.Background(), func(string) (mountIdentity, error) {
		called = true
		return mountIdentity{}, nil
	}, priorUnmountIdentity{}, gate)
	if err == nil || called || row.Started != "" || row.Returned != "" || row.Outcome != "unavailable" {
		t.Fatalf("sealed foreground observation permitted a late probe or invented invocation: %+v, called=%t (%v)", row, called, err)
	}
}

func TestSuccessfulDetachDoesNotProbeThePriorUnmountPin(t *testing.T) {
	disk, att, cmd, identity := priorUnmountDisk(t)
	cmd.detachOK = true
	var calls atomic.Int32
	disk.mountProbe = func(string) (mountIdentity, error) { calls.Add(1); return identity, nil }
	if err := disk.Unmount(context.Background(), att.Volumes[0]); err != nil {
		t.Fatal(err)
	}
	if err := disk.Detach(context.Background(), att); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("healthy cleanup added a failure-only kernel probe", calls.Load())
	}
	for _, command := range disk.T.Commands {
		if command.Label == "busy-detach-prior-unmount" {
			t.Fatal("healthy cleanup produced failure-only mount evidence")
		}
	}
}

func TestPriorUnmountEvidenceIdentifiesItsOriginalTranscriptAfterHandoff(t *testing.T) {
	instantWaits(t)
	disk, att, _, identity := priorUnmountDisk(t)
	disk.mountProbe = func(string) (mountIdentity, error) { return identity, nil }
	if err := disk.Unmount(context.Background(), att.Volumes[0]); err != nil {
		t.Fatal(err)
	}
	original := disk.T
	disk.SetTranscript(&Transcript{})
	if err := disk.Detach(context.Background(), att); err == nil {
		t.Fatal("busy cleanup unexpectedly passed")
	}
	for _, command := range disk.T.Commands {
		if command.Label != "busy-detach-prior-unmount" {
			continue
		}
		var row map[string]any
		if err := json.Unmarshal([]byte(command.StdoutText), &row); err != nil {
			t.Fatal(err)
		}
		if row["UnmountTranscript"] != "prior" {
			t.Fatalf("prior unmount ordinal silently points into a different transcript: marker=%v, ordinal=%v", row["UnmountTranscript"], row["UnmountCommand"])
		}
		index := int(row["UnmountCommand"].(float64))
		if original.Commands[index].Label != "unmount" || disk.T.Commands[index].Label == "unmount" {
			t.Fatal("handoff control did not distinguish the two original command sequences")
		}
		return
	}
	t.Fatal("handoff lost the prior mount observation")
}

func TestBlockedPriorUnmountProbeDoesNotDelayForegroundEvidence(t *testing.T) {
	disk, att, cmd, identity := priorUnmountDisk(t)
	entered, release := make(chan struct{}), make(chan struct{})
	releaseProbe := sync.OnceFunc(func() { close(release) })
	defer releaseProbe()
	var calls atomic.Int32
	disk.mountProbe = func(string) (mountIdentity, error) {
		if calls.Add(1) == 1 {
			return identity, nil
		}
		close(entered)
		<-release
		return identity, nil
	}
	if err := disk.Unmount(context.Background(), att.Volumes[0]); err != nil {
		t.Fatal(err)
	}
	capture := newAttachmentDiagnostics(disk, att)
	finish := capture.observePriorUnmounts(context.Background())
	<-entered
	// This native-inventory seam must remain runnable while statfs is held.
	// No elapsed-time threshold or sleep is needed: release happens afterward.
	info, err := disk.Info(context.Background(), att.Dev)
	if err != nil || info["Mounted"] != false {
		t.Fatal("foreground evidence could not complete before the kernel probe", info, err)
	}
	for _, command := range disk.T.Commands {
		if command.Label == "busy-detach-prior-unmount" {
			t.Fatal("worker mutated the transcript before foreground merge")
		}
	}
	releaseProbe()
	finish()
	if capture.err != nil || len(capture.priorUnmounts) != 1 || priorUnmountRow(t, disk).Outcome != "same" {
		t.Fatalf("concurrent probe did not publish its complete local answer: %+v (%v)", capture.priorUnmounts, capture.err)
	}
	unmounts, detaches := priorUnmountActions(cmd)
	if unmounts != 1 || detaches != 0 {
		t.Fatalf("evidence performed filesystem actions: unmounts=%d detaches=%d", unmounts, detaches)
	}
}
