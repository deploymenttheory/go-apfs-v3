package fixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBusyEjectObservationPreservesRecoveredCleanupAndRecordedBoundary(t *testing.T) {
	instantWaits(t)
	image := detachImage(t, t.TempDir())
	att := &Attachment{Image: image, Dev: "/dev/disk42"}
	commander := detachCommander(t, map[string]any{"images": []any{attachedImage(image, att.Dev)}})
	disk := imageTestDisk(commander)
	disk.ObserveBusyEject = true
	// Explicitly deny the real-host guard. This is an ordinary fake-command
	// contract: not even a tracer preflight may execute on the development host.
	t.Setenv("APFS_NATIVE_DISPOSABLE_VM", "")
	t.Setenv("GITHUB_ACTIONS", "")
	t.Setenv("RUNNER_ENVIRONMENT", "")
	if err := disk.Detach(context.Background(), att); err != nil {
		t.Fatal(err)
	}
	if detachCalls(commander) != 2 || len(commander.calls) != 6 {
		t.Fatal("observation changed existing normal requests or ran tools despite the guard")
	}
	var receipt struct {
		EjectTrace *struct {
			State        string
			AfterCommand int
		}
	}
	if err := json.Unmarshal([]byte(disk.T.Commands[len(disk.T.Commands)-1].StdoutText), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.EjectTrace == nil {
		t.Fatal("qualified busy response has no explicit admitted/skipped trace observation")
	}
	if receipt.EjectTrace.State != "skipped" || receipt.EjectTrace.AfterCommand != 1 {
		t.Fatalf("guard refusal or frozen first-response anchor changed: %+v", receipt.EjectTrace)
	}
	if disk.T.Commands[receipt.EjectTrace.AfterCommand].Status != "16" {
		t.Fatal("observation preceded the original recorded busy response")
	}
}

func TestEjectTracePreflightRefusesActiveUnknownAndAmbiguousDaemonState(t *testing.T) {
	for _, tc := range []struct {
		name, state, pid string
		status           int
		wantCalls        int
	}{
		{"active", "1\n", "", 0, 1},
		{"background", "2\n", "", 0, 1},
		{"unknown", "OFF\n", "", 0, 1},
		{"failed", "0\n", "", 1, 1},
		{"empty", "", "", 0, 1},
		{"multiple daemons", "0\n", "12\n13\n", 0, 2},
		{"zero daemon", "0\n", "0\n", 0, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			commander := discoveryCommandFunc(func(_ context.Context, cmd Command) Result {
				calls++
				switch cmd.Label {
				case "busy-eject-trace-state":
					return Result{Status: tc.status, Stdout: []byte(tc.state)}
				case "busy-eject-daemon-pid":
					return Result{Stdout: []byte(tc.pid)}
				default:
					t.Errorf("unadmitted native observation %s", cmd.Label)
					return Result{Status: 1}
				}
			})
			disk := &HostDisk{C: commander, T: &Transcript{}, ejectTraceGuard: func() error { return nil }}
			capture := newAttachmentDiagnostics(disk, &Attachment{Dev: "/dev/disk42"})
			capture.startEjectTrace(context.Background(), 3)
			capture.finishEjectTrace(context.Background(), true, "control")
			if calls != tc.wantCalls || capture.ejectTrace.State != "skipped" || capture.ejectTrace.Availability != "unknown" || capture.err != nil || len(capture.probes) != calls {
				t.Fatalf("unsafe admission or missing original preflight: calls=%d evidence=%+v err=%v", calls, capture.ejectTrace, capture.err)
			}
		})
	}
}

func TestEjectTraceStopCannotDelayRecoveredDetachOrPublishAfterReturn(t *testing.T) {
	instantWaits(t)
	image := detachImage(t, t.TempDir())
	att := &Attachment{Image: image, Dev: "/dev/disk42"}
	base := detachCommander(t, map[string]any{"images": []any{attachedImage(image, att.Dev)}})
	entered, release, left := make(chan struct{}), make(chan struct{}), make(chan struct{})
	reader := discoveryCommandFunc(func(ctx context.Context, cmd Command) Result {
		switch cmd.Label {
		case "busy-eject-trace-state":
			return Result{Stdout: []byte("0\n")}
		case "busy-eject-daemon-pid":
			return Result{Stdout: []byte("314\n")}
		case "busy-eject-fs-usage":
			want := []string{"/usr/bin/env", "TZ=UTC", "/usr/bin/fs_usage", "-w", "-f", "filesys", "-t", "6", "314"}
			if !reflect.DeepEqual(cmd.Argv, want) || !cmd.Sudo || cmd.Timeout != busyProbeTimeout {
				t.Errorf("trace scope/UTC/budget changed: %+v", cmd)
			}
			close(entered)
			<-release // Deliberately hostile: the observation cannot hold cleanup.
			defer close(left)
			return Result{Stdout: []byte(syntheticEjectTrace)}
		}
		if cmd.Label == "detach" && len(cmd.Argv) == 4 {
			select {
			case <-entered:
			case <-ctx.Done():
				return Result{Status: -1, Err: ctx.Err()}
			}
		}
		return base.Run(ctx, cmd)
	})
	recorder := &ownershipEvidenceCommander{C: reader, Dir: t.TempDir(), Phase: "busy-cleanup"}
	disk := imageTestDisk(recorder)
	disk.ObserveBusyEject, disk.ejectTraceGuard = true, func() error { return nil }
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := disk.Detach(ctx, att); err != nil {
		t.Fatal(err)
	}
	if detachCalls(base) != 2 {
		t.Fatal("observer changed normal action count")
	}
	var receipt struct{ EjectTrace ejectTraceEvidence }
	if err := json.Unmarshal([]byte(disk.T.Commands[len(disk.T.Commands)-1].StdoutText), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.EjectTrace.State != "outcome-unavailable" || receipt.EjectTrace.Started == "" || receipt.EjectTrace.Returned != "" || receipt.EjectTrace.StopRequested == "" || receipt.EjectTrace.Availability != "unknown" {
		t.Fatalf("in-flight result was invented: %+v", receipt.EjectTrace)
	}
	if receipt.EjectTrace.AfterCommand != 1 || disk.T.Commands[1].Status != "16" {
		t.Fatal("observer did not follow frozen original busy record")
	}
	for _, row := range recorder.Results {
		if row.Label == "busy-eject-fs-usage" {
			t.Fatal("unfinished trace falsely published a normal original result")
		}
	}
	close(release)
	<-left
}

func TestEjectTraceForegroundSealsActualRecorderAndFreezesCompletedBytes(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	delegate := discoveryCommandFunc(func(_ context.Context, cmd Command) Result {
		switch cmd.Label {
		case "busy-eject-trace-state":
			return Result{Stdout: []byte("0\n")}
		case "busy-eject-daemon-pid":
			return Result{Stdout: []byte("314\n")}
		default:
			close(entered)
			<-release
			return Result{Stdout: []byte(syntheticEjectTrace)}
		}
	})
	recorder := &ownershipEvidenceCommander{C: delegate, Dir: t.TempDir(), Phase: "original-phase"}
	disk := &HostDisk{C: recorder, T: &Transcript{}, ejectTraceGuard: func() error { return nil }}
	capture := newAttachmentDiagnostics(disk, &Attachment{Dev: "/dev/disk42"})
	capture.startEjectTrace(context.Background(), 4)
	<-entered
	capture.finishEjectTrace(context.Background(), false, "operation-finished")
	if len(recorder.Results) != 2 || len(capture.probes) != 2 {
		t.Fatalf("completed preflight originals missing: %d/%d", len(recorder.Results), len(capture.probes))
	}
	before, err := json.Marshal(recorder.Results)
	if err != nil {
		t.Fatal(err)
	}
	commands := len(disk.T.Commands)
	recorder.Phase = "next-phase"
	close(release)
	<-capture.ejectJob.done // The late delegate and all local freezing have finished.
	after, err := json.Marshal(recorder.Results)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || len(disk.T.Commands) != commands || recorder.Err != nil {
		t.Fatal("abandoned read published after foreground handoff")
	}
	for _, row := range recorder.Results {
		if row.Phase != "original-phase" {
			t.Fatal("phase was not frozen before launch")
		}
	}
}

func TestEjectTraceAvailabilityRequiresFullOriginalStreamsAndDatedExactTarget(t *testing.T) {
	for _, tc := range []struct {
		name, stderr string
		status       int
		want         bool
	}{
		{"complete", "", 0, true},
		{"dropped", "fs_usage: buffer overrun\n", 0, false},
		{"permission", "permission denied\n", 1, false},
		{"nonzero", "", 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commander := discoveryCommandFunc(func(_ context.Context, cmd Command) Result {
				switch cmd.Label {
				case "busy-eject-trace-state":
					return Result{Stdout: []byte("0\n")}
				case "busy-eject-daemon-pid":
					return Result{Stdout: []byte("314\n")}
				default:
					return Result{Status: tc.status, Stdout: []byte(syntheticEjectTrace), Stderr: []byte(tc.stderr)}
				}
			})
			disk := &HostDisk{C: commander, T: &Transcript{}, ejectTraceGuard: func() error { return nil }}
			capture := newAttachmentDiagnostics(disk, &Attachment{Dev: "/dev/disk42"})
			capture.startEjectTrace(context.Background(), -1)
			capture.finishEjectTrace(context.Background(), true, "control")
			e := capture.ejectTrace
			// Fixed ordinary-file projection: event bytes are synthetic; bind
			// their UTC date/interval explicitly rather than changing originals.
			e.LocalDate, e.LocalZone, e.UTCOffsetSeconds = "2026-10-25", "UTC", 0
			e.Started, e.Returned, e.Deadline = "2026-10-25T12:34:56Z", "2026-10-25T12:34:57Z", "2026-10-25T12:35:00Z"
			capture.qualifyEjectCoverage()
			if (e.Availability == "observed-target-lifecycles") != tc.want || capture.err != nil {
				t.Fatalf("bad availability: %+v err=%v", e, capture.err)
			}
		})
	}
}

func TestEjectTraceDateCorrelationRefusesAmbiguousOrUnobservedTime(t *testing.T) {
	e := ejectTraceEvidence{LocalDate: "2026-10-25", LocalZone: "UTC"}
	start, _ := time.Parse(time.RFC3339Nano, "2026-10-25T23:59:59Z")
	end := start.Add(2 * time.Second)
	if got, ok := e.correlateTime("00:00:00.100001", start, end); !ok || got.Day() != 26 {
		t.Fatal("midnight observation did not bind to following UTC date")
	}
	if _, ok := e.correlateTime("12:34:56.100001", start, end); ok {
		t.Fatal("out-of-window event qualified")
	}
	if _, ok := e.correlateTime("00:00:00.100001", start, start.Add(49*time.Hour)); ok {
		t.Fatal("ambiguous date qualified")
	}
}

func TestEjectTraceNeverObservesHealthyOrPermanentFirstDetach(t *testing.T) {
	for _, status := range []int{0, 5} {
		t.Run(strconv.Itoa(status), func(t *testing.T) {
			image := detachImage(t, t.TempDir())
			att := &Attachment{Image: image, Dev: "/dev/disk42"}
			base := detachCommander(t, map[string]any{"images": []any{attachedImage(image, att.Dev)}})
			base.sequence["hdiutil"][1] = Result{Status: status}
			disk := imageTestDisk(base)
			disk.ObserveBusyEject = true
			disk.ejectTraceGuard = func() error { t.Error("observer ran without first native busy"); return nil }
			err := disk.Detach(context.Background(), att)
			if (err == nil) != (status == 0) || detachCalls(base) != 1 || len(base.calls) != 3 {
				t.Fatalf("original outcome/actions changed: %v, %+v", err, base.calls)
			}
		})
	}
}

func TestEjectTraceRetainsLaunchFailuresAndOverflowWithoutQualifyingThem(t *testing.T) {
	cause := errors.New("synthetic tracer launch refusal")
	for _, tc := range []struct {
		name               string
		result             Result
		wantRetentionError bool
	}{
		{"launch", Result{Status: -1, Err: cause}, false},
		{"stream overflow", Result{Stdout: bytes.Repeat([]byte{'x'}, busyEvidenceStreamLimit+1)}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commander := discoveryCommandFunc(func(_ context.Context, cmd Command) Result {
				switch cmd.Label {
				case "busy-eject-trace-state":
					return Result{Stdout: []byte("0\n")}
				case "busy-eject-daemon-pid":
					return Result{Stdout: []byte("314\n")}
				default:
					return tc.result
				}
			})
			disk := &HostDisk{C: commander, T: &Transcript{}, ejectTraceGuard: func() error { return nil }}
			capture := newAttachmentDiagnostics(disk, &Attachment{Dev: "/dev/disk42"})
			capture.startEjectTrace(context.Background(), -1)
			capture.finishEjectTrace(context.Background(), true, "control")
			if (capture.err != nil) != tc.wantRetentionError || capture.ejectTrace.OutputComplete || capture.ejectTrace.Availability != "unknown" {
				t.Fatalf("loss/launch failure was qualified or changed cleanup: %+v %v", capture.ejectTrace, capture.err)
			}
			p := capture.probes[len(capture.probes)-1]
			if p.Stdout.Bytes != len(tc.result.Stdout) || p.Stdout.SHA256 != fmt.Sprintf("%x", sha256.Sum256(tc.result.Stdout)) || len(p.Stdout.Data) != min(len(tc.result.Stdout), busyEvidenceStreamLimit) {
				t.Fatal("full originals and retained prefix conflated")
			}
		})
	}
}

func TestEjectTraceSealedBeforeStartCannotInvokeAnyNativeRead(t *testing.T) {
	calls := 0
	job := &ejectTraceJob{reads: make(chan ejectTraceRead, 3)}
	job.seal()
	result := runEjectTrace(context.Background(), discoveryCommandFunc(func(context.Context, Command) Result { calls++; return Result{} }), job, ejectTraceEvidence{})
	if calls != 0 || result.evidence.State != "skipped" || result.evidence.Admission != "active-or-unknown" {
		t.Fatalf("sealed observation invoked: calls=%d %+v", calls, result.evidence)
	}
}

func TestEjectTraceFreezesReusedReadBuffersAndDistinguishesCallerCancellation(t *testing.T) {
	shared := []byte("0\n")
	commander := discoveryCommandFunc(func(_ context.Context, cmd Command) Result {
		switch cmd.Label {
		case "busy-eject-trace-state":
			return Result{Stdout: shared}
		case "busy-eject-daemon-pid":
			copy(shared, "7\n")
			return Result{Stdout: shared}
		default:
			return Result{}
		}
	})
	disk := &HostDisk{C: commander, T: &Transcript{}, ejectTraceGuard: func() error { return nil }}
	capture := newAttachmentDiagnostics(disk, &Attachment{Dev: "/dev/disk42"})
	capture.startEjectTrace(context.Background(), 1)
	capture.finishEjectTrace(context.Background(), true, "control")
	if string(capture.probes[0].Stdout.Data) != "0\n" || string(capture.probes[1].Stdout.Data) != "7\n" {
		t.Fatal("later command reuse rewrote frozen original preflight")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	disk = &HostDisk{C: commander, T: &Transcript{}, ejectTraceGuard: func() error { return nil }}
	capture = newAttachmentDiagnostics(disk, &Attachment{Dev: "/dev/disk42"})
	capture.startEjectTrace(ctx, 1)
	capture.finishEjectTrace(ctx, false, "operation-finished")
	if !strings.HasPrefix(capture.ejectTrace.StopReason, "caller-cancelled:") || capture.ejectTrace.Availability != "unknown" || capture.err != nil {
		t.Fatalf("caller cancellation was mislabeled or manufactured a diagnostic failure: %+v %v", capture.ejectTrace, capture.err)
	}
}

func TestEjectTraceReadBeforeFinalAdmissionCannotQualifyVisibility(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cmd := Command{Label: "busy-eject-fs-usage", Argv: []string{"/usr/bin/env", "TZ=UTC", "/usr/bin/fs_usage"}, Expected: "record"}
	job := &ejectTraceJob{ctx: ctx, cancel: cancel, done: make(chan ejectTraceAnswer, 1), reads: make(chan ejectTraceRead, 3)}
	// Exact scheduling seam: the completed native result is buffered, while
	// the worker's final OFF/PID/tool metadata has not yet been delivered.
	job.reads <- ejectTraceRead{cmd, freezeDetachLog(ctx, cmd, Result{Stdout: []byte(syntheticEjectTrace)}, "2026-10-25T12:34:56Z", "2026-10-25T12:34:57Z")}
	capture := newAttachmentDiagnostics(&HostDisk{T: &Transcript{}}, &Attachment{Dev: "/dev/disk42"})
	capture.ejectTrace = &ejectTraceEvidence{Availability: "unknown", LocalDate: "2026-10-25", LocalZone: "UTC", RawTargets: []string{"/dev/rdisk42"}}
	capture.ejectJob = job
	capture.finishEjectTrace(ctx, false, "operation-finished")
	if !capture.ejectTrace.OutputComplete || len(capture.probes) != 1 {
		t.Fatal("completed original read was discarded")
	}
	if capture.ejectTrace.Availability != "unknown" || capture.ejectTrace.Admission != "" || capture.ejectTrace.DaemonPID != 0 {
		t.Fatalf("missing final admission metadata became positive: %+v", capture.ejectTrace)
	}
}

func TestEjectTraceSuccessfulResultWithRecordedCancellationRemainsUnqualified(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	commander := discoveryCommandFunc(func(_ context.Context, cmd Command) Result {
		switch cmd.Label {
		case "busy-eject-trace-state":
			return Result{Stdout: []byte("0\n")}
		case "busy-eject-daemon-pid":
			return Result{Stdout: []byte("314\n")}
		default:
			cancel()
			return Result{Stdout: []byte(syntheticEjectTrace)}
		}
	})
	capture := newAttachmentDiagnostics(&HostDisk{C: commander, T: &Transcript{}, ejectTraceGuard: func() error { return nil }}, &Attachment{Dev: "/dev/disk42"})
	capture.startEjectTrace(ctx, 1)
	answer := <-capture.ejectJob.done
	capture.ejectJob.done <- answer
	capture.finishEjectTrace(ctx, true, "control")
	last := capture.probes[len(capture.probes)-1]
	if last.Error == "" || last.Returned == "" {
		t.Fatal("original successful return/cancellation uncertainty was lost")
	}
	if capture.ejectTrace.OutputComplete || capture.ejectTrace.Availability != "unknown" {
		t.Fatalf("cancelled read became qualified: %+v", capture.ejectTrace)
	}
	if capture.err != nil {
		t.Fatal("observed cancellation manufactured cleanup failure", capture.err)
	}
}

func TestEjectTraceAvailabilityRequiresReturnWithinDeclaredDeadline(t *testing.T) {
	coverage, err := inspectEjectTrace([]byte(syntheticEjectTrace), "/dev/rdisk42")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		deadline string
		want     bool
	}{
		{"", false}, {"unparseable", false}, {"2026-10-25T12:34:56.5Z", false}, {"2026-10-25T12:34:57Z", true},
	} {
		e := ejectTraceEvidence{Admission: "off-observed-nonatomic", DaemonPID: 314, OutputComplete: true, Started: "2026-10-25T12:34:56Z", Returned: "2026-10-25T12:34:57Z", Deadline: tc.deadline, LocalDate: "2026-10-25", LocalZone: "UTC", RawTargets: []string{"/dev/rdisk42"}, Coverage: []ejectTraceCoverage{coverage}}
		capture := &attachmentDiagnostics{ejectTrace: &e}
		capture.qualifyEjectCoverage()
		if (e.Availability == "observed-target-lifecycles") != tc.want {
			t.Fatalf("invalid deadline qualification: %+v", e)
		}
	}
}
