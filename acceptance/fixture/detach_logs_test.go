package fixture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func logActionWindow(c *attachmentDiagnostics) {
	now := time.Now().UTC()
	c.busy = true
	c.actions = []detachOperationEvidence{{Started: now.Add(-time.Second).Format(time.RFC3339Nano), Returned: now.Format(time.RFC3339Nano)}}
}

func TestBusyDetachLogReadsDoNotDelayMandatoryDeviceAndHolderEvidence(t *testing.T) {
	instantWaits(t)
	image := detachImage(t, t.TempDir())
	base := &detachActionCommander{image: image}
	type invocation struct {
		command  Command
		deadline time.Time
	}
	entered := make(chan invocation, 2)
	deadlines := map[string]time.Time{}
	release := make(chan struct{})
	var once sync.Once
	unblock := func() { once.Do(func() { close(release) }) }
	defer unblock()
	var foreground atomic.Bool
	commander := discoveryCommandFunc(func(ctx context.Context, cmd Command) Result {
		if cmd.Argv[0] == "/usr/bin/log" {
			if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > busyProbeTimeout {
				t.Error("log has no existing ten-second child deadline")
			}
			if cmd.Timeout != busyProbeTimeout {
				t.Error("log changed command timeout")
			}
			deadline, _ := ctx.Deadline()
			entered <- invocation{cmd, deadline}
			select {
			case <-release:
				return Result{Stdout: []byte("{\"finished\":true}\n")}
			case <-ctx.Done():
				return Result{Status: -1, Err: ctx.Err()}
			}
		}
		if cmd.Label == "busy-detach-open-files" {
			// Neither read can complete until the unchanged foreground holder probe
			// has been scheduled and both independent log delegates are executing.
			for range 2 {
				select {
				case call := <-entered:
					deadlines[call.command.Label] = call.deadline
				case <-ctx.Done():
					t.Error("log delegates did not run concurrently")
				}
			}
			foreground.Store(true)
			unblock()
		}
		return base.Run(ctx, cmd)
	})
	disk := imageTestDisk(commander)
	err := disk.Detach(context.Background(), &Attachment{Image: image, Dev: "/dev/disk42"})
	var busy *NotSettledError
	if !errors.As(err, &busy) || busy.Checks != 6 || !foreground.Load() {
		t.Fatalf("diagnostics displaced original fatal/action/foreground obligations: %v", err)
	}
	var receipt struct {
		Logs    []detachLogEvidence
		Probes  []attachmentDiagnosticProbe
		Actions []detachOperationEvidence
	}
	last := disk.T.Commands[len(disk.T.Commands)-1]
	if err := json.Unmarshal([]byte(last.StdoutText), &receipt); err != nil || len(receipt.Logs) != 2 {
		t.Fatal("fixed log receipts missing", err)
	}
	for i, row := range receipt.Logs {
		command := disk.T.Commands[row.Command]
		if row.BackendPID != 123 || row.Error != "" || row.WindowClamped || command.Status != "0" {
			t.Fatalf("qualified query lost its observed outcome: %+v", row)
		}
		for _, probe := range receipt.Probes {
			if probe.Command == row.Command {
				deadline, err := time.Parse(time.RFC3339Nano, probe.Deadline)
				if err != nil || !deadline.Equal(deadlines[row.Scope]) {
					t.Fatal("receipt did not preserve actual child context deadline", err)
				}
			}
		}
		if i == 0 && !slices.Equal(command.Argv[len(command.Argv)-2:], []string{"--process", "123"}) {
			t.Fatal("backend PID was guessed or omitted")
		}
		if i == 1 && (!strings.Contains(command.Argv[len(command.Argv)-1], `process == "diskarbitrationd"`) || !strings.Contains(command.Argv[len(command.Argv)-1], "eventMessage CONTAINS[c] "+strconv.Quote(image))) {
			t.Fatal("arbitration/device query lost target scope")
		}
		if i > 0 && row.Command <= receipt.Logs[i-1].Command {
			t.Fatal("worker completion changed deterministic publication order")
		}
		// The window is frozen from original actions, not from delayed log reads.
		end, _ := time.Parse("2006-01-02 15:04:05-0700", row.WindowEnd)
		originalEnd, _ := time.Parse(time.RFC3339Nano, receipt.Actions[len(receipt.Actions)-1].Returned)
		if end.Before(originalEnd) || end.Sub(originalEnd) > time.Second {
			t.Fatal("query window did not bracket original failed requests")
		}
	}
}

func TestDetachLogPredicateQuotesWindowsImagePath(t *testing.T) {
	image := `C:\Users\runneradmin\AppData\Local\Temp\image path\writable.raw`
	c := newAttachmentDiagnostics(imageTestDisk(&fakeCommander{}), &Attachment{Image: image, Dev: "/dev/disk42"})
	logActionWindow(c)
	commands, _, err := c.logCommands(234)
	if err != nil {
		t.Fatal(err)
	}
	predicate := commands[1].Argv[len(commands[1].Argv)-1]
	want := `eventMessage CONTAINS[c] "C:\\Users\\runneradmin\\AppData\\Local\\Temp\\image path\\writable.raw"`
	if !strings.Contains(predicate, want) {
		t.Fatalf("Windows image path is not retained as one complete quoted literal: %q", predicate)
	}
}

func TestDetachLogWindowAndPredicateRemainBoundedAndLiteral(t *testing.T) {
	c := newAttachmentDiagnostics(imageTestDisk(&fakeCommander{}), &Attachment{Image: "/tmp/a \"quoted\" \\path/writable.raw", Dev: "/dev/disk42"})
	start := time.Date(2026, 10, 24, 21, 42, 0, 123, time.UTC)
	c.actions = []detachOperationEvidence{{Started: start.Format(time.RFC3339Nano), Returned: start.Add(2 * time.Minute).Format(time.RFC3339Nano)}}
	commands, rows, err := c.logCommands(234)
	if err != nil || len(commands) != 2 || !rows[0].WindowClamped || rows[0].WindowStart != "2026-10-24 21:43:01+0000" || rows[0].WindowEnd != "2026-10-24 21:44:01+0000" {
		t.Fatalf("window was extended or unbounded: %+v %v", rows, err)
	}
	predicate := commands[1].Argv[len(commands[1].Argv)-1]
	if !strings.Contains(predicate, `"/tmp/a \"quoted\" \\path/writable.raw"`) || !strings.Contains(predicate, `"disk42"`) {
		t.Fatalf("native path escaped the literal predicate: %q", predicate)
	}
}

func TestDetachLogsRecordUnknownBindingsAndCancelledScopesWithoutCommands(t *testing.T) {
	for _, state := range []string{"unknown-binding", "missing-pid", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			var calls atomic.Int32
			disk := imageTestDisk(discoveryCommandFunc(func(context.Context, Command) Result { calls.Add(1); return Result{} }))
			c := newAttachmentDiagnostics(disk, &Attachment{Image: "/tmp/image.raw", Dev: "/dev/disk42"})
			logActionWindow(c)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("fresh owner unavailable")
			pid := 123
			var bindingErr error
			switch state {
			case "unknown-binding":
				bindingErr = cause
			case "missing-pid":
				pid = 0
			case "cancelled":
				cancel()
			}
			c.startLogs(ctx, pid, bindingErr)()
			if calls.Load() != 0 || c.err == nil || len(c.logs) != 2 || len(c.probes) != 2 {
				t.Fatalf("unknown state caused a native query or lost fixed scope: calls=%d err=%v", calls.Load(), c.err)
			}
			if state == "cancelled" && !errors.Is(c.err, context.Canceled) {
				t.Fatal("cancellation cause lost")
			}
			if state == "unknown-binding" && !errors.Is(c.err, cause) {
				t.Fatal("original binding cause lost")
			}
			for _, row := range c.logs {
				if row.Error == "" || disk.T.Commands[row.Command].Status != "launch-failed" {
					t.Fatalf("not-attempted scope looks successful: %+v", row)
				}
			}
		})
	}
}

func TestDetachLogWorkersCannotPublishLateOrMaskCancellation(t *testing.T) {
	started := make(chan struct{}, 2)
	release := make(chan struct{})
	done := make(chan struct{}, 2)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	disk := imageTestDisk(discoveryCommandFunc(func(context.Context, Command) Result {
		started <- struct{}{}
		<-release // deliberately violates Commander cancellation to test isolation
		defer func() { done <- struct{}{} }()
		return Result{Stdout: []byte("late result must not replace timeout")}
	}))
	c := newAttachmentDiagnostics(disk, &Attachment{Image: "/tmp/image.raw", Dev: "/dev/disk42"})
	logActionWindow(c)
	finish := c.startLogs(ctx, 123, nil)
	for range 2 {
		<-started
	}
	cancel()
	finish()
	before := slices.Clone(disk.T.Commands)
	if !errors.Is(c.err, context.Canceled) || len(before) != 2 {
		t.Fatal("cancelled reads did not produce exactly two bounded unknown results", c.err)
	}
	close(release)
	for range 2 {
		<-done
	}
	if !reflect.DeepEqual(disk.T.Commands, before) {
		t.Fatal("late worker published into the shared transcript")
	}
}

func TestDetachLogsShareRawAllowanceAndPreserveOriginalErrors(t *testing.T) {
	launch := errors.New("log launch denied")
	original := bytes.Repeat([]byte{0, 0xff, '\r', '\n'}, 4)
	disk := imageTestDisk(discoveryCommandFunc(func(context.Context, Command) Result { return Result{Status: -1, Err: launch, Stdout: original} }))
	c := newAttachmentDiagnostics(disk, &Attachment{Image: "/tmp/image.raw", Dev: "/dev/disk42"})
	logActionWindow(c)
	c.stored = busyEvidenceTotalLimit - 3
	c.startLogs(context.Background(), 123, nil)()
	if !errors.Is(c.err, launch) || !strings.Contains(c.err.Error(), "bounds") || c.stored != busyEvidenceTotalLimit {
		t.Fatal("launch/bounds causes or aggregate allowance lost", c.err)
	}
	if !bytes.Equal(c.probes[0].Stdout.Data, original[:3]) || c.probes[0].Stdout.Bytes != len(original) || c.probes[0].Stdout.SHA256 == c.probes[0].Stdout.StoredSHA256 || len(c.probes[1].Stdout.Data) != 0 {
		t.Fatal("full versus retained-prefix raw bindings changed")
	}
}

func TestNativeOwnershipRecorderPreservesParallelDelegateResultsAndUniqueFiles(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	commander := discoveryCommandFunc(func(_ context.Context, cmd Command) Result {
		entered <- struct{}{}
		<-release
		return Result{Stdout: []byte(cmd.Label), Stderr: []byte("stderr:" + cmd.Label)}
	})
	recorder := &ownershipEvidenceCommander{C: commander, Dir: t.TempDir(), Phase: "parallel-read-only-logs"}
	var wg sync.WaitGroup
	for _, label := range []string{"backend", "arbitration"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			recorder.Run(context.Background(), Command{Label: label, Argv: []string{"/usr/bin/log"}})
		}()
	}
	for range 2 {
		<-entered
	}
	close(release)
	wg.Wait()
	if recorder.Err != nil || len(recorder.Results) != 2 {
		t.Fatal("parallel results were lost", recorder.Err)
	}
	for i, row := range recorder.Results {
		raw, err := os.ReadFile(filepath.Join(recorder.Dir, filepath.FromSlash(row.Stdout.File)))
		if err != nil || string(raw) != row.Label || row.Sequence != i || row.Stdout.StoredSHA256 != row.Stdout.SHA256 || row.Phase != "parallel-read-only-logs" {
			t.Fatalf("parallel recorder reused ordinal/file or changed bytes: %s, %v", fmt.Sprint(row), err)
		}
	}
}

func TestTimedOutLogWorkersCannotPublishNativeRecorderFilesOrChangePhase(t *testing.T) {
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	finished := make(chan struct{}, 2)
	delegate := discoveryCommandFunc(func(context.Context, Command) Result {
		entered <- struct{}{}
		<-release
		defer func() { finished <- struct{}{} }()
		return Result{Stdout: []byte("late native bytes")}
	})
	recorder := &ownershipEvidenceCommander{C: delegate, Dir: t.TempDir(), Phase: "original-detach"}
	// Exercise the actual Detach observer's seam forwarding too.
	disk := imageTestDisk(recorder)
	c := newAttachmentDiagnostics(disk, &Attachment{Image: "/tmp/image.raw", Dev: "/dev/disk42"})
	disk.C = &detachOperationCommander{delegate: recorder, evidence: c}
	logActionWindow(c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	merge := c.startLogs(ctx, 123, nil)
	for range 2 {
		<-entered
	}
	if len(recorder.Results) != 0 {
		t.Fatal("a worker published before foreground merge")
	}
	cancel()
	merge()
	if !errors.Is(c.err, context.Canceled) || len(recorder.Results) != 2 {
		t.Fatal("deadline outcomes missing", c.err)
	}
	for _, row := range recorder.Results {
		if row.Phase != "original-detach" || row.Status != -1 || !strings.Contains(row.Error, "invoked; outcome unavailable") {
			t.Fatalf("unknown invocation was mislabelled: %+v", row)
		}
	}
	for _, probe := range c.probes {
		if probe.Started == "" || probe.Returned != "" || probe.Observed == "" || !strings.Contains(probe.Error, "invoked; outcome unavailable") {
			t.Fatal("actual caller start or unknown-result distinction was lost")
		}
	}
	before, err := json.Marshal(recorder.Results)
	if err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(filepath.Join(recorder.Dir, "command-results"))
	if err != nil || len(files) != 4 {
		t.Fatal("timeout stream files missing", err)
	}
	recorder.Phase = "after-detach-snapshot"
	close(release)
	for range 2 {
		<-finished
	}
	// A delegate may finish after return; it has no recorder or publisher, only
	// a local channel. Reading Phase/Results/Err here must remain race-safe.
	after, err := json.Marshal(recorder.Results)
	if err != nil || !bytes.Equal(before, after) || recorder.Phase != "after-detach-snapshot" || recorder.Err != nil {
		t.Fatal("late worker altered native recorder publication", err, recorder.Err)
	}
	for _, row := range recorder.Results {
		for _, stream := range []ownershipStreamEvidence{row.Stdout, row.Stderr} {
			raw, err := os.ReadFile(filepath.Join(recorder.Dir, filepath.FromSlash(stream.File)))
			if err != nil || len(raw) != 0 {
				t.Fatal("late original bytes replaced unknown outcome files", err)
			}
		}
	}
}

func TestNativeRecorderForegroundLogPublicationKeepsFullAndRetainedBindingsDistinct(t *testing.T) {
	original := bytes.Repeat([]byte{0, 0xff, '\r', '\n'}, 4)
	recorder := &ownershipEvidenceCommander{C: discoveryCommandFunc(func(context.Context, Command) Result { return Result{Stdout: original, Status: 7} }), Dir: t.TempDir(), Phase: "query-invocation"}
	disk := imageTestDisk(recorder)
	c := newAttachmentDiagnostics(disk, &Attachment{Image: "/tmp/image.raw", Dev: "/dev/disk42"})
	logActionWindow(c)
	c.stored = busyEvidenceTotalLimit - 3
	merge := c.startLogs(context.Background(), 123, nil)
	recorder.Phase = "later-foreground-phase"
	merge()
	if c.err == nil || recorder.Err == nil || len(recorder.Results) != 2 {
		t.Fatal("incomplete retention was silently published", c.err, recorder.Err)
	}
	first := recorder.Results[0]
	raw, err := os.ReadFile(filepath.Join(recorder.Dir, filepath.FromSlash(first.Stdout.File)))
	if err != nil || first.Phase != "query-invocation" || first.Status != 7 || first.Stdout.Bytes != len(original) || first.Stdout.StoredBytes != 3 || first.Stdout.SHA256 == first.Stdout.StoredSHA256 || first.Stdout.RetentionError == "" || !bytes.Equal(raw, original[:3]) {
		t.Fatalf("truncated bytes were presented as original outcome/phase: %+v, %v", first, err)
	}
}

func TestDiagnosticInvocationGateSealsBeforeWorkerCanStart(t *testing.T) {
	var calls atomic.Int32
	commander := discoveryCommandFunc(func(context.Context, Command) Result { calls.Add(1); return Result{} })
	gate := &diagnosticInvocationGate{}
	if started := gate.seal(); started != "" {
		t.Fatal("uninvoked gate invented a start")
	}
	cmd := Command{Label: "busy-detach-backend-log", Argv: []string{"/usr/bin/log", "show"}, Expected: "record"}
	// This is the exact post-context-check scheduling gap: the gate was sealed
	// before a resumed worker could atomically claim its invocation.
	result := readDetachLog(context.Background(), commander, cmd, nil, gate)
	if calls.Load() != 0 || result.probe.Started != "" || result.probe.Returned != "" || result.probe.Observed == "" || result.err == nil {
		t.Fatal("abandoned worker ran or fabricated invocation bounds", result.err)
	}
}

func TestDiagnosticInvocationGateRecordsStartWithoutHoldingNativeCall(t *testing.T) {
	gate := &diagnosticInvocationGate{}
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan detachLogResult, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	commander := discoveryCommandFunc(func(context.Context, Command) Result { close(entered); <-release; return Result{} })
	cmd := Command{Label: "busy-detach-backend-log", Argv: []string{"/usr/bin/log", "show"}, Expected: "record"}
	go func() { done <- readDetachLog(ctx, commander, cmd, nil, gate) }()
	<-entered
	cancel()
	// This must not wait for the native delegate or hold a publication lock.
	started := gate.seal()
	if started == "" {
		t.Fatal("active caller invocation was lost")
	}
	close(release)
	result := <-done
	if result.probe.Started != started || result.probe.Returned == "" || !errors.Is(result.err, context.Canceled) {
		t.Fatal("completed original caller bounds/cancellation changed", result.err)
	}
}
