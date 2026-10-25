package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

const ejectTraceSeconds = 6

// An OFF preflight is an observation, not atomic admission: another tool can
// acquire background tracing before fs_usage starts. Never reset/take over a
// reported active/unknown session. Protected-daemon visibility stays unknown
// until the exact raw-path/FD/eject chain is actually captured.
type ejectTraceEvidence struct {
	State                                 string
	Reason                                string `json:",omitempty"`
	AfterCommand                          int
	Admission                             string
	DaemonPID                             int
	PreflightCommands                     []int
	Command                               *int `json:",omitempty"`
	RequestedSeconds                      int
	Started, Returned, Deadline, Observed string
	StopReason                            string `json:",omitempty"`
	StopRequested                         string `json:",omitempty"`
	OutputComplete                        bool
	RawTargets                            []string
	ToolSHA256                            map[string]string
	ToolErrors                            []string `json:",omitempty"`
	LocalDate, LocalZone                  string
	UTCOffsetSeconds                      int
	Coverage                              []ejectTraceCoverage
	Availability                          string
}

type ejectTraceRead struct {
	cmd    Command
	result detachLogResult
}
type ejectTraceAnswer struct {
	evidence ejectTraceEvidence
}
type ejectTraceJob struct {
	ctx     context.Context
	cancel  context.CancelFunc
	done    chan ejectTraceAnswer
	gates   [3]diagnosticInvocationGate
	reads   chan ejectTraceRead
	publish func(Command, detachLogResult) error
}

func (c *attachmentDiagnostics) startEjectTrace(ctx context.Context, after int, targets ...string) {
	if c.ejectTrace != nil {
		return
	}
	if len(targets) == 0 {
		targets = []string{strings.Replace(c.attachment.Dev, "/dev/disk", "/dev/rdisk", 1)}
	}
	now := time.Now().UTC()
	zone, offset := now.Zone()
	ev := ejectTraceEvidence{State: "pending", AfterCommand: after, RequestedSeconds: ejectTraceSeconds, RawTargets: append([]string(nil), targets...), Availability: "unknown", LocalDate: now.Format("2006-01-02"), LocalZone: zone, UTCOffsetSeconds: offset}
	c.ejectTrace = &ev
	guard := c.disk.ejectTraceGuard
	if guard == nil {
		guard = RequireDisposableHost
	}
	if err := guard(); err != nil {
		ev.State, ev.Admission, ev.Reason = "skipped", "host-refused", err.Error()
		return
	}
	child, cancel := context.WithTimeout(ctx, busyProbeTimeout)
	delegate, publish := prepareDiagnosticRead(c.disk.C)
	job := &ejectTraceJob{ctx: child, cancel: cancel, done: make(chan ejectTraceAnswer, 1), reads: make(chan ejectTraceRead, 3), publish: publish}
	c.ejectJob = job
	go func(evidence ejectTraceEvidence) { job.done <- runEjectTrace(child, delegate, job, evidence) }(ev)
}

func runEjectTrace(ctx context.Context, commander Commander, job *ejectTraceJob, evidence ejectTraceEvidence) ejectTraceAnswer {
	answer := ejectTraceAnswer{evidence: evidence}
	answer.evidence.Deadline = deadlineText(ctx)
	readIndex := 0
	read := func(label string, sudo bool, argv ...string) detachLogResult {
		cmd := Command{Label: label, Argv: argv, Sudo: sudo, Timeout: busyProbeTimeout, Expected: "record"}
		result := readDetachLog(ctx, commander, cmd, nil, &job.gates[readIndex])
		readIndex++
		job.reads <- ejectTraceRead{cmd, result}
		return result
	}
	// XNU ktrace.state is a read-only integer: OFF=0, FG=1, BG=2.
	// Exact source: f6217f891ac0bb64f3d375211650a4c1ff8ca1ea,
	// bsd/kern/kern_ktrace.c and bsd/sys/ktrace.h. No configuration writes.
	state := read("busy-eject-trace-state", false, "/usr/sbin/sysctl", "-n", "ktrace.state")
	if state.result.Err != nil || state.result.Status != 0 || state.probe.Stdout.Bytes > 64 || strings.TrimSpace(string(state.probe.Stdout.Data)) != "0" {
		answer.evidence.State, answer.evidence.Admission, answer.evidence.Reason = "skipped", "active-or-unknown", "ktrace state is not a successful exact OFF observation"
		return answer
	}
	pidRead := read("busy-eject-daemon-pid", false, "/usr/bin/pgrep", "-x", "diskarbitrationd")
	pid, err := ejectDaemonPID(pidRead)
	if err != nil {
		answer.evidence.State, answer.evidence.Admission, answer.evidence.Reason = "skipped", "pid-unknown", err.Error()
		return answer
	}
	answer.evidence.DaemonPID = pid
	answer.evidence.Admission = "off-observed-nonatomic"
	answer.evidence.ToolSHA256 = map[string]string{}
	for _, path := range []string{"/usr/bin/env", "/usr/bin/fs_usage", "/usr/sbin/sysctl", "/usr/bin/pgrep"} {
		info, err := os.Stat(path)
		if err == nil && (!info.Mode().IsRegular() || info.Size() > busyEvidenceStreamLimit) {
			err = errors.New("tool identity outside small regular-file bound")
		}
		var digest string
		if err == nil {
			digest, err = schema.FileDigest(path)
		}
		if err != nil {
			answer.evidence.ToolErrors = append(answer.evidence.ToolErrors, path+": "+err.Error())
		} else {
			answer.evidence.ToolSHA256[path] = digest
		}
	}
	cmd := Command{Label: "busy-eject-fs-usage", Argv: []string{"/usr/bin/env", "TZ=UTC", "/usr/bin/fs_usage", "-w", "-f", "filesys", "-t", strconv.Itoa(ejectTraceSeconds), strconv.Itoa(pid)}, Sudo: true, Timeout: busyProbeTimeout, Expected: "record"}
	result := readDetachLog(ctx, commander, cmd, nil, &job.gates[2])
	job.reads <- ejectTraceRead{cmd, result}
	answer.evidence.Started, answer.evidence.Returned = result.probe.Started, result.probe.Returned
	answer.evidence.State = "returned"
	if result.probe.Started == "" {
		answer.evidence.State = "not-invoked"
	} else if result.probe.Returned == "" {
		answer.evidence.State = "outcome-unavailable"
	}
	if result.result.Err != nil || result.result.Status != 0 {
		answer.evidence.Reason = "trace outcome unavailable or unsuccessful"
	}
	return answer
}

func ejectDaemonPID(result detachLogResult) (int, error) {
	text := strings.TrimSpace(string(result.probe.Stdout.Data))
	if result.result.Err != nil || result.result.Status != 0 || result.probe.Stdout.Bytes > 64 || text == "" {
		return 0, errors.New("no successful unique daemon PID observation")
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return 0, errors.New("daemon PID observation is not one numeric PID")
		}
	}
	pid, err := strconv.ParseInt(text, 10, 32)
	if err != nil || pid <= 0 {
		return 0, errors.New("daemon PID is outside positive native range")
	}
	return int(pid), nil
}

func deadlineText(ctx context.Context) string {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline.UTC().Format(time.RFC3339Nano)
	}
	return ""
}

// Waiting is allowed only for exhausted failure evidence (inside its existing
// deadline) or the explicit two-image visibility control. A recovered/terminal
// ordinary operation stops and polls without waiting for the six-second reader.
func (c *attachmentDiagnostics) finishEjectTrace(ctx context.Context, wait bool, reason string) {
	if c.ejectTrace == nil {
		return
	}
	if c.ejectJob == nil {
		c.recordEjectTrace()
		return
	}
	job := c.ejectJob
	var answer ejectTraceAnswer
	known := false
	stopRequested := ""
	if ctx.Err() != nil {
		reason = "caller-cancelled: " + ctx.Err().Error()
	}
	if !wait {
		job.seal()
		stopRequested = time.Now().UTC().Format(time.RFC3339Nano)
		job.cancel()
	}
	if wait {
		select {
		case answer = <-job.done:
			known = true
		case <-ctx.Done():
		case <-job.ctx.Done():
		}
	}
	if !known {
		select {
		case answer = <-job.done:
			known = true
		default:
		}
	}
	started := job.seal()
	if stopRequested == "" {
		stopRequested = time.Now().UTC().Format(time.RFC3339Nano)
	}
	job.cancel()
	if known {
		answer.evidence.StopReason = reason
		c.ejectTrace = &answer.evidence
	}
	// Only the foreground can publish completed reads. A late worker can send
	// at most three local results; it has no shared recorder/transcript access.
	for {
		select {
		case read := <-job.reads:
			result := read.result
			result.probe.Stdout = c.retainLogStream(result.probe.Stdout)
			result.probe.Stderr = c.retainLogStream(result.probe.Stderr)
			if job.publish != nil {
				c.err = errors.Join(c.err, job.publish(read.cmd, result))
			}
			index := len(c.disk.T.Commands)
			c.disk.T.Commands = append(c.disk.T.Commands, result.command)
			result.probe.Command = index
			c.probes = append(c.probes, result.probe)
			if read.cmd.Label == "busy-eject-fs-usage" {
				c.ejectTrace.Command = &index
				c.ejectTrace.Started, c.ejectTrace.Returned = result.probe.Started, result.probe.Returned
				c.ejectTrace.Deadline = result.probe.Deadline
				c.ejectTrace.State = "returned"
				if result.probe.Started == "" {
					c.ejectTrace.State = "not-invoked"
				} else if result.probe.Returned == "" {
					c.ejectTrace.State = "outcome-unavailable"
				}
				c.ejectTrace.OutputComplete = result.err == nil && result.result.Err == nil && result.result.Status == 0 && len(result.probe.Stdout.Data) == result.probe.Stdout.Bytes && len(result.probe.Stderr.Data) == result.probe.Stderr.Bytes && result.probe.Stderr.Bytes == 0
				for _, target := range c.ejectTrace.RawTargets {
					coverage, err := inspectEjectTrace(result.probe.Stdout.Data, target)
					c.ejectTrace.Coverage = append(c.ejectTrace.Coverage, coverage)
					if err != nil {
						c.ejectTrace.Reason = err.Error()
					}
				}
			} else {
				c.ejectTrace.PreflightCommands = append(c.ejectTrace.PreflightCommands, index)
			}
		default:
			goto merged
		}
	}
merged:
	if !known && c.ejectTrace.Command == nil {
		c.ejectTrace.State = "outcome-unavailable"
		if started == "" {
			c.ejectTrace.State = "not-invoked"
		}
		c.ejectTrace.Started = started
		c.ejectTrace.Returned = ""
		c.ejectTrace.Deadline = deadlineText(job.ctx)
		c.ejectTrace.Reason = "observer output/status not available at foreground stop"
	}
	c.ejectTrace.StopRequested = stopRequested
	c.ejectTrace.StopReason = reason
	c.ejectTrace.Observed = time.Now().UTC().Format(time.RFC3339Nano)
	c.qualifyEjectCoverage()
	c.recordEjectTrace()
}

func (c *attachmentDiagnostics) recordEjectTrace() {
	data, err := json.Marshal(c.ejectTrace)
	c.err = errors.Join(c.err, err)
	c.err = errors.Join(c.err, c.disk.T.RecordFS("busy-eject-observation", []string{"observation", "fs_usage"}, err, "record"))
	entry := &c.disk.T.Commands[len(c.disk.T.Commands)-1]
	entry.StdoutSHA256, entry.StdoutText = digestAndText(data)
}

// Availability describes only the positively observed target lifecycles. It is
// never a claim that every daemon event or every target attempt was visible.
func (c *attachmentDiagnostics) qualifyEjectCoverage() {
	e := c.ejectTrace
	e.Availability = "unknown"
	if e.Admission != "off-observed-nonatomic" || e.DaemonPID <= 0 {
		e.Reason = "final OFF/PID admission metadata unavailable"
		return
	}
	if !e.OutputComplete || e.Started == "" || e.Returned == "" || len(e.Coverage) != len(e.RawTargets) || len(e.Coverage) == 0 {
		return
	}
	start, sErr := time.Parse(time.RFC3339Nano, e.Started)
	end, eErr := time.Parse(time.RFC3339Nano, e.Returned)
	if sErr != nil || eErr != nil || end.Before(start) {
		e.Reason = "observer wall-clock interval cannot be correlated"
		return
	}
	deadline, dErr := time.Parse(time.RFC3339Nano, e.Deadline)
	if dErr != nil || end.After(deadline) {
		e.Reason = "observer return is outside its declared deadline"
		return
	}
	for _, coverage := range e.Coverage {
		if !coverage.Complete {
			return
		}
		positive := false
		for _, attempt := range coverage.Attempts {
			if attempt.OpenErrno != 0 || attempt.EjectTime == "" || attempt.CloseTime == "" {
				continue
			}
			a, ok1 := e.correlateTime(attempt.OpenTime, start, end)
			b, ok2 := e.correlateTime(attempt.EjectTime, start, end)
			d, ok3 := e.correlateTime(attempt.CloseTime, start, end)
			if ok1 && ok2 && ok3 && !b.Before(a) && !d.Before(b) {
				positive = true
			}
		}
		if !positive {
			e.Reason = "target lifecycle date/time is not unambiguously inside the observer interval"
			return
		}
	}
	e.Availability = "observed-target-lifecycles"
}

func (e *ejectTraceEvidence) correlateTime(clock string, start, end time.Time) (time.Time, bool) {
	if end.Before(start) || end.Sub(start) >= 24*time.Hour {
		return time.Time{}, false
	}
	zone := time.FixedZone(e.LocalZone, e.UTCOffsetSeconds)
	date, err := time.ParseInLocation("2006-01-02", e.LocalDate, zone)
	if err != nil {
		return time.Time{}, false
	}
	var found time.Time
	matches := 0
	for _, day := range []int{-1, 0, 1} {
		candidate, err := time.ParseInLocation("2006-01-02 15:04:05.000000", date.AddDate(0, 0, day).Format("2006-01-02")+" "+clock, zone)
		if err == nil && !candidate.Before(start) && !candidate.After(end) {
			found = candidate
			matches++
		}
	}
	return found, matches == 1
}

// Seal every fixed invocation before cancellation. A preflight which has not
// begun can never start after the foreground describes it as unobserved.
func (job *ejectTraceJob) seal() string {
	for i := range job.gates {
		job.gates[i].seal()
	}
	return job.gates[2].seal()
}
