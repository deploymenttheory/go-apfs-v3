package fixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// These are retained, read-only observations. A finished/empty, redacted,
// failed or timed-out log query never establishes approval or release.
type detachLogEvidence struct {
	Scope         string
	Command       int
	BackendPID    int
	WindowStart   string
	WindowEnd     string
	WindowClamped bool
	Outcome       string
	Error         string `json:",omitempty"`
}

type detachLogResult struct {
	// Scalar native outcome only. Prefix bytes never masquerade as full Result streams.
	result  Result
	command schema.Command
	probe   attachmentDiagnosticProbe
	err     error
}

// Recording wrappers may separate cancellation-safe execution from publication.
// The foreground freezes wrapper phase before launch and alone publishes accepted
// results, including explicit unknown outcomes. An abandoned worker has no shared
// recorder or file publication capability.
type diagnosticReadSource interface {
	prepareDiagnosticRead() (Commander, func(Command, detachLogResult) error)
}

func prepareDiagnosticRead(c Commander) (Commander, func(Command, detachLogResult) error) {
	if source, ok := c.(diagnosticReadSource); ok {
		return source.prepareDiagnosticRead()
	}
	return c, nil
}

// The gate linearizes invocation with deadline sealing. A worker which loses
// the gate can never start a read after the foreground reports not-attempted.
// It is never held while a native call runs or a result is retained.
type diagnosticInvocationGate struct {
	mu      sync.Mutex
	sealed  bool
	started string
}

func (g *diagnosticInvocationGate) begin(ctx context.Context) (string, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.sealed || g.started != "" || ctx.Err() != nil {
		return "", false
	}
	g.started = time.Now().UTC().Format(time.RFC3339Nano)
	return g.started, true
}
func (g *diagnosticInvocationGate) seal() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.sealed = true
	return g.started
}

// Start both fixed reads without consuming the foreground device/holder probes'
// scheduling budget. Commander implementations on this path must allow parallel
// read-only calls, honor context cancellation, and return independently owned
// result buffers. Workers never touch the shared transcript or retention state.
func (c *attachmentDiagnostics) startLogs(ctx context.Context, pid int, bindingErr error) func() {
	commands, rows, err := c.logCommands(pid)
	err = errors.Join(err, bindingErr)
	type pending struct {
		ctx     context.Context
		cancel  context.CancelFunc
		done    chan detachLogResult
		gate    *diagnosticInvocationGate
		publish func(Command, detachLogResult) error
	}
	jobs := make([]pending, len(commands))
	for i, command := range commands {
		jobCtx, cancel := context.WithTimeout(ctx, busyProbeTimeout)
		delegate, publish := prepareDiagnosticRead(c.disk.C)
		jobs[i] = pending{ctx: jobCtx, cancel: cancel, done: make(chan detachLogResult, 1), gate: &diagnosticInvocationGate{}, publish: publish}
		job := jobs[i]
		if err != nil || jobCtx.Err() != nil {
			job.done <- readDetachLog(jobCtx, nil, command, errors.Join(err, jobCtx.Err()), nil)
			continue
		}
		go func() { job.done <- readDetachLog(jobCtx, delegate, command, nil, job.gate) }()
	}
	return func() {
		// Publish in scope order, independent of native completion order. One shared
		// raw-byte allowance includes original actions, mandatory scopes and logs.
		for i, job := range jobs {
			var result detachLogResult
			select {
			case result = <-job.done:
			case <-job.ctx.Done():
				select {
				case result = <-job.done:
				default:
					started := job.gate.seal()
					reason := "diagnostic log not attempted before deadline"
					if started != "" {
						reason = "diagnostic log invoked; outcome unavailable before deadline"
					}
					result = freezeDetachLog(job.ctx, commands[i], Result{Status: -1, Err: fmt.Errorf("%s: %w", reason, job.ctx.Err())}, started, "")
				}
			}
			job.gate.seal()
			job.cancel()
			result.probe.Stdout = c.retainLogStream(result.probe.Stdout)
			result.probe.Stderr = c.retainLogStream(result.probe.Stderr)
			if job.publish != nil {
				c.err = errors.Join(c.err, job.publish(commands[i], result))
			}
			index := len(c.disk.T.Commands)
			c.disk.T.Commands = append(c.disk.T.Commands, result.command)
			result.probe.Command = index
			c.probes = append(c.probes, result.probe)
			rows[i].Command, rows[i].Error = index, result.probe.Error
			rows[i].Outcome = "returned"
			if result.probe.Returned == "" {
				rows[i].Outcome = "not-attempted"
				if result.probe.Started != "" {
					rows[i].Outcome = "outcome-unavailable"
				}
			}
			c.logs = append(c.logs, rows[i])
			c.err = errors.Join(c.err, result.err)
		}
	}
}

func readDetachLog(ctx context.Context, commander Commander, cmd Command, unavailable error, gate *diagnosticInvocationGate) detachLogResult {
	started := ""
	var result Result
	if unavailable != nil || ctx.Err() != nil || commander == nil {
		result = Result{Status: -1, Err: fmt.Errorf("diagnostic log not attempted: %w", errors.Join(unavailable, ctx.Err()))}
	} else {
		var allowed bool
		started, allowed = gate.begin(ctx)
		if !allowed {
			result = Result{Status: -1, Err: errors.Join(errors.New("diagnostic log invocation sealed before start"), ctx.Err())}
		} else {
			result = commander.Run(ctx, cmd)
		}
	}
	returned := ""
	if started != "" {
		returned = time.Now().UTC().Format(time.RFC3339Nano)
	}
	return freezeDetachLog(ctx, cmd, result, started, returned)
}

func freezeDetachLog(ctx context.Context, cmd Command, result Result, started, returned string) detachLogResult {
	local := &Transcript{}
	err := errors.Join(local.Record(cmd, result), ctx.Err())
	probe := attachmentDiagnosticProbe{Started: started, Returned: returned, Stdout: detachedLogStream(result.Stdout), Stderr: detachedLogStream(result.Stderr)}
	if deadline, ok := ctx.Deadline(); ok {
		probe.Deadline = deadline.UTC().Format(time.RFC3339Nano)
	}
	if returned == "" {
		probe.Observed = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if err != nil {
		probe.Error = err.Error()
	}
	result.Stdout, result.Stderr = nil, nil
	return detachLogResult{result: result, command: local.Commands[0], probe: probe, err: err}
}

// Freeze a worker's retained prefix and full digest before its Result can be
// reused. This is an 8 MiB raw-retention bound, not an Exec-memory/JSON bound.
func detachedLogStream(raw []byte) attachmentDiagnosticStream {
	data := bytes.Clone(raw[:min(len(raw), busyEvidenceStreamLimit)])
	return attachmentDiagnosticStream{Bytes: len(raw), SHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), StoredSHA256: fmt.Sprintf("%x", sha256.Sum256(data)), Data: data}
}

func (c *attachmentDiagnostics) retainLogStream(stream attachmentDiagnosticStream) attachmentDiagnosticStream {
	keep := min(len(stream.Data), busyEvidenceTotalLimit-c.stored)
	stream.Data = stream.Data[:keep]
	c.stored += keep
	stream.StoredSHA256 = fmt.Sprintf("%x", sha256.Sum256(stream.Data))
	if keep != stream.Bytes {
		c.err = errors.Join(c.err, fmt.Errorf("busy attachment diagnostic log stream exceeded bounds: retained %d of %d bytes", keep, stream.Bytes))
	}
	return stream
}

func (c *attachmentDiagnostics) logCommands(pid int) ([]Command, []detachLogEvidence, error) {
	var start, end time.Time
	var err error
	if len(c.actions) == 0 {
		err = errors.New("detach log window unavailable: no original action interval")
	} else {
		start, err = time.Parse(time.RFC3339Nano, c.actions[0].Started)
		last, parseErr := time.Parse(time.RFC3339Nano, c.actions[len(c.actions)-1].Returned)
		end, err = last, errors.Join(err, parseErr)
		if end.Before(start) {
			err = errors.Join(err, errors.New("detach log action interval is reversed"))
		}
	}
	if !c.started.IsZero() {
		start = c.started
		if end.Before(start) {
			err = errors.Join(err, errors.New("detach return predates caller entry"))
		}
	}
	start = start.Add(-2 * time.Second).Truncate(time.Second)
	// log(1) documents whole-second date strings. Round outward so the requested
	// window contains the original invocation/return, then explicitly cap it.
	if end.Nanosecond() != 0 {
		end = end.Truncate(time.Second).Add(time.Second)
	}
	clamped := end.Sub(start) > time.Minute
	if clamped {
		start = end.Add(-time.Minute)
	}
	if pid <= 0 {
		err = errors.Join(err, errors.New("detach log backend PID has no positive fresh image binding"))
	}
	device := strings.TrimPrefix(c.attachment.Dev, "/dev/")
	if !registryBSDName(device) {
		err = errors.Join(err, errors.New("detach log target BSD identity is invalid"))
	}
	const format = "2006-01-02 15:04:05-0700"
	base := []string{"/usr/bin/log", "show", "--style", "ndjson", "--info", "--debug", "--start", start.UTC().Format(format), "--end", end.UTC().Format(format)}
	predicate := `(process == "diskarbitrationd") OR ((process == "hdiutil" OR process == "kernel") AND (eventMessage CONTAINS[c] ` + strconv.Quote(device) + ` OR eventMessage CONTAINS[c] ` + strconv.Quote(c.attachment.Image) + `))`
	commands := []Command{
		{Label: "busy-detach-backend-log", Argv: append(append([]string(nil), base...), "--process", strconv.Itoa(pid)), Timeout: busyProbeTimeout, Expected: "record"},
		{Label: "busy-detach-arbitration-log", Argv: append(append([]string(nil), base...), "--predicate", predicate), Timeout: busyProbeTimeout, Expected: "record"},
	}
	rows := make([]detachLogEvidence, len(commands))
	for i, command := range commands {
		rows[i] = detachLogEvidence{Scope: command.Label, BackendPID: pid, WindowStart: start.UTC().Format(format), WindowEnd: end.UTC().Format(format), WindowClamped: clamped}
	}
	return commands, rows, err
}
