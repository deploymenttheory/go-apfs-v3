package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

type priorUnmountIdentity struct {
	Identity   mountIdentity
	Command    int
	transcript *Transcript
}

// priorUnmountObservation describes a former private mount pin at failure
// time. An enclosing filesystem is evidence about that path only, never proof
// that an image is detached or that it has no mounts elsewhere.
type priorUnmountObservation struct {
	UnmountCommand int
	// UnmountCommand is local to the original transcript. Only "current"
	// permits applying this receipt's transcript offset to that ordinal.
	UnmountTranscript string
	Command           int
	CanonicalPin      string
	Expected          mountIdentity
	Actual            mountIdentity
	// Started/Returned bracket the actual probe invocation. Returned remains
	// empty when the observation has not returned before foreground sealing.
	Started  string
	Returned string
	Deadline string
	Outcome  string
	Error    string `json:",omitempty"`
}

// observePriorUnmounts runs only in the exhausted-detach diagnostic collector.
// Its saved pins are independent of diskutil's later Mounted flag. No result
// changes cleanup authority, action budgets, or the original fatal verdict.
func (c *attachmentDiagnostics) observePriorUnmounts(ctx context.Context) func() {
	type result struct {
		row priorUnmountObservation
		err error
	}
	type pending struct {
		saved  priorUnmountIdentity
		ctx    context.Context
		cancel context.CancelFunc
		done   chan result
		gate   *diagnosticInvocationGate
	}
	probe := c.disk.mountProbe
	if probe == nil {
		probe = mountedFilesystem
	}
	var jobs []pending
	for _, volume := range c.attachment.Volumes {
		if volume == nil || volume.priorUnmount == nil {
			continue
		}
		if len(jobs) == busyEvidenceTargets {
			c.err = errors.Join(c.err, errors.New("prior unmount evidence exceeds target bound"))
			break
		}
		jobCtx, cancel := context.WithTimeout(ctx, busyProbeTimeout)
		job := pending{saved: *volume.priorUnmount, ctx: jobCtx, cancel: cancel, done: make(chan result, 1), gate: &diagnosticInvocationGate{}}
		jobs = append(jobs, job)
		go func() {
			row, err := probePriorUnmount(job.ctx, probe, job.saved, job.gate)
			job.done <- result{row, err}
		}()
	}
	return func() {
		// The original device/holder scopes have already run. Publish in
		// attachment order; workers never write transcript or receipt state.
		for _, job := range jobs {
			var answer result
			select {
			case answer = <-job.done:
			case <-job.ctx.Done():
				started := job.gate.seal()
				select {
				case answer = <-job.done:
				default:
					answer.row = pendingPriorUnmountObservation(job.ctx, job.saved)
					answer.row.Started = started
					answer.err = errors.Join(errors.New("prior unmount observation outcome unavailable before deadline"), job.ctx.Err())
					answer.row.Error = answer.err.Error()
				}
			}
			job.gate.seal()
			job.cancel()
			row, err := c.disk.recordPriorUnmount(answer.row, job.saved, answer.err)
			c.priorUnmounts = append(c.priorUnmounts, row)
			c.err = errors.Join(c.err, err)
		}
	}
}

func pendingPriorUnmountObservation(ctx context.Context, saved priorUnmountIdentity) priorUnmountObservation {
	row := priorUnmountObservation{UnmountCommand: saved.Command, CanonicalPin: saved.Identity.MountPoint, Expected: saved.Identity, Outcome: "unavailable"}
	if deadline, ok := ctx.Deadline(); ok {
		row.Deadline = deadline.UTC().Format(time.RFC3339Nano)
	}
	return row
}

// probePriorUnmount owns no transcript or collector state. Its single worker
// may outlive the existing diagnostic deadline, but cannot publish late facts.
func probePriorUnmount(ctx context.Context, probe func(string) (mountIdentity, error), saved priorUnmountIdentity, gate *diagnosticInvocationGate) (priorUnmountObservation, error) {
	pin := saved.Identity.MountPoint
	row := pendingPriorUnmountObservation(ctx, saved)
	var err error
	if err = ctx.Err(); err == nil && probe == nil {
		err = errors.New("prior unmount observation was not attempted")
	}
	if err == nil {
		var allowed bool
		row.Started, allowed = gate.begin(ctx)
		if !allowed {
			err = errors.Join(errors.New("prior unmount observation invocation sealed before start"), ctx.Err())
		} else {
			row.Actual, err = probe(pin)
			row.Returned = time.Now().UTC().Format(time.RFC3339Nano)
		}
	}
	err = errors.Join(err, ctx.Err())
	if err == nil {
		actual := row.Actual
		if !filepath.IsAbs(actual.MountPoint) || strings.ContainsRune(actual.MountPoint, 0) || actual.Source == "" || strings.ContainsRune(actual.Source, 0) || actual.FSID == [2]int32{} {
			err = errors.New("prior unmount diagnostic returned an incomplete kernel mount identity")
		} else {
			switch {
			case actual == saved.Identity:
				row.Outcome = "same"
			case actual.MountPoint == pin:
				row.Outcome = "changed"
			default:
				rel, relErr := filepath.Rel(actual.MountPoint, pin)
				if relErr == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel) {
					row.Outcome = "enclosing"
				} else if actual.FSID != saved.Identity.FSID {
					// A different filesystem observed at this pin need not have
					// a lexically enclosing mountpoint. This is no release proof.
					row.Outcome = "different-filesystem"
				} else {
					err = errors.New("prior unmount diagnostic returned neither the exact pin nor an enclosing filesystem")
				}
			}
		}
	}
	if contextErr := ctx.Err(); contextErr != nil {
		err, row.Outcome = errors.Join(err, contextErr), "unavailable"
	}
	if err != nil {
		row.Error = err.Error()
	}
	return row, err
}

func (d *HostDisk) recordPriorUnmount(row priorUnmountObservation, saved priorUnmountIdentity, err error) (priorUnmountObservation, error) {
	row.UnmountTranscript = "prior"
	switch saved.transcript {
	case nil:
		row.UnmountTranscript = "unknown"
	case d.T:
		row.UnmountTranscript = "current"
	}
	row.Command = len(d.T.Commands)
	data, marshalErr := json.Marshal(row)
	err = errors.Join(err, marshalErr)
	recordErr := d.T.RecordFS("busy-detach-prior-unmount", []string{"statfs", row.CanonicalPin}, err, "record")
	entry := &d.T.Commands[len(d.T.Commands)-1]
	entry.StdoutSHA256, entry.StdoutText = digestAndText(data)
	if err != nil {
		err = fmt.Errorf("observe prior unmount pin %q: %w", row.CanonicalPin, err)
	}
	return row, errors.Join(err, recordErr)
}
