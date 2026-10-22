package imageedit

import (
	"context"
	"errors"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Editor addresses the selected filesystem in one managed, unpublished disk
// copy. It is valid only inside Edit's callback and is used sequentially. Every
// command observes earlier commands; any failure discards the whole copy.
type Editor struct {
	ctx     context.Context
	view    *mutablePartition
	isAPFS  bool
	options Options
	report  Report
	active  bool
	failed  error
}

// Edit stages the source once, runs ordinary ordered commands, validates the
// final filesystem and publishes one completed image. Neither failed commands
// nor a failed callback publish any intermediate output.
func Edit(ctx context.Context, source, destination string, options Options, commands func(*Editor) error) (report Report, err error) {
	defer func() {
		var published *filesystem.PublishedOutputError
		if err != nil && !errors.As(err, &published) {
			report.Clones = nil
		}
	}()
	if commands == nil {
		return Report{}, fs.ErrInvalid
	}
	return editImage(ctx, source, destination, options, func(view *mutablePartition, isAPFS bool) (Report, error) {
		// Commands need filesystem choices, never envelope or volume credentials.
		// A retained, expired Editor must not retain borrowed password buffers.
		commandOptions := Options{ActorUID: options.ActorUID, Partition: options.Partition, Volume: options.Volume, Format: options.Format, Time: options.Time}
		e := &Editor{ctx: ctx, view: view, isAPFS: isAPFS, options: commandOptions, active: true}
		defer func() { e.active = false }()
		if err := commands(e); err != nil {
			return e.report, err
		}
		// A caller cannot ignore a failed command and publish partially changed
		// scratch. Failed engine writes may have already changed private bytes.
		return e.report, e.failed
	})
}

func (e *Editor) ready() error {
	if e == nil || !e.active {
		return fs.ErrClosed
	}
	if e.failed != nil {
		return e.failed
	}
	return e.ctx.Err()
}

func (e *Editor) collect(r Report) {
	e.report.Clones = append(e.report.Clones, r.Clones...)
	e.report.VolumeID, e.report.FreeBlocks, e.report.Transaction = r.VolumeID, r.FreeBlocks, r.Transaction
	e.report.Changed = append(e.report.Changed, r.Changed...)
}

// Apply executes changes against the current scratch state. Large ordinary
// command batches use bounded engine transactions without restaging the disk.
func (e *Editor) Apply(changes []Change) (Report, error) {
	if err := e.ready(); err != nil {
		return Report{}, err
	}
	if len(changes) == 0 {
		e.failed = fs.ErrInvalid
		return Report{}, e.failed
	}
	if len(changes) > 1<<18 {
		e.failed = filesystem.ErrLimit
		return Report{}, e.failed
	}
	var result Report
	for len(changes) > 0 {
		n := min(4096, len(changes))
		r, err := modify(e.ctx, e.view, e.isAPFS, changes[:n], e.options.Time, e.options.Volume, e.options.ActorUID)
		if err != nil {
			e.failed = err
			return result, err
		}
		result.VolumeID, result.FreeBlocks, result.Transaction = r.VolumeID, r.FreeBlocks, r.Transaction
		result.Changed = append(result.Changed, r.Changed...)
		changes = changes[n:]
	}
	e.collect(result)
	return result, nil
}

// Copy executes cp commands, including host import, against the same current
// scratch state. Later Apply or Copy calls can address the copied files.
func (e *Editor) Copy(commands []CopyCommand) (CopyReport, error) {
	if err := e.ready(); err != nil {
		return CopyReport{}, err
	}
	result, err := copyTo(e.ctx, e.view, e.isAPFS, e.options, commands)
	if err != nil {
		e.failed = err
		return result, err
	}
	e.collect(result.Report)
	return result, nil
}
