package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"slices"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

// Ordinary verb arguments remain intact after the initial --; --next separates
// commands. Arguments are already shell-parsed, never shell-executed or JSON.
func editCommands(ctx context.Context, args []string, input io.Reader, out, diagnostics io.Writer) error {
	separator := slices.Index(args, "--")
	if separator < 0 {
		return fmt.Errorf("usage: apfs edit --image IMAGE --output NEW_DMG [options] -- COMMAND [arguments] [--next COMMAND ...]")
	}
	f := flag.NewFlagSet("edit", flag.ContinueOnError)
	f.SetOutput(diagnostics)
	source := f.String("image", "", "original image, opened read-only")
	destination := f.String("output", "", "publish one completed edited image at a new path")
	partition := f.Int("partition", 0, "on-disk partition index")
	volume := f.String("volume", "", "APFS UUID or HFS volume ID; required when ambiguous")
	format := f.String("format", "UDZO", "output DMG encoding: UDRO or UDZO")
	fixed := f.String("time", "", "one operation time for the batch, RFC3339 whole seconds")
	f.String("uid", "", "logical creator/writer UID, independent of host credentials")
	jsonOutput := f.Bool("json", false, "emit a machine-readable output report")
	addEditEncryptionFlags(f)
	if err := f.Parse(args[:separator]); err != nil {
		return err
	}
	if f.NArg() != 0 || *source == "" || *destination == "" || *partition < 0 {
		return fs.ErrInvalid
	}
	clock := time.Now().UTC().Truncate(time.Second)
	if *fixed != "" {
		var err error
		clock, err = time.Parse(time.RFC3339, *fixed)
		if err != nil || clock.Nanosecond() != 0 {
			return fs.ErrInvalid
		}
	}
	var commands [][]string
	remaining := args[separator+1:]
	for {
		next := slices.Index(remaining, "--next")
		if next < 0 {
			next = len(remaining)
		}
		if next == 0 || len(commands) >= 4096 {
			return fs.ErrInvalid
		}
		commands = append(commands, remaining[:next])
		if next == len(remaining) {
			break
		}
		remaining = remaining[next+1:]
	}
	options := imageedit.Options{Partition: *partition, Volume: *volume, Format: *format, Time: clock}
	actor, err := imageActor(f)
	if err != nil {
		return err
	}
	options.ActorUID = actor
	options, err = editEncryptionOptions(f, input, options)
	if err != nil {
		return err
	}
	defer clearEditPasswords(options)
	report, err := imageedit.Edit(ctx, *source, *destination, options, func(editor *imageedit.Editor) error {
		for index, command := range commands {
			if err := fileCommandWithEditor(ctx, command, nil, io.Discard, diagnostics, editor, options); err != nil {
				return fmt.Errorf("command %d (%s): %w", index+1, command[0], err)
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(out).Encode(report)
	}
	_, err = fmt.Fprintf(out, "Applied %d command(s) in volume %s; published %s (%s)\n", len(commands), report.VolumeID, *destination, report.Format)
	return err
}
