package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func editImageCommand(ctx context.Context, verb string, f *flag.FlagSet, common *sessionFlags, source, destination string, partition int, format string, operands []string, out io.Writer) (err error) {
	if verb != "cp" && verb != "chmod" {
		return fmt.Errorf("existing-image %s: %w", verb, filesystem.ErrUnsupported)
	}
	if common.name != "" || destination == "" || partition < 0 {
		return fmt.Errorf("image editing requires --image and --output, with no --session: %w", fs.ErrInvalid)
	}
	allowed := map[string]bool{"image": true, "output": true, "partition": true, "format": true, "time": true, "json": true}
	if verb == "cp" {
		allowed["from-host"] = true
		allowed["resource-fork"] = true
	}
	f.Visit(func(option *flag.Flag) {
		if !allowed[option.Name] {
			err = fmt.Errorf("--%s is unsupported for existing-image %s: %w", option.Name, verb, filesystem.ErrUnsupported)
		}
	})
	if err != nil {
		return err
	}
	clock := time.Now().UTC().Truncate(time.Second)
	if s := f.Lookup("time").Value.String(); s != "" {
		clock, err = time.Parse(time.RFC3339, s)
		if err != nil || clock.Nanosecond() != 0 {
			return fs.ErrInvalid
		}
	}
	var changes []hfsplus.Change
	if verb == "chmod" {
		if len(operands) < 2 {
			return fmt.Errorf("usage: apfs chmod --image IMAGE --output NEW_DMG MODE PATH [PATH]")
		}
		for _, path := range operands[1:] {
			changes = append(changes, hfsplus.Change{Path: path, Mode: operands[0]})
		}
	} else {
		if len(operands) != 2 || f.Lookup("from-host").Value.String() != "true" {
			return fmt.Errorf("usage: apfs cp --image IMAGE --output NEW_DMG --from-host [--resource-fork] HOST_FILE EXISTING_PATH")
		}
		data, e := block.Open(operands[0])
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, data.Close()) }()
		changes = []hfsplus.Change{{Path: operands[1], Data: data, ResourceFork: f.Lookup("resource-fork").Value.String() == "true"}}
	}
	report, err := imageedit.Apply(ctx, source, destination, imageedit.Options{Partition: partition, Format: format, Time: clock}, changes)
	if err != nil {
		return err
	}
	if common.json {
		return json.NewEncoder(out).Encode(report)
	}
	_, err = fmt.Fprintf(out, "Updated %d file operation(s) in volume %s; published %s (%s); %d free allocation blocks\n", len(report.Changed), report.VolumeID, destination, report.Format, report.FreeBlocks)
	return err
}
