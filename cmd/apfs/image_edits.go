package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/internal/copyfile"
)

func editImageCommand(ctx context.Context, verb string, f *flag.FlagSet, common *sessionFlags, source, destination string, partition int, format string, operands []string, out io.Writer) (err error) {
	if verb == "xattr" && f.Lookup("w").Value.String() != "true" && f.Lookup("d").Value.String() != "true" {
		return readImageAttributes(ctx, f, common, source, partition, operands, out)
	}
	if verb != "cp" && verb != "chmod" && verb != "mkdir" && verb != "mv" && verb != "rm" && verb != "chown" && verb != "chflags" && verb != "touch" && verb != "xattr" && verb != "ln" {
		return fmt.Errorf("existing-image %s: %w", verb, filesystem.ErrUnsupported)
	}
	if common.name != "" || destination == "" || partition < 0 {
		return fmt.Errorf("image editing requires --image and --output, with no --session: %w", fs.ErrInvalid)
	}
	allowed := map[string]bool{"image": true, "output": true, "partition": true, "volume": true, "format": true, "time": true, "json": true}
	if verb == "cp" {
		allowed["from-host"] = true
		allowed["resource-fork"] = true
		for _, option := range []string{"R", "p", "a", "n", "X", "H", "L", "P", "preserve-links"} {
			allowed[option] = true
		}
	}
	if verb == "mkdir" {
		allowed["p"] = true
		allowed["m"] = true
	}
	if verb == "mv" {
		allowed["n"] = true
	}
	if verb == "ln" {
		allowed["s"] = true
		allowed["f"] = true
		allowed["h"] = true
	}
	if verb == "rm" {
		allowed["r"] = true
		allowed["R"] = true
		allowed["f"] = true
	}
	if verb == "chmod" || verb == "chown" || verb == "chflags" {
		allowed["R"] = true
		allowed["h"] = true
		allowed["P"] = true
	}
	if verb == "touch" {
		for _, name := range []string{"a", "m", "c", "h", "d", "r"} {
			allowed[name] = true
		}
	}
	if verb == "xattr" {
		for _, name := range []string{"w", "d", "s", "x", "value-file"} {
			allowed[name] = true
		}
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
	var changes []imageedit.Change
	switch verb {
	case "ln":
		if len(operands) != 2 {
			return fs.ErrInvalid
		}
		changes = []imageedit.Change{{Operation: verb, Path: operands[0], Destination: operands[1], Symbolic: f.Lookup("s").Value.String() == "true", Force: f.Lookup("f").Value.String() == "true", NoFollow: f.Lookup("h").Value.String() == "true"}}
	case "chown", "chflags", "touch", "xattr":
		var close func() error
		changes, close, err = imageMetadataChanges(verb, f, operands)
		defer func() { err = errors.Join(err, close()) }()
		if err != nil {
			return err
		}
	case "chmod":
		if len(operands) < 2 {
			return fmt.Errorf("usage: apfs chmod --image IMAGE --output NEW_DMG MODE PATH [PATH]")
		}
		for _, path := range operands[1:] {
			changes = append(changes, imageedit.Change{Operation: verb, Path: path, Mode: operands[0], Recursive: f.Lookup("R").Value.String() == "true", NoFollow: f.Lookup("h").Value.String() == "true"})
		}
	case "mkdir", "rm":
		if len(operands) == 0 {
			return fs.ErrInvalid
		}
		for _, path := range operands {
			c := imageedit.Change{Operation: verb, Path: path}
			if verb == "mkdir" {
				c.Parents = f.Lookup("p").Value.String() == "true"
				c.Mode = f.Lookup("m").Value.String()
			} else {
				c.Recursive = f.Lookup("r").Value.String() == "true"
				c.Force = f.Lookup("f").Value.String() == "true"
			}
			changes = append(changes, c)
		}
	case "mv":
		if len(operands) != 2 {
			return fs.ErrInvalid
		}
		changes = []imageedit.Change{{Operation: verb, Path: operands[0], Destination: operands[1], NoClobber: f.Lookup("n").Value.String() == "true"}}
	case "cp":
		if len(operands) < 2 {
			return fs.ErrInvalid
		}
		copyOptions := imageedit.CopyOptions{FromHost: f.Lookup("from-host").Value.String() == "true", Recursive: f.Lookup("R").Value.String() == "true", Preserve: f.Lookup("p").Value.String() == "true", Archive: f.Lookup("a").Value.String() == "true", NoClobber: f.Lookup("n").Value.String() == "true", NoAttributes: f.Lookup("X").Value.String() == "true", PreserveLinks: f.Lookup("preserve-links").Value.String() == "true", Follow: f.Lookup("P").Value.String()}
		if f.Lookup("resource-fork").Value.String() != "true" {
			report, err := imageedit.Copy(ctx, source, destination, imageedit.Options{Partition: partition, Volume: f.Lookup("volume").Value.String(), Format: format, Time: clock}, operands[:len(operands)-1], operands[len(operands)-1], copyOptions)
			if err != nil {
				return err
			}
			if common.json {
				return json.NewEncoder(out).Encode(report)
			}
			if err = copyOmissions(f.Output(), report.OmittedAttributes); err != nil {
				return err
			}
			_, err = fmt.Fprintf(out, "Copied %d path(s) in volume %s; published %s (%s); %d free allocation blocks\n", report.Copied, report.VolumeID, destination, report.Format, report.FreeBlocks)
			return err
		}
		if len(operands) != 2 || !copyOptions.FromHost || copyOptions.Recursive || copyOptions.Preserve || copyOptions.Archive || copyOptions.NoAttributes || copyOptions.PreserveLinks || copyOptions.Follow != "" {
			return fs.ErrInvalid
		}
		data, e := block.Open(operands[0])
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, data.Close()) }()
		changes = []imageedit.Change{{Operation: verb, Path: operands[1], Name: filepath.Base(operands[0]), Data: data, ResourceFork: f.Lookup("resource-fork").Value.String() == "true", NoClobber: f.Lookup("n").Value.String() == "true"}}
	}
	report, err := imageedit.Apply(ctx, source, destination, imageedit.Options{Partition: partition, Volume: f.Lookup("volume").Value.String(), Format: format, Time: clock}, changes)
	if err != nil {
		return err
	}
	if common.json {
		return json.NewEncoder(out).Encode(report)
	}
	_, err = fmt.Fprintf(out, "Updated %d file operation(s) in volume %s; published %s (%s); %d free allocation blocks\n", len(report.Changed), report.VolumeID, destination, report.Format, report.FreeBlocks)
	return err
}

func copyOmissions(out io.Writer, omissions []copyfile.Omission) error {
	for _, value := range omissions {
		if _, err := fmt.Fprintf(out, "Copy %s to %s omitted %s: %s\n", value.Source, value.Destination, value.Attribute, value.Reason); err != nil {
			return err
		}
	}
	return nil
}
