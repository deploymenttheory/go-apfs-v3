package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func snapshots(ctx context.Context, args []string, input io.Reader, out, diagnostics io.Writer) (err error) {
	if len(args) == 0 || args[0] != "list" {
		return fmt.Errorf("usage: apfs snapshot list [options] IMAGE")
	}
	flags := flag.NewFlagSet("snapshot list", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	options := readerFlags(flags)
	jsonOutput := flags.Bool("json", false, "emit a versioned snapshot inventory")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: apfs snapshot list [options] IMAGE")
	}
	reader, cleanup, err := options.open(ctx, flags.Arg(0), input)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	v, ok := reader.(*apfs.Volume)
	if !ok {
		return fmt.Errorf("snapshot enumeration requires APFS: %w", filesystem.ErrUnsupported)
	}
	result := struct {
		Schema    int             `json:"schema"`
		Volume    string          `json:"volume"`
		Snapshots []apfs.Snapshot `json:"snapshots"`
	}{1, v.UUID, []apfs.Snapshot{}}
	if err := v.ListSnapshots(ctx, func(s apfs.Snapshot) error {
		result.Snapshots = append(result.Snapshots, s)
		return nil
	}); err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(out).Encode(result)
	}
	for _, s := range result.Snapshots {
		if _, err := fmt.Fprintf(out, "%d\t%s\t%q\n", s.XID, s.CreateTime.Format(time.RFC3339Nano), s.Name); err != nil {
			return err
		}
	}
	return nil
}
