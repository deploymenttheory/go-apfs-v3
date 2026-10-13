package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func checkpointCommand(ctx context.Context, args []string, out, diagnostics io.Writer) (err error) {
	if len(args) == 0 || (args[0] != "inspect" && args[0] != "recover") {
		return fmt.Errorf("usage: apfs checkpoint inspect|recover --image IMAGE [options]")
	}
	f := flag.NewFlagSet("checkpoint "+args[0], flag.ContinueOnError)
	f.SetOutput(diagnostics)
	image := f.String("image", "", "source image opened read-only")
	partition := f.Int("partition", 0, "on-disk partition index")
	jsonOutput := f.Bool("json", false, "emit a versioned checkpoint report")
	var output, format string
	if args[0] == "recover" {
		f.StringVar(&output, "output", "", "new recovered image path; must not exist")
		f.StringVar(&format, "format", "UDZO", "output DMG encoding: UDRO or UDZO")
	}
	if err = f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 || *image == "" || *partition < 0 || (args[0] == "recover" && output == "") {
		return fs.ErrInvalid
	}
	if args[0] == "recover" {
		report, e := imageedit.RecoverCheckpoint(ctx, *image, output, imageedit.CheckpointRecoveryOptions{Partition: *partition, Format: format})
		if e != nil {
			return e
		}
		if *jsonOutput {
			return json.NewEncoder(out).Encode(struct {
				Schema int `json:"schema"`
				imageedit.Report
			}{1, report})
		}
		_, err = fmt.Fprintf(out, "Recovered APFS checkpoint %d into %s; discarded %d incomplete descriptors\n", report.Transaction, output, len(report.Checkpoint.DiscardedDescriptors))
		return err
	}
	img, err := openImage(ctx, *image, "", nil)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, img.Close()) }()
	source, err := img.Partition(*partition)
	if err != nil {
		return err
	}
	report, err := apfs.InspectCheckpoints(ctx, source)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(out).Encode(struct {
			Schema     int                   `json:"schema"`
			Checkpoint apfs.CheckpointReport `json:"checkpoint"`
		}{1, report})
	}
	if _, err = fmt.Fprintf(out, "APFS container %s; block zero transaction %d, checksum valid=%t\n", report.ContainerUUID, report.BlockZeroTransaction, report.BlockZeroValid); err != nil {
		return err
	}
	for _, candidate := range report.Candidates {
		if _, err = fmt.Fprintf(out, "  Transaction %d at block %d: %s", candidate.Transaction, candidate.Address, candidate.State); err != nil {
			return err
		}
		if candidate.Reason != "" {
			if _, err = fmt.Fprintf(out, " (%s)", candidate.Reason); err != nil {
				return err
			}
		}
		if _, err = fmt.Fprintln(out); err != nil {
			return err
		}
	}
	if report.SelectedAddress == 0 {
		_, err = fmt.Fprintln(out, "No structurally complete checkpoint can be selected.")
	} else {
		_, err = fmt.Fprintf(out, "Newest complete checkpoint: transaction %d at block %d; recovery separately validates filesystem ownership.\n", report.SelectedTransaction, report.SelectedAddress)
	}
	return err
}
