package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func journalCommand(ctx context.Context, args []string, out, diagnostics io.Writer) (err error) {
	if len(args) == 0 || (args[0] != "inspect" && args[0] != "replay") {
		return fmt.Errorf("usage: apfs journal inspect|replay --image IMAGE [options]")
	}
	f := flag.NewFlagSet("journal "+args[0], flag.ContinueOnError)
	f.SetOutput(diagnostics)
	image := f.String("image", "", "source image opened read-only")
	partition := f.Int("partition", 0, "on-disk partition index")
	jsonOutput := f.Bool("json", false, "emit a versioned journal report")
	var output, format string
	if args[0] == "replay" {
		f.StringVar(&output, "output", "", "new recovered image path; must not exist")
		f.StringVar(&format, "format", "UDZO", "output DMG encoding: UDRO or UDZO")
	}
	if err = f.Parse(args[1:]); err != nil {
		return err
	}
	if f.NArg() != 0 || *image == "" || *partition < 0 || (args[0] == "replay" && output == "") {
		return fs.ErrInvalid
	}
	if args[0] == "replay" {
		report, e := imageedit.RecoverJournal(ctx, *image, output, imageedit.JournalRecoveryOptions{Partition: *partition, Format: format})
		if e != nil {
			return e
		}
		if *jsonOutput {
			return json.NewEncoder(out).Encode(struct {
				Schema int `json:"schema"`
				imageedit.Report
			}{1, report})
		}
		_, err = fmt.Fprintf(out, "Recovered %d journal transactions (%d sectors) into %s\n", report.Journal.Transactions, report.Journal.Sectors, output)
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
	j, err := hfsplus.InspectJournal(source)
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(out).Encode(struct {
			Schema  int                  `json:"schema"`
			Journal *hfsplus.JournalInfo `json:"journal"`
		}{1, j})
	}
	_, err = fmt.Fprintf(out, "Internal HFS journal: pending=%t, start=%d, end=%d, size=%d, %s\n", j.Pending, j.Start, j.End, j.Size, j.ByteOrder)
	return err
}
