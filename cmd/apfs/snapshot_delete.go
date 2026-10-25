package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func snapshotDelete(ctx context.Context, args []string, input io.Reader, out, diagnostics io.Writer) error {
	f := flag.NewFlagSet("snapshot delete", flag.ContinueOnError)
	f.SetOutput(diagnostics)
	image := f.String("image", "", "source image opened read-only")
	output := f.String("output", "", "new image path; must not exist")
	partition := f.Int("partition", 0, "on-disk partition index")
	volume := f.String("volume", "", "APFS volume UUID; required when ambiguous")
	name := f.String("snapshot-name", "", "exact retained snapshot name")
	xid := f.Uint64("snapshot-xid", 0, "retained APFS snapshot transaction identifier")
	format := f.String("format", "UDZO", "output DMG encoding: UDRO or UDZO")
	fixed := f.String("time", "", "operation time, RFC3339 whole seconds")
	jsonOutput := f.Bool("json", false, "emit a versioned output report")
	addEditEncryptionFlags(f)
	if err := f.Parse(args); err != nil {
		return err
	}
	byName, byXID := flagWasSet(f, "snapshot-name"), flagWasSet(f, "snapshot-xid")
	if f.NArg() != 0 || *image == "" || *output == "" || *partition < 0 || byName == byXID || (byName && *name == "") || (byXID && *xid == 0) {
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
	options, err := editEncryptionOptions(f, input, imageedit.Options{Partition: *partition, Volume: *volume, Format: *format, Time: clock})
	if err != nil {
		return err
	}
	defer clearEditPasswords(options)
	report, err := imageedit.DeleteSnapshot(ctx, *image, *output, options, apfs.SnapshotSelector{Name: *name, XID: apfs.XID(*xid)})
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(out).Encode(struct {
			Schema int `json:"schema"`
			imageedit.Report
		}{1, report})
	}
	if byName {
		_, err = fmt.Fprintf(out, "Deleted snapshot %q in volume %s; published %s (%s)\n", *name, report.VolumeID, *output, report.Format)
	} else {
		_, err = fmt.Fprintf(out, "Deleted snapshot XID %d in volume %s; published %s (%s)\n", *xid, report.VolumeID, *output, report.Format)
	}
	return err
}
