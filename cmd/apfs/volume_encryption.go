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

func convertVolumeEncryption(ctx context.Context, command string, args []string, input io.Reader, out, diagnostics io.Writer) error {
	f := flag.NewFlagSet(command, flag.ContinueOnError)
	f.SetOutput(diagnostics)
	image := f.String("image", "", "existing source image, opened read-only")
	output := f.String("output", "", "completed new image; must not exist")
	partition := f.Int("partition", 0, "on-disk partition index")
	volume := f.String("volume", "", "selected APFS volume UUID; required when ambiguous")
	format := f.String("format", "UDZO", "output DMG encoding: UDRO or UDZO")
	fixed := f.String("time", "", "operation time, RFC3339 whole seconds")
	jsonOutput := f.Bool("json", false, "emit a versioned completed conversion report")
	newPassword := f.String("new-password-file", "", "new APFS volume password bytes; - reads stdin to EOF (encrypt only)")
	addEditEncryptionFlags(f)
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *image == "" || *output == "" || *partition < 0 {
		return fs.ErrInvalid
	}
	encrypt := command == "encrypt"
	if encrypt && (*newPassword == "" || f.Lookup("password-file").Value.String() != "") || !encrypt && (*newPassword != "" || f.Lookup("password-file").Value.String() == "") {
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
	conversion := apfs.EncryptionConversion{Encrypt: encrypt}
	if encrypt {
		conversion.Password, err = readPassword(*newPassword, input)
		if err != nil {
			return err
		}
		defer clear(conversion.Password)
	}
	report, err := imageedit.ConvertVolumeEncryption(ctx, *image, *output, options, conversion)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(out).Encode(struct {
			Schema int `json:"schema"`
			imageedit.Report
		}{1, report})
	}
	_, err = fmt.Fprintf(out, "Completed volume %s conversion for %s; published %s (%s)\n", command, report.VolumeID, *output, report.Format)
	return err
}
