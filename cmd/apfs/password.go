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

func changeVolumePassword(ctx context.Context, args []string, input io.Reader, out, diagnostics io.Writer) error {
	f := flag.NewFlagSet("passwd", flag.ContinueOnError)
	f.SetOutput(diagnostics)
	image := f.String("image", "", "source image opened read-only")
	output := f.String("output", "", "new image path; must not exist")
	partition := f.Int("partition", 0, "on-disk partition index")
	volume := f.String("volume", "", "APFS volume UUID; required when ambiguous")
	user := f.String("crypto-user", "", "exact crypto-user UUID; default is the admitted Disk user")
	newPassword := f.String("new-password-file", "", "new APFS password bytes in FILE; - reads stdin to EOF")
	format := f.String("format", "UDZO", "output DMG encoding: UDRO or UDZO")
	fixed := f.String("time", "", "operation time, RFC3339 whole seconds")
	jsonOutput := f.Bool("json", false, "emit a versioned output report")
	addEditEncryptionFlags(f)
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 || *image == "" || *output == "" || *partition < 0 || *newPassword == "" || f.Lookup("password-file").Value.String() == "" {
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
	password, err := readPassword(*newPassword, input)
	if err != nil {
		return err
	}
	defer clear(password)
	report, err := imageedit.ChangeVolumePassword(ctx, *image, *output, options, apfs.PasswordChange{CryptoUser: *user, OldPassword: options.VolumePassword, NewPassword: password})
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(out).Encode(struct {
			Schema int `json:"schema"`
			imageedit.Report
		}{1, report})
	}
	_, err = fmt.Fprintf(out, "Changed password for crypto user %s in volume %s; published %s (%s)\n", report.CryptoUser, report.VolumeID, *output, report.Format)
	return err
}
