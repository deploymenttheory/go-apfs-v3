package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

func readFiles(ctx context.Context, args []string, input io.Reader, out, diagnostics io.Writer) (err error) {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	options := readerFlags(flags)
	jsonOutput := flags.Bool("json", false, "list entries or extraction report as JSON")
	snapshotName := flags.String("snapshot-name", "", "exact retained APFS snapshot name")
	snapshotXID := flags.Uint64("snapshot-xid", 0, "retained APFS snapshot transaction identifier")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	arguments := 2
	if args[0] == "extract" {
		arguments = 3
	}
	if flags.NArg() != arguments {
		if args[0] == "extract" {
			return fmt.Errorf("usage: apfs extract [options] IMAGE PATH NEW_WORKSPACE")
		}
		return fmt.Errorf("usage: apfs %s [--partition INDEX] [--volume ID] IMAGE PATH", args[0])
	}
	if *jsonOutput && args[0] == "cat" {
		return fmt.Errorf("cat emits file bytes; --json applies to list")
	}
	var byName, byXID bool
	flags.Visit(func(f *flag.Flag) {
		byName = byName || f.Name == "snapshot-name"
		byXID = byXID || f.Name == "snapshot-xid"
	})
	if byName && byXID {
		return fmt.Errorf("choose either --snapshot-name or --snapshot-xid")
	}
	if (byName && *snapshotName == "") || (byXID && *snapshotXID == 0) {
		return fmt.Errorf("snapshot selector must be nonempty and nonzero")
	}
	reader, cleanup, err := options.open(ctx, flags.Arg(0), input)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, cleanup()) }()
	if byName || byXID {
		v, ok := reader.(*apfs.Volume)
		if !ok {
			return fmt.Errorf("snapshot selection requires APFS: %w", filesystem.ErrUnsupported)
		}
		if byName {
			reader, err = v.OpenSnapshotName(ctx, *snapshotName)
		} else {
			reader, err = v.OpenSnapshot(ctx, apfs.XID(*snapshotXID))
		}
		if err != nil {
			return err
		}
	}
	id, err := filesystem.Lookup(ctx, reader, flags.Arg(1))
	if err != nil {
		return err
	}
	if args[0] == "extract" {
		report, err := workspace.Extract(ctx, reader, id, flags.Arg(2), workspace.Limits{})
		if err != nil {
			return err
		}
		return printWorkspaceReport(out, report, *jsonOutput)
	}
	if args[0] == "cat" {
		data, err := reader.OpenData(ctx, id)
		if err != nil {
			return err
		}
		defer func() {
			if e := data.Close(); err == nil {
				err = e
			}
		}()
		_, err = io.Copy(out, io.NewSectionReader(data, 0, data.Size()))
		return err
	}
	encoder := json.NewEncoder(out)
	return reader.ReadDir(ctx, id, func(e filesystem.DirEntry) error {
		if *jsonOutput {
			return encoder.Encode(struct {
				Schema int `json:"schema"`
				filesystem.DirEntry
			}{1, e})
		}
		_, err := fmt.Fprintln(out, e.Name)
		return err
	})
}

// readerOptions is shared by file and snapshot commands. The returned cleanup
// closes an owned unlock before its image; historical views borrow both.
type readerOptions struct {
	partition                               int
	volume, passwordFile, imagePasswordFile string
}

func readerFlags(flags *flag.FlagSet) *readerOptions {
	o := &readerOptions{}
	flags.IntVar(&o.partition, "partition", -1, "on-disk partition index (required if ambiguous)")
	flags.StringVar(&o.volume, "volume", "", "APFS UUID or HFS volume ID (required if ambiguous)")
	flags.StringVar(&o.passwordFile, "password-file", "", "APFS password bytes in FILE; - reads stdin to EOF; no newline removal")
	flags.StringVar(&o.imagePasswordFile, "image-password-file", "", "DMG envelope password bytes in FILE; - reads stdin to EOF")
	return o
}

func (o *readerOptions) open(ctx context.Context, path string, input io.Reader) (reader filesystem.Reader, cleanup func() error, err error) {
	if o.passwordFile == "-" && o.imagePasswordFile == "-" {
		return nil, nil, fmt.Errorf("image and volume passwords cannot both consume stdin; use a file for one")
	}
	img, err := openImage(ctx, path, o.imagePasswordFile, input)
	if err != nil {
		return nil, nil, err
	}
	cleanup = img.Close
	defer func() {
		if err != nil {
			err = errors.Join(err, cleanup())
			cleanup = nil
		}
	}()
	report, err := inspect.Image(ctx, img)
	if err != nil {
		return nil, cleanup, err
	}
	reader, err = selectReader(report, o.partition, o.volume)
	if err != nil {
		return nil, cleanup, err
	}
	if o.passwordFile != "" {
		v, ok := reader.(*apfs.Volume)
		if !ok || !v.Encrypted {
			return nil, cleanup, fmt.Errorf("--password-file requires an encrypted APFS volume")
		}
		password, err := readPassword(o.passwordFile, input)
		if err != nil {
			return nil, cleanup, err
		}
		unlocked, err := v.Unlock(ctx, password)
		clear(password)
		if err != nil {
			return nil, cleanup, err
		}
		cleanup = func() error { return errors.Join(unlocked.Close(), img.Close()) }
		reader = unlocked
	}
	return reader, cleanup, nil
}

func openImage(ctx context.Context, path, passwordFile string, input io.Reader) (*diskimage.Image, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if passwordFile == "" {
		return diskimage.Open(path)
	}
	password, err := readPassword(passwordFile, input)
	if err != nil {
		return nil, err
	}
	defer clear(password)
	return diskimage.OpenWithPassword(ctx, path, password)
}

// Credentials are exact bytes, including spaces and line endings. The explicit
// file/stdin option avoids exposing passwords in process arguments or logs.
func readPassword(path string, input io.Reader) ([]byte, error) {
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer func() { _ = f.Close() }()
		info, err := f.Stat()
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("password file must be regular")
		}
		input = f
	}
	if input == nil {
		return nil, fmt.Errorf("password input is unavailable")
	}
	b, err := io.ReadAll(io.LimitReader(input, 4097))
	if err != nil {
		clear(b)
		return nil, err
	}
	if len(b) > 4096 {
		clear(b)
		return nil, filesystem.ErrLimit
	}
	return b, nil
}

func selectReader(report *inspect.Report, partition int, volume string) (filesystem.Reader, error) {
	var result filesystem.Reader
	count := 0
	for _, p := range report.Partitions {
		if partition >= 0 && p.Index != partition {
			continue
		}
		if p.APFS != nil {
			for i := range p.APFS.Volumes {
				v := &p.APFS.Volumes[i]
				if volume != "" && v.UUID != volume {
					continue
				}
				result = v
				count++
			}
		}
		if p.HFSPlus != nil && (volume == "" || p.HFSPlus.VolumeID == volume) {
			result = p.HFSPlus
			count++
		}
	}
	if count == 0 {
		return nil, fmt.Errorf("no filesystem matches the selected partition and volume")
	}
	if count > 1 {
		return nil, fmt.Errorf("%d filesystems match; choose --partition and/or --volume", count)
	}
	return result, nil
}
