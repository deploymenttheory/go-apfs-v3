package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

func readFiles(ctx context.Context, args []string, out, diagnostics io.Writer) (err error) {
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	partition := flags.Int("partition", -1, "on-disk partition index (required if ambiguous)")
	volume := flags.String("volume", "", "APFS UUID or HFS volume ID (required if ambiguous)")
	jsonOutput := flags.Bool("json", false, "list as one JSON record per entry")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 2 {
		return fmt.Errorf("usage: apfs %s [--partition INDEX] [--volume ID] IMAGE EXACT_PATH", args[0])
	}
	if *jsonOutput && args[0] == "cat" {
		return fmt.Errorf("cat emits file bytes; --json applies to list")
	}
	img, err := diskimage.Open(flags.Arg(0))
	if err != nil {
		return err
	}
	defer func() {
		if e := img.Close(); err == nil {
			err = e
		}
	}()
	report, err := inspect.Image(ctx, img)
	if err != nil {
		return err
	}
	reader, err := selectReader(report, *partition, *volume)
	if err != nil {
		return err
	}
	id, err := filesystem.LookupExact(ctx, reader, flags.Arg(1))
	if err != nil {
		return err
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
