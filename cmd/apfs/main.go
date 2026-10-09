package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		code := 1
		if errors.Is(err, filesystem.ErrUnsupported) {
			code = 5
		}
		if errors.Is(err, flag.ErrHelp) {
			code = 0
		}
		os.Exit(code)
	}
}

func run(ctx context.Context, args []string, out, diagnostics io.Writer) (err error) {
	if len(args) == 0 {
		return fmt.Errorf("usage: apfs inspect|info|list|cat [options] IMAGE [EXACT_PATH]")
	}
	if args[0] == "licenses" {
		_, err = fmt.Fprintln(out, "Original go-apfs-v3 code: MIT.\nApple-derived FinderInfo adapter: Copyright (c) 2000-2023 Apple Inc.; APSL-2.0.\nSource and license are supplied with this project and available at:\nhttps://github.com/deploymenttheory/go-apfs-v3\nSee hfsplus/finderinfo.go, LICENSES/APSL-2.0.txt and THIRD_PARTY_NOTICES.md.")
		return err
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err = fmt.Fprintln(out, "usage: apfs inspect|info [--json] IMAGE\n       apfs list [--json] [--partition INDEX] [--volume ID] IMAGE EXACT_PATH\n       apfs cat [--partition INDEX] [--volume ID] IMAGE EXACT_PATH\n\nRead-only inspection and uncompressed file reading. Paths use exact enumerated spelling; symlinks are not followed. Writes are not implemented yet.")
		return err
	}
	if args[0] == "list" || args[0] == "cat" {
		return readFiles(ctx, args, out, diagnostics)
	}
	if args[0] != "inspect" && args[0] != "info" {
		return fmt.Errorf("command %q: %w", args[0], filesystem.ErrUnsupported)
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	jsonOutput := flags.Bool("json", false, "emit a versioned JSON structural report")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: apfs %s [--json] IMAGE", args[0])
	}
	img, err := diskimage.Open(flags.Arg(0))
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, img.Close()) }()
	r, err := inspect.Image(ctx, img)
	if err != nil {
		return err
	}
	if err := r.RequireFilesystem(); err != nil {
		return err
	}
	if *jsonOutput {
		b, err := r.Marshal()
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, string(b))
		return err
	}
	if _, err = fmt.Fprintf(out, "%s image, %d bytes, %s partition map\n", r.Format, r.Size, r.PartitionMap); err != nil {
		return err
	}
	for _, p := range r.Partitions {
		if _, err = fmt.Fprintf(out, "Partition %d: %s (%d bytes)\n", p.Index, p.Filesystem, p.Size); err != nil {
			return err
		}
		if p.APFS != nil {
			if _, err = fmt.Fprintf(out, "  Container %s, checkpoint %d, transaction %d\n", p.APFS.UUID, p.APFS.Checkpoint, p.APFS.XID); err != nil {
				return err
			}
			for _, v := range p.APFS.Volumes {
				if _, err = fmt.Fprintf(out, "  Volume %q, %s, encrypted=%t\n", v.Name, v.UUID, v.Encrypted); err != nil {
					return err
				}
			}
		}
		if p.HFSPlus != nil {
			if _, err = fmt.Fprintf(out, "  Volume %q, journaled=%t, clean=%t\n", p.HFSPlus.Name, p.HFSPlus.Journaled, p.HFSPlus.Clean); err != nil {
				return err
			}
		}
	}
	return nil
}
