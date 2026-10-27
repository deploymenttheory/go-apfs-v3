package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
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

func run(ctx context.Context, args []string, input io.Reader, out, diagnostics io.Writer) (err error) {
	if len(args) == 0 {
		return fmt.Errorf("usage: apfs COMMAND [options] [operands]; use apfs help for commands")
	}
	if args[0] == "edit" {
		return editCommands(ctx, args[1:], input, out, diagnostics)
	}
	if args[0] == "passwd" {
		return changeVolumePassword(ctx, args[1:], input, out, diagnostics)
	}
	if args[0] == "encrypt" || args[0] == "decrypt" {
		return convertVolumeEncryption(ctx, args[0], args[1:], input, out, diagnostics)
	}
	if args[0] == "licenses" {
		_, err = fmt.Fprintln(out, "Original go-apfs-v3 code: MIT.\nApple-derived HFS formatter, mutation and journal recovery engines, FinderInfo adapter and AppleDouble codec: Copyright Apple Inc.; APSL-2.0.\nSource and license are supplied with this project and available at:\nhttps://github.com/deploymenttheory/go-apfs-v3\nApple/Berkeley-derived mode parser: BSD-3-Clause. golang.org/x/sys: BSD-3-Clause.\nSee hfsplus/build.go, hfsplus/journal.go, hfsplus/journal_replay.go, hfsplus/mutate_allocation.go, hfsplus/mutate_tree.go, internal/finderinfo/hfs.go, appledouble/appledouble.go, internal/mode/mode.go, LICENSES and THIRD_PARTY_NOTICES.md.")
		return err
	}
	if args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err = fmt.Fprintln(out, "usage: apfs inspect|info [--json] [--image-password-file FILE] IMAGE\n       apfs list [--json] [--partition INDEX] [--volume ID] [--image-password-file FILE] [--password-file FILE] IMAGE PATH\n       apfs cat [--partition INDEX] [--volume ID] [--image-password-file FILE] [--password-file FILE] IMAGE PATH\n       apfs snapshot list [--json] [--partition INDEX] [--volume ID] [--image-password-file FILE] [--password-file FILE] IMAGE\n       apfs snapshot delete --image IMAGE --output NEW_DMG (--snapshot-name NAME | --snapshot-xid XID) [options]\n       apfs encrypt --image IMAGE --output NEW_DMG --new-password-file FILE [options]\n       apfs decrypt --image IMAGE --output NEW_DMG --password-file FILE [options]\n       apfs passwd --image IMAGE --output NEW_DMG --volume UUID --password-file OLD --new-password-file NEW [options]\n       apfs checkpoint inspect --image IMAGE [--partition INDEX] [--json]\n       apfs checkpoint recover --image IMAGE --output NEW_DMG [--partition INDEX] [--format UDRO|UDZO] [--json]\n       apfs journal inspect --image IMAGE [--partition INDEX] [--json]\n       apfs journal replay --image IMAGE --output NEW_DMG [--partition INDEX] [--format UDRO|UDZO] [--json]\n       apfs extract [--json] [reader options] IMAGE PATH NEW_WORKSPACE\n       apfs workspace verify [--json] WORKSPACE\n       apfs pack [--format UDRO|UDZO] IMAGE NEW_DMG\n       apfs pack [--session NAME | --filesystem apfs|hfsplus|hfsx DIRECTORY] [options] NEW_DMG\n       apfs pack --volume NAME [--session NAME | --directory PATH] [--volume ...] NEW_DMG\n       apfs session create --filesystem apfs|hfsplus|hfsx [options] NAME\n       apfs session open --image IMAGE [reader options] NAME\n       apfs session status|verify|remove NAME\n       apfs session export NAME NEW_DESTINATION\n       apfs edit --image IMAGE --output NEW_DMG [options] -- COMMAND [args] [--next COMMAND ...]\n       apfs cp --image IMAGE --output NEW_DMG --from-host [--resource-fork] HOST_FILE EXISTING_PATH\n       apfs chmod --image IMAGE --output NEW_DMG MODE PATH...\n       apfs cp --session NAME [--from-host] [-RpanX] SOURCE... DESTINATION\n       apfs chmod|chown|chflags --session NAME [-R] VALUE PATH...\n       apfs mkdir|touch|mv|rm|ln|xattr --session NAME [options] PATH...\n       apfs list|cat|stat --session NAME PATH\n\nlist/cat/extract accept --snapshot-name NAME or --snapshot-xid XID for historical APFS reads.\nRead-only inspection and ordinary, compressed or encrypted file reading. Image passwords unlock DMG envelopes; volume passwords unlock APFS. Image-reading paths use native filename comparison without following symlinks. Session commands follow their documented link options. pack accepts --file-compression preserve|zlib|none for filesystem builds, independently of --format. pack accepts --encryption AES-128|AES-256 with --output-password-file FILE, or explicit --encryption none when removing source image encryption. Image editing accepts --image-password-file FILE and preserves source envelope encryption by default; --output-password-file FILE replaces its password, --encryption AES-128|AES-256 selects strength, and --encryption none removes it. --password-file supplies the selected APFS volume credential. Additional encrypted peers require --volume-password-file UUID=FILE. encrypt/decrypt convert an existing APFS volume while preserving its identity and retained history; envelope encryption remains independent. encrypt uses --new-password-file, and decrypt uses --password-file. passwd changes the selected admitted Disk crypto user without changing the volume key. Password files contain exact bytes; use - for stdin through EOF.")
		return err
	}
	if args[0] == "pack" {
		return packCommand(ctx, args[1:], input, out, diagnostics)
	}
	if args[0] == "session" {
		return sessions(ctx, args[1:], input, out, diagnostics)
	}
	switch args[0] {
	case "cp", "chmod", "chown", "chflags", "touch", "mkdir", "mv", "rm", "ln", "xattr", "stat":
		return fileCommand(ctx, args, input, out, diagnostics)
	}
	if (args[0] == "list" || args[0] == "cat") && hasSession(args[1:]) {
		return fileCommand(ctx, args, input, out, diagnostics)
	}
	if args[0] == "snapshot" {
		return snapshots(ctx, args[1:], input, out, diagnostics)
	}
	if args[0] == "journal" {
		return journalCommand(ctx, args[1:], out, diagnostics)
	}
	if args[0] == "checkpoint" {
		return checkpointCommand(ctx, args[1:], out, diagnostics)
	}
	if args[0] == "workspace" {
		return workspaceCommand(ctx, args[1:], out, diagnostics)
	}
	if args[0] == "list" || args[0] == "cat" || args[0] == "extract" {
		return readFiles(ctx, args, input, out, diagnostics)
	}
	if args[0] != "inspect" && args[0] != "info" {
		return fmt.Errorf("command %q: %w", args[0], filesystem.ErrUnsupported)
	}
	flags := flag.NewFlagSet(args[0], flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	jsonOutput := flags.Bool("json", false, "emit a versioned JSON structural report")
	imagePasswordFile := flags.String("image-password-file", "", "DMG envelope password bytes in FILE; - reads stdin to EOF")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 1 {
		return fmt.Errorf("usage: apfs %s [--json] IMAGE", args[0])
	}
	img, err := openImage(ctx, flags.Arg(0), *imagePasswordFile, input)
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
	if r.Encryption != nil {
		if _, err = fmt.Fprintf(out, "Image encryption: %s, %d-bit key, %d-byte blocks\n", r.Encryption.Cipher, r.Encryption.KeyBits, r.Encryption.BlockSize); err != nil {
			return err
		}
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
			if j := p.HFSPlus.Journal; j != nil {
				if _, err = fmt.Fprintf(out, "  Journal: pending=%t, start=%d, end=%d\n", j.Pending, j.Start, j.End); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
