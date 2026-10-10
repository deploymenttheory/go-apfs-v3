package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

// parseCommandFlags accepts clustered short options and options after operands.
// -- stops option interpretation; it also admits symbolic modes beginning '-'.
func parseCommandFlags(f *flag.FlagSet, args []string) ([]string, error) {
	var options, operands []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--help" {
			f.Usage()
			return nil, flag.ErrHelp
		}
		if arg == "--" {
			operands = append(operands, args[i+1:]...)
			break
		}
		if arg == "-" || !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
			continue
		}
		if strings.HasPrefix(arg, "--") {
			key, _, equal := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
			v := f.Lookup(key)
			if v == nil {
				return nil, fmt.Errorf("unknown option --%s", key)
			}
			options = append(options, arg)
			if !equal && !booleanFlag(v) {
				i++
				if i >= len(args) {
					return nil, fmt.Errorf("--%s requires a value", key)
				}
				options = append(options, args[i])
			}
			continue
		}
		short := arg[1:]
		for j := 0; j < len(short); j++ {
			key := string(short[j])
			v := f.Lookup(key)
			if v == nil {
				return nil, fmt.Errorf("unknown option -%s", key)
			}
			options = append(options, "-"+key)
			if !booleanFlag(v) {
				if j+1 < len(short) {
					options = append(options, short[j+1:])
				} else {
					i++
					if i >= len(args) {
						return nil, fmt.Errorf("-%s requires a value", key)
					}
					options = append(options, args[i])
				}
				break
			}
		}
	}
	if err := f.Parse(options); err != nil {
		return nil, err
	}
	return operands, nil
}
func booleanFlag(f *flag.Flag) bool {
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return ok && b.IsBoolFlag()
}

type sessionFlags struct {
	name, scratch string
	json          bool
}

func addSessionFlags(f *flag.FlagSet) *sessionFlags {
	o := &sessionFlags{}
	f.StringVar(&o.name, "session", "", "named editing session")
	f.StringVar(&o.scratch, "scratch-dir", os.Getenv("APFS_SCRATCH_DIR"), "session storage root")
	f.BoolVar(&o.json, "json", false, "emit a machine-readable report")
	return o
}

var sessionName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

func sessionDirectory(root, name string) (string, error) {
	if !sessionName.MatchString(name) || strings.HasSuffix(name, ".") {
		return "", fmt.Errorf("invalid session name: %w", fs.ErrInvalid)
	}
	name = strings.ToLower(name)
	stem, _, _ := strings.Cut(name, ".")
	reserved := stem == "con" || stem == "prn" || stem == "aux" || stem == "nul" || (len(stem) == 4 && (strings.HasPrefix(stem, "com") || strings.HasPrefix(stem, "lpt")) && stem[3] >= '1' && stem[3] <= '9')
	if reserved {
		return "", fmt.Errorf("reserved session name: %w", fs.ErrInvalid)
	}
	if root == "" {
		cache, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		root = filepath.Join(cache, "go-apfs-v3", "sessions")
	}
	return filepath.Join(root, name), nil
}
func printSessionReport(out io.Writer, r session.Report, jsonOutput bool) error {
	if jsonOutput {
		return json.NewEncoder(out).Encode(r)
	}
	if _, err := fmt.Fprintf(out, "%s session: %d objects, %d entries, %d stored bytes.\nScratch: %s\nRevision: %s\n", r.Names.Format, r.Objects, r.Entries, r.BlobBytes, r.Location, r.Revision); err != nil {
		return err
	}
	for _, d := range r.Defaulted {
		if _, err := fmt.Fprintf(out, "Object %d uses supplied defaults: %s.\n", d.Object, strings.Join(d.Fields, ", ")); err != nil {
			return err
		}
	}
	for _, id := range r.AttributesUnavailable {
		if _, err := fmt.Fprintf(out, "Object %d: host extended attributes were unavailable.\n", id); err != nil {
			return err
		}
	}
	return nil
}

type rootReader struct {
	filesystem.Reader
	root uint64
}

func (r rootReader) Root() uint64 { return r.root }

func sessions(ctx context.Context, args []string, input io.Reader, out, diagnostics io.Writer) (err error) {
	if len(args) == 0 {
		return fmt.Errorf("usage: apfs session create|open|status|verify|export|remove [options] NAME")
	}
	f := flag.NewFlagSet("session "+args[0], flag.ContinueOnError)
	f.SetOutput(diagnostics)
	common := addSessionFlags(f)
	format := f.String("filesystem", "", "apfs, hfsplus or hfsx")
	sensitive := f.Bool("case-sensitive", false, "use case-sensitive APFS names")
	image := f.String("image", "", "source image for session open")
	sourcePath := f.String("path", "/", "source subtree")
	fixed := f.String("time", "", "fixed operation time, RFC3339")
	uid := f.Uint("uid", 0, "logical creation UID")
	gid := f.Uint("gid", 0, "logical creation GID")
	mask := f.String("umask", "022", "logical octal creation mask")
	readerOptions := readerFlags(f)
	snapshotName := f.String("snapshot-name", "", "exact snapshot name")
	snapshotXID := f.Uint64("snapshot-xid", 0, "retained APFS snapshot XID")
	operands, err := parseCommandFlags(f, args[1:])
	if err != nil {
		return err
	}
	allowed := map[string]bool{"scratch-dir": true, "json": true}
	if args[0] == "create" || args[0] == "open" {
		for _, name := range []string{"time", "uid", "gid", "umask"} {
			allowed[name] = true
		}
	}
	if args[0] == "create" {
		allowed["filesystem"] = true
		allowed["case-sensitive"] = true
	}
	if args[0] == "open" {
		for _, name := range []string{"image", "path", "snapshot-name", "snapshot-xid", "partition", "volume", "password-file", "image-password-file"} {
			allowed[name] = true
		}
	}
	f.Visit(func(option *flag.Flag) {
		if !allowed[option.Name] && err == nil {
			err = fmt.Errorf("--%s is not valid for session %s", option.Name, args[0])
		}
	})
	if err != nil {
		return err
	}
	if (f.Lookup("snapshot-name").Value.String() == "" && flagWasSet(f, "snapshot-name")) || (*snapshotXID == 0 && flagWasSet(f, "snapshot-xid")) {
		return fs.ErrInvalid
	}
	want := 1
	if args[0] == "export" {
		want = 2
	}
	if len(operands) != want || common.name != "" {
		return fmt.Errorf("session %s requires a name%s", args[0], map[bool]string{true: " and new destination"}[want == 2])
	}
	dir, err := sessionDirectory(common.scratch, operands[0])
	if err != nil {
		return err
	}
	if args[0] == "remove" {
		return session.Remove(ctx, dir)
	}
	if args[0] != "create" && args[0] != "open" && args[0] != "status" && args[0] != "verify" && args[0] != "export" {
		return filesystem.ErrUnsupported
	}
	var s *session.Session
	if args[0] == "create" || args[0] == "open" {
		if *uid >= uint(^uint32(0)) || *gid >= uint(^uint32(0)) {
			return fs.ErrInvalid
		}
		umask, e := parseOctal(*mask, 0777)
		if e != nil {
			return e
		}
		o := session.Options{UID: uint32(*uid), GID: uint32(*gid), Umask: &umask}
		if *fixed != "" {
			t, e := time.Parse(time.RFC3339Nano, *fixed)
			if e != nil {
				return e
			}
			o.Time = &t
		}
		if e = os.MkdirAll(filepath.Dir(dir), 0700); e != nil {
			return e
		}
		if args[0] == "create" {
			if *image != "" {
				return fs.ErrInvalid
			}
			switch *format {
			case "apfs":
				o.Names = filesystem.NameRules{Format: "APFS", CaseSensitive: *sensitive, NormalizationInsensitive: true}
			case "hfsplus", "hfsx":
				if *sensitive {
					return fs.ErrInvalid
				}
				o.Names = filesystem.NameRules{Format: "HFS+", CaseSensitive: *format == "hfsx", NormalizationInsensitive: true}
			default:
				return fmt.Errorf("--filesystem must be apfs, hfsplus or hfsx")
			}
			s, err = session.Create(ctx, dir, o)
		} else {
			if *image == "" || *format != "" || *sensitive {
				return fs.ErrInvalid
			}
			reader, cleanup, e := readerOptions.open(ctx, *image, input)
			if e != nil {
				return e
			}
			defer func() { err = errors.Join(err, cleanup()) }()
			if *snapshotName != "" || *snapshotXID != 0 {
				v, ok := reader.(*apfs.Volume)
				if !ok || (*snapshotName != "" && *snapshotXID != 0) {
					return fs.ErrInvalid
				}
				if *snapshotName != "" {
					reader, e = v.OpenSnapshotName(ctx, *snapshotName)
				} else {
					reader, e = v.OpenSnapshot(ctx, apfs.XID(*snapshotXID))
				}
				if e != nil {
					return e
				}
			}
			id, e := filesystem.Lookup(ctx, reader, *sourcePath)
			if e != nil {
				return e
			}
			s, err = session.Capture(ctx, rootReader{reader, id}, dir, o)
		}
	} else {
		s, err = session.Open(ctx, dir)
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, s.Close()) }()
	if args[0] == "verify" {
		if err = s.Verify(ctx); err != nil {
			return err
		}
	}
	if args[0] == "export" {
		r, e := s.Export(ctx, operands[1])
		if e != nil {
			return e
		}
		return printWorkspaceReport(out, r, common.json)
	}
	return printSessionReport(out, s.Report(), common.json)
}

func hasSession(args []string) bool {
	for _, a := range args {
		if a == "--session" || strings.HasPrefix(a, "--session=") {
			return true
		}
	}
	return false
}

func flagWasSet(f *flag.FlagSet, name string) bool {
	found := false
	f.Visit(func(v *flag.Flag) {
		if v.Name == name {
			found = true
		}
	})
	return found
}
