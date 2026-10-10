package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

func packCommand(ctx context.Context, args []string, out, diagnostics io.Writer) (err error) {
	f := flag.NewFlagSet("pack", flag.ContinueOnError)
	f.SetOutput(diagnostics)
	common := addSessionFlags(f)
	format := f.String("format", "UDZO", "DMG encoding: UDRO or UDZO")
	filesystemName := f.String("filesystem", "", "directory target: hfsplus or hfsx; sessions retain their format")
	name := f.String("volume-name", "Untitled", "volume name")
	capacity := f.String("capacity", "", "volume size in bytes, or with KiB/MiB/GiB suffix; default automatic")
	fixed := f.String("time", "", "fixed RFC3339 build clock; file timestamps remain preserved")
	id := f.String("volume-id", "", "native HFS identifier as 16 hex digits; default derived from contents")
	uid := f.Uint("uid", 0, "owner for metadata unavailable on the source host")
	gid := f.Uint("gid", 0, "group for metadata unavailable on the source host")
	operands, err := parseCommandFlags(f, args)
	if err != nil {
		return err
	}
	if *format != "UDRO" && *format != "UDZO" {
		return filesystem.ErrUnsupported
	}
	want := 2
	if common.name != "" {
		want = 1
	}
	if len(operands) != want {
		return fmt.Errorf("usage: apfs pack [--session NAME | --filesystem hfsplus|hfsx DIRECTORY] [options] NEW_DMG")
	}
	if _, e := os.Lstat(operands[len(operands)-1]); e == nil {
		return fs.ErrExist
	} else if !errors.Is(e, fs.ErrNotExist) {
		return e
	}
	clock := time.Now().UTC().Truncate(time.Second)
	if *fixed != "" {
		clock, err = time.Parse(time.RFC3339, *fixed)
		if err != nil {
			return err
		}
		if clock.Nanosecond() != 0 {
			return fmt.Errorf("HFS build time requires whole seconds")
		}
	}
	options := pack.Options{Format: *format, Volume: hfsplus.BuildOptions{Name: *name, Time: clock}}
	if *capacity != "" {
		options.Volume.Capacity, err = parseCapacity(*capacity)
		if err != nil {
			return err
		}
	}
	if *id != "" {
		b, e := hex.DecodeString(*id)
		if e != nil || len(b) != 8 {
			return fs.ErrInvalid
		}
		copy(options.Volume.VolumeID[:], b)
	}
	var s *session.Session
	if common.name != "" {
		if *filesystemName != "" || flagWasSet(f, "uid") || flagWasSet(f, "gid") {
			return fs.ErrInvalid
		}
		path, e := sessionDirectory(common.scratch, common.name)
		if e != nil {
			return e
		}
		s, err = session.Open(ctx, path)
		if err != nil {
			return err
		}
	} else {
		if *filesystemName != "hfsplus" && *filesystemName != "hfsx" {
			return fmt.Errorf("--filesystem must be hfsplus or hfsx")
		}
		if *uid >= uint(^uint32(0)) || *gid >= uint(^uint32(0)) {
			return fs.ErrInvalid
		}
		info, e := os.Stat(operands[0])
		if e != nil {
			return e
		}
		if !info.IsDir() {
			return fmt.Errorf("pack source must be a directory")
		}
		if common.scratch != "" {
			if e = os.MkdirAll(common.scratch, 0700); e != nil {
				return e
			}
		}
		root, e := os.MkdirTemp(common.scratch, "apfs-pack-session-")
		if e != nil {
			return e
		}
		defer func() { err = errors.Join(err, os.RemoveAll(root)) }()
		s, err = session.Create(ctx, filepath.Join(root, "build"), session.Options{Names: filesystem.NameRules{Format: "HFS+", CaseSensitive: *filesystemName == "hfsx", NormalizationInsensitive: true}, UID: uint32(*uid), GID: uint32(*gid), Time: &clock})
		if err != nil {
			return err
		}
		defer func() { err = errors.Join(err, s.Close()) }()
		source := filepath.Clean(operands[0]) + string(filepath.Separator)
		_, err = s.Copy(ctx, []string{source}, "/", session.CopyOptions{FromHost: true, Archive: true, PreserveLinks: true})
		if err != nil {
			return err
		}
	}
	if common.name != "" {
		defer func() { err = errors.Join(err, s.Close()) }()
	}
	if s.NameRules().Format != "HFS+" {
		return fmt.Errorf("APFS image creation is not implemented: %w", filesystem.ErrUnsupported)
	}
	options.Volume.CaseSensitive = s.NameRules().CaseSensitive
	if err = s.Verify(ctx); err != nil {
		return err
	}
	if err = packDestination(s.Report().Location, operands[len(operands)-1]); err != nil {
		return err
	}
	report, err := pack.Create(ctx, operands[len(operands)-1], s, options)
	if err != nil {
		return err
	}
	provenance := s.Report()
	if common.json {
		return json.NewEncoder(out).Encode(struct {
			Schema int `json:"schema"`
			pack.Report
			Defaulted             []session.Default `json:"defaulted,omitempty"`
			AttributesUnavailable []uint64          `json:"attributesUnavailable,omitempty"`
		}{1, report, provenance.Defaulted, provenance.AttributesUnavailable})
	}
	_, err = fmt.Fprintf(out, "Created %s %s image: %d bytes (%d-byte volume)\n", report.Filesystem, report.Format, report.ImageBytes, report.VolumeBytes)
	if err == nil && (len(provenance.Defaulted) > 0 || len(provenance.AttributesUnavailable) > 0) {
		_, err = fmt.Fprintf(out, "Host metadata defaults on %d objects; attributes unavailable on %d objects.\n", len(provenance.Defaulted), len(provenance.AttributesUnavailable))
	}
	return err
}
func parseCapacity(s string) (int64, error) {
	factor := int64(1)
	for _, suffix := range []struct {
		name   string
		factor int64
	}{{"KiB", 1 << 10}, {"MiB", 1 << 20}, {"GiB", 1 << 30}} {
		if strings.HasSuffix(s, suffix.name) {
			factor = suffix.factor
			s = strings.TrimSuffix(s, suffix.name)
			break
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 || n > (1<<40)/factor {
		return 0, fs.ErrInvalid
	}
	return n * factor, nil
}

// Scratch is managed storage; a new image must be published outside it.
func packDestination(scratch, destination string) error {
	original, err := os.Stat(scratch)
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil {
		return err
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return err
	}
	for {
		info, err := os.Stat(parent)
		if err != nil {
			return err
		}
		if os.SameFile(original, info) {
			return fmt.Errorf("image destination is inside session scratch: %w", fs.ErrInvalid)
		}
		next := filepath.Dir(parent)
		if next == parent {
			return nil
		}
		parent = next
	}
}
