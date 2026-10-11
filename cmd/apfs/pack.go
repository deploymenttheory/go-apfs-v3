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
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

func packCommand(ctx context.Context, args []string, input io.Reader, out, diagnostics io.Writer) (err error) {
	if packHasVolumes(args) {
		return packVolumesCommand(ctx, args, input, out, diagnostics)
	}
	f := flag.NewFlagSet("pack", flag.ContinueOnError)
	f.SetOutput(diagnostics)
	f.Usage = func() {
		_, _ = fmt.Fprintln(diagnostics, "Usage: apfs pack [options] SOURCE NEW_DMG\n       apfs pack --session NAME [options] NEW_DMG\n       apfs pack --volume NAME [--session NAME | --directory PATH] [volume options] [--volume ...] NEW_DMG\nUse pack --volume NAME --help for APFS container options.")
		f.PrintDefaults()
	}
	encryption := addPackEncryptionFlags(f, true)
	common := addSessionFlags(f)
	format := f.String("format", "UDZO", "DMG encoding: UDRO or UDZO")
	fileCompression := addPackCompressionFlag(f)
	filesystemName := f.String("filesystem", "", "directory target: apfs, hfsplus or hfsx; sessions retain their format")
	sensitive := f.Bool("case-sensitive", false, "use case-sensitive APFS names for directory input")
	name := f.String("volume-name", "Untitled", "volume name")
	capacity := f.String("capacity", "", "volume size in bytes, or with KiB/MiB/GiB suffix; default automatic")
	fixed := f.String("time", "", "fixed RFC3339 build clock; file timestamps remain preserved")
	id := f.String("volume-id", "", "native HFS identifier as 16 hex digits; default derived from contents")
	volumeUUID := f.String("volume-uuid", "", "APFS volume UUID; default derived from contents")
	containerUUID := f.String("container-uuid", "", "APFS container UUID; default derived from contents")
	uid := f.Uint("uid", 0, "owner for metadata unavailable on the source host")
	gid := f.Uint("gid", 0, "group for metadata unavailable on the source host")
	operands, err := parseCommandFlags(f, args)
	if err != nil {
		return err
	}
	if err = validatePackCompression(*fileCompression); err != nil {
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
		return fmt.Errorf("usage: apfs pack [--format UDRO|UDZO] IMAGE NEW_DMG; or pack [--session NAME | --filesystem apfs|hfsplus|hfsx DIRECTORY] [options] NEW_DMG")
	}
	if _, e := os.Lstat(operands[len(operands)-1]); e == nil {
		return fs.ErrExist
	} else if !errors.Is(e, fs.ErrNotExist) {
		return e
	}
	if common.name == "" {
		info, e := os.Stat(operands[0])
		if e != nil {
			return e
		}
		if !info.IsDir() {
			for _, option := range []string{"filesystem", "volume-name", "capacity", "time", "volume-id", "volume-uuid", "container-uuid", "case-sensitive", "uid", "gid", "scratch-dir", "file-compression"} {
				if flagWasSet(f, option) {
					return fmt.Errorf("--%s does not apply to image repacking", option)
				}
			}
			crypt, e := encryption.options(input, true)
			if e != nil {
				return e
			}
			defer clearPackPasswords(crypt)
			crypt.Format = *format
			report, e := pack.RepackWithOptions(ctx, operands[0], operands[1], crypt)
			if e != nil {
				return e
			}
			if common.json {
				return json.NewEncoder(out).Encode(struct {
					Schema int `json:"schema"`
					pack.RepackReport
				}{1, report})
			}
			_, e = fmt.Fprintf(out, "Repacked %s image: %d bytes (%d-byte disk)\nDisk SHA-256: %s\nImage encryption: %s\n", report.Format, report.ImageBytes, report.DiskBytes, report.DiskSHA256, packEncryptionLabel(report.Encryption))
			return e
		}
	}
	crypt, err := encryption.options(input, false)
	if err != nil {
		return err
	}
	defer clearPackPasswords(crypt)
	clock := time.Now().UTC().Truncate(time.Second)
	if *fixed != "" {
		clock, err = time.Parse(time.RFC3339, *fixed)
		if err != nil {
			return err
		}
	}
	options := pack.Options{Format: *format, Encryption: crypt.Encryption, FileCompression: *fileCompression, ScratchDir: common.scratch, Volume: pack.VolumeOptions{Name: *name, Time: clock}}
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
	for _, item := range []struct {
		value string
		dst   *[16]byte
	}{{*volumeUUID, &options.Volume.VolumeUUID}, {*containerUUID, &options.Volume.ContainerUUID}} {
		if item.value == "" {
			continue
		}
		*item.dst, err = parseBuildUUID(item.value)
		if err != nil {
			return err
		}
	}
	var s *session.Session
	if common.name != "" {
		if *filesystemName != "" || flagWasSet(f, "uid") || flagWasSet(f, "gid") || flagWasSet(f, "case-sensitive") {
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
		if *filesystemName != "apfs" && *filesystemName != "hfsplus" && *filesystemName != "hfsx" {
			return fmt.Errorf("--filesystem must be apfs, hfsplus or hfsx")
		}
		if *filesystemName != "apfs" && flagWasSet(f, "case-sensitive") {
			return fs.ErrInvalid
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
		rules := filesystem.NameRules{Format: "HFS+", CaseSensitive: *filesystemName == "hfsx", NormalizationInsensitive: true}
		if *filesystemName == "apfs" {
			rules.Format = "APFS"
			rules.CaseSensitive = *sensitive
		}
		s, err = session.Create(ctx, filepath.Join(root, "build"), session.Options{Names: rules, UID: uint32(*uid), GID: uint32(*gid), Time: &clock})
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
	if s.NameRules().Format == "APFS" {
		if flagWasSet(f, "volume-id") {
			return fmt.Errorf("--volume-id applies to HFS; use --volume-uuid for APFS")
		}
	} else {
		if flagWasSet(f, "volume-uuid") || flagWasSet(f, "container-uuid") {
			return fmt.Errorf("UUID options apply to APFS")
		}
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
	_, err = fmt.Fprintf(out, "Created %s %s image: %d bytes (%d-byte volume)\nImage encryption: %s\n", report.Filesystem, report.Format, report.ImageBytes, report.VolumeBytes, packEncryptionLabel(report.Encryption))
	if err == nil {
		err = writePackCompressionReport(out, report.FileCompression, report.Compression)
	}
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
