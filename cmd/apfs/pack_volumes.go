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

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

type packVolume struct {
	spec                          apfs.VolumeSpec
	source, sourceKind, groupWith string
	groupUUID                     [16]byte
	sensitiveSet                  bool
	uid, gid                      uint32
	ownershipSet                  bool
}

func packHasVolumes(args []string) bool {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			break
		}
		if a == "--volume" || strings.HasPrefix(a, "--volume=") {
			return true
		}
		// Skip option values: a directory, session or ordinary volume name can
		// itself be spelled --volume. The flag parser still validates options.
		if strings.HasPrefix(a, "--") && !strings.Contains(a, "=") && a != "--case-sensitive" && a != "--json" && a != "--help" {
			i++
		}
	}
	return false
}

// --volume starts one volume's options. Container options apply to the complete
// output wherever they occur; scoped options require a preceding --volume.
func packVolumesCommand(ctx context.Context, args []string, input io.Reader, out, diagnostics io.Writer) (err error) {
	f := flag.NewFlagSet("pack", flag.ContinueOnError)
	f.SetOutput(diagnostics)
	encryption := addPackEncryptionFlags(f, false)
	format := f.String("format", "UDZO", "DMG encoding: UDRO or UDZO")
	capacity := f.String("capacity", "", "shared container capacity; default automatic")
	fixed := f.String("time", "", "fixed RFC3339 construction clock")
	containerUUID := f.String("container-uuid", "", "APFS container UUID; default derived")
	scratch := f.String("scratch-dir", os.Getenv("APFS_SCRATCH_DIR"), "session storage and temporary import root")
	jsonOutput := f.Bool("json", false, "emit a versioned construction report")
	var volumes []*packVolume
	f.Func("volume", "start a volume named NAME; omitted source creates an empty volume", func(name string) error {
		if name == "" || len(volumes) >= 100 {
			return fs.ErrInvalid
		}
		for _, v := range volumes {
			if v.spec.Name == name {
				return fmt.Errorf("duplicate volume name %q: %w", name, filesystem.ErrConflict)
			}
		}
		volumes = append(volumes, &packVolume{spec: apfs.VolumeSpec{Name: name}})
		return nil
	})
	scoped := func(name, help string, apply func(*packVolume, string) error) {
		f.Func(name, help, func(value string) error {
			if len(volumes) == 0 {
				return fmt.Errorf("--%s requires a preceding --volume", name)
			}
			return apply(volumes[len(volumes)-1], value)
		})
	}
	for _, kind := range []string{"session", "directory"} {
		scoped(kind, "source for the preceding volume", func(v *packVolume, value string) error {
			if value == "" || v.sourceKind != "" {
				return fmt.Errorf("one source per volume: %w", fs.ErrInvalid)
			}
			v.sourceKind, v.source = kind, value
			return nil
		})
	}
	f.BoolFunc("case-sensitive", "case-sensitive names for the preceding directory or empty volume", func(value string) error {
		if len(volumes) == 0 {
			return fmt.Errorf("--case-sensitive requires a preceding --volume")
		}
		v := volumes[len(volumes)-1]
		v.sensitiveSet = true
		v.spec.CaseSensitive, err = strconv.ParseBool(value)
		return err
	})
	scoped("role", "volume role: none, system or data", func(v *packVolume, value string) error {
		switch value {
		case "none":
			v.spec.Role = apfs.VolumeRoleNone
		case "system":
			v.spec.Role = apfs.VolumeRoleSystem
		case "data":
			v.spec.Role = apfs.VolumeRoleData
		default:
			return fs.ErrInvalid
		}
		return nil
	})
	scoped("group-with", "pair this System volume with a named Data volume in this build", func(v *packVolume, value string) error {
		if value == "" {
			return fs.ErrInvalid
		}
		v.groupWith = value
		return nil
	})
	scoped("group-uuid", "UUID for this System/Data pair; default derived", func(v *packVolume, value string) error { v.groupUUID, err = parseBuildUUID(value); return err })
	scoped("volume-uuid", "UUID for the preceding volume; default derived", func(v *packVolume, value string) error { v.spec.UUID, err = parseBuildUUID(value); return err })
	for _, name := range []string{"reserve", "quota"} {
		scoped(name, "volume space limit in bytes, KiB, MiB or GiB; 0 clears", func(v *packVolume, value string) error {
			var n int64
			var e error
			if value != "0" {
				n, e = parseCapacity(value)
			}
			if e != nil {
				return e
			}
			if name == "reserve" {
				v.spec.Reserve = n
			} else {
				v.spec.Quota = n
			}
			return nil
		})
	}
	for _, name := range []string{"uid", "gid"} {
		scoped(name, "ownership default for this imported or empty volume", func(v *packVolume, value string) error {
			n, e := strconv.ParseUint(value, 10, 32)
			if e != nil || n == 1<<32-1 {
				return fs.ErrInvalid
			}
			v.ownershipSet = true
			if name == "uid" {
				v.uid = uint32(n)
			} else {
				v.gid = uint32(n)
			}
			return nil
		})
	}
	operands, err := parseCommandFlags(f, args)
	if err != nil {
		return err
	}
	if len(operands) != 1 || len(volumes) == 0 {
		return fmt.Errorf("usage: apfs pack [container options] --volume NAME [--session NAME | --directory PATH] [volume options] [--volume ...] NEW_DMG")
	}
	if *format != "UDRO" && *format != "UDZO" {
		return filesystem.ErrUnsupported
	}
	if _, e := os.Lstat(operands[0]); e == nil {
		return fs.ErrExist
	} else if !errors.Is(e, fs.ErrNotExist) {
		return e
	}
	crypt, err := encryption.options(input, false)
	if err != nil {
		return err
	}
	defer clearPackPasswords(crypt)
	clock := time.Now().UTC().Truncate(time.Second)
	if *fixed != "" {
		clock, err = time.Parse(time.RFC3339Nano, *fixed)
		if err != nil {
			return err
		}
	}
	options := pack.ContainerOptions{Format: *format, Encryption: crypt.Encryption, APFS: apfs.ContainerBuildOptions{Time: clock}}
	if *capacity != "" {
		options.APFS.Capacity, err = parseCapacity(*capacity)
		if err != nil {
			return err
		}
	}
	if *containerUUID != "" {
		options.APFS.UUID, err = parseBuildUUID(*containerUUID)
		if err != nil {
			return err
		}
	}
	for i, v := range volumes {
		if v.groupWith == "" {
			if v.groupUUID != [16]byte{} {
				return fmt.Errorf("--group-uuid requires --group-with")
			}
			continue
		}
		target := -1
		for j, other := range volumes {
			if other.spec.Name == v.groupWith {
				target = j
			}
		}
		if target < 0 {
			return fmt.Errorf("unknown group volume %q", v.groupWith)
		}
		options.APFS.Groups = append(options.APFS.Groups, apfs.VolumeGroupSpec{System: i, Data: target, UUID: v.groupUUID})
	}
	var opened []*session.Session
	var temporary string
	defer func() {
		for _, s := range opened {
			err = errors.Join(err, s.Close())
		}
		if temporary != "" {
			err = errors.Join(err, os.RemoveAll(temporary))
		}
	}()
	sessions := map[string]*session.Session{}
	var inputs []apfs.VolumeSpec
	type provenance struct {
		Name                  string            `json:"name"`
		Defaulted             []session.Default `json:"defaulted,omitempty"`
		AttributesUnavailable []uint64          `json:"attributesUnavailable,omitempty"`
	}
	var imports []provenance
	for i, v := range volumes {
		var s *session.Session
		if v.sourceKind == "session" {
			if v.sensitiveSet || v.ownershipSet {
				return fmt.Errorf("session %q retains its case policy and ownership", v.source)
			}
			path, e := sessionDirectory(*scratch, v.source)
			if e != nil {
				return e
			}
			s = sessions[path]
			if s == nil {
				s, err = session.Open(ctx, path)
				if err != nil {
					return err
				}
				sessions[path] = s
				opened = append(opened, s)
				if err = s.Verify(ctx); err != nil {
					return err
				}
			}
			v.spec.CaseSensitive = s.NameRules().CaseSensitive
		} else {
			if temporary == "" {
				if *scratch != "" {
					if err = os.MkdirAll(*scratch, 0700); err != nil {
						return err
					}
				}
				temporary, err = os.MkdirTemp(*scratch, "apfs-pack-volumes-")
				if err != nil {
					return err
				}
			}
			s, err = session.Create(ctx, filepath.Join(temporary, strconv.Itoa(i)), session.Options{Names: filesystem.NameRules{Format: "APFS", CaseSensitive: v.spec.CaseSensitive, NormalizationInsensitive: true}, UID: v.uid, GID: v.gid, Time: &clock})
			if err != nil {
				return err
			}
			opened = append(opened, s)
			if v.sourceKind == "directory" {
				info, e := os.Stat(v.source)
				if e != nil {
					return e
				}
				if !info.IsDir() {
					return fmt.Errorf("volume source must be a directory")
				}
				_, err = s.Copy(ctx, []string{filepath.Clean(v.source) + string(filepath.Separator)}, "/", session.CopyOptions{FromHost: true, Archive: true, PreserveLinks: true})
				if err != nil {
					return err
				}
			}
			if err = s.Verify(ctx); err != nil {
				return err
			}
		}
		if err = packDestination(s.Report().Location, operands[0]); err != nil {
			return err
		}
		r := s.Report()
		imports = append(imports, provenance{Name: v.spec.Name, Defaulted: r.Defaulted, AttributesUnavailable: r.AttributesUnavailable})
		v.spec.Reader = s
		inputs = append(inputs, v.spec)
	}
	report, err := pack.CreateContainer(ctx, operands[0], inputs, options)
	if err != nil {
		return err
	}
	if *jsonOutput {
		return json.NewEncoder(out).Encode(struct {
			Schema int `json:"schema"`
			pack.ContainerReport
			Volumes []provenance `json:"volumes"`
		}{1, report, imports})
	}
	_, err = fmt.Fprintf(out, "Created %s APFS image with %d volumes: %d bytes (%d-byte container)\nImage encryption: %s\n", report.Format, report.VolumeCount, report.ImageBytes, report.ContainerBytes, packEncryptionLabel(report.Encryption))
	return err
}

func parseBuildUUID(s string) ([16]byte, error) {
	var id [16]byte
	if len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return id, fs.ErrInvalid
	}
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		return id, fs.ErrInvalid
	}
	copy(id[:], b)
	if id == [16]byte{} {
		return id, fs.ErrInvalid
	}
	return id, nil
}
