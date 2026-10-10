package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

type choiceFlag struct {
	target *string
	value  string
}

func (f choiceFlag) String() string   { return *f.target }
func (f choiceFlag) Set(string) error { *f.target = f.value; return nil }
func (f choiceFlag) IsBoolFlag() bool { return true }
func walkFlags(f *flag.FlagSet) *session.WalkOptions {
	o := &session.WalkOptions{}
	f.BoolVar(&o.Recursive, "R", false, "recurse into directories")
	f.BoolVar(&o.NoFollow, "h", false, "operate on symlinks themselves")
	for _, letter := range []string{"H", "L", "P"} {
		f.Var(choiceFlag{&o.Follow, letter}, letter, "symbolic-link traversal policy")
	}
	return o
}
func parseOctal(s string, max uint32) (uint32, error) {
	v, err := strconv.ParseUint(s, 8, 32)
	if err != nil || v > uint64(max) {
		return 0, fs.ErrInvalid
	}
	return uint32(v), nil
}

func fileCommand(ctx context.Context, args []string, out, diagnostics io.Writer) (err error) {
	verb := args[0]
	f := flag.NewFlagSet(verb, flag.ContinueOnError)
	f.SetOutput(diagnostics)
	common := addSessionFlags(f)
	var walk *session.WalkOptions
	var cp session.CopyOptions
	var mkdir session.MkdirOptions
	var touch session.TouchOptions
	var remove session.RemoveOptions
	var link session.LinkOptions
	var noClobber, fork, hexValue, xread, xwrite, xdelete, attrNoFollow bool
	var mode, date, reference, valueFile string
	switch verb {
	case "chmod", "chown", "chflags":
		walk = walkFlags(f)
	case "cp":
		f.BoolVar(&cp.FromHost, "from-host", false, "copy from host paths into the session")
		f.BoolVar(&cp.Recursive, "R", false, "copy directories recursively")
		f.BoolVar(&cp.Preserve, "p", false, "preserve available source metadata")
		f.Var(archiveFlag{&cp}, "a", "archive copy (-RpP)")
		f.BoolVar(&cp.NoClobber, "n", false, "refuse existing files")
		f.BoolVar(&cp.NoAttributes, "X", false, "omit attributes and resource forks")
		f.BoolVar(&cp.PreserveLinks, "preserve-links", false, "retain regular-file hard-link relationships")
		f.BoolVar(&fork, "resource-fork", false, "replace the destination file's complete resource fork")
		for _, letter := range []string{"H", "L", "P"} {
			f.Var(choiceFlag{&cp.Follow, letter}, letter, "symbolic-link traversal policy")
		}
	case "mkdir":
		f.BoolVar(&mkdir.Parents, "p", false, "create missing parent directories")
		f.StringVar(&mkdir.Mode, "m", "", "creation mode")
	case "touch":
		f.BoolVar(&touch.Access, "a", false, "change access time")
		f.BoolVar(&touch.Modify, "m", false, "change modification time")
		f.BoolVar(&touch.NoCreate, "c", false, "do not create absent files")
		f.BoolVar(&touch.NoFollow, "h", false, "change symlink times")
		f.StringVar(&date, "d", "", "RFC3339 date")
		f.StringVar(&reference, "r", "", "reference file within session")
	case "rm":
		f.BoolVar(&remove.Recursive, "r", false, "remove directories recursively")
		f.BoolVar(&remove.Recursive, "R", false, "remove directories recursively")
		f.BoolVar(&remove.Force, "f", false, "ignore absent files")
	case "mv":
		f.BoolVar(&noClobber, "n", false, "skip an existing destination")
	case "ln":
		f.BoolVar(&link.Symbolic, "s", false, "create a symbolic link")
		f.BoolVar(&link.Force, "f", false, "replace an existing non-directory entry")
	case "xattr":
		f.BoolVar(&xread, "p", false, "print an attribute")
		f.BoolVar(&xwrite, "w", false, "write an attribute")
		f.BoolVar(&xdelete, "d", false, "remove an attribute")
		f.BoolVar(&hexValue, "x", false, "hexadecimal attribute value")
		f.BoolVar(&attrNoFollow, "s", false, "operate on symlinks themselves")
		f.StringVar(&valueFile, "value-file", "", "read attribute bytes from a host file")
	case "cat":
		f.BoolVar(&fork, "resource-fork", false, "read the independent resource fork")
	case "list", "stat":
	default:
		return filesystem.ErrUnsupported
	}
	operands, err := parseCommandFlags(f, args[1:])
	if err != nil {
		return err
	}
	if common.name == "" {
		return fmt.Errorf("%s requires --session NAME", verb)
	}
	dir, err := sessionDirectory(common.scratch, common.name)
	if err != nil {
		return err
	}
	s, err := session.Open(ctx, dir)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, s.Close()) }()
	var report session.Report
	switch verb {
	case "chmod", "chown", "chflags":
		if len(operands) < 2 {
			return fs.ErrInvalid
		}
		mode = operands[0]
		switch verb {
		case "chmod":
			report, err = s.Chmod(ctx, operands[1:], mode, *walk)
		case "chown":
			report, err = s.Chown(ctx, operands[1:], mode, *walk)
		case "chflags":
			report, err = s.Chflags(ctx, operands[1:], mode, *walk)
		}
	case "mkdir":
		report, err = s.Mkdir(ctx, operands, mkdir)
	case "touch":
		touch.Reference = reference
		if date != "" {
			t, e := time.Parse(time.RFC3339Nano, date)
			if e != nil {
				return e
			}
			touch.Time = &t
		}
		report, err = s.Touch(ctx, operands, touch)
	case "rm":
		report, err = s.Remove(ctx, operands, remove)
	case "mv":
		if len(operands) != 2 {
			return fs.ErrInvalid
		}
		report, err = s.Move(ctx, operands[0], operands[1], noClobber)
	case "ln":
		if len(operands) != 2 {
			return fs.ErrInvalid
		}
		report, err = s.Link(ctx, operands[0], operands[1], link)
	case "cp":
		if len(operands) < 2 {
			return fs.ErrInvalid
		}
		if fork {
			if len(operands) != 2 || !cp.FromHost || cp.Recursive || cp.Archive || cp.Preserve || cp.NoAttributes || cp.PreserveLinks || cp.NoClobber || cp.Follow != "" {
				return fs.ErrInvalid
			}
			data, e := block.Open(operands[0])
			if e != nil {
				return e
			}
			defer func() { err = errors.Join(err, data.Close()) }()
			report, err = s.ReplaceResourceFork(ctx, operands[1], data)
		} else {
			report, err = s.Copy(ctx, operands[:len(operands)-1], operands[len(operands)-1], cp)
		}
	case "xattr":
		return sessionAttributes(ctx, s, operands, xread, xwrite, xdelete, hexValue, attrNoFollow, valueFile, common.json, out)
	case "cat", "list", "stat":
		if len(operands) != 1 {
			return fs.ErrInvalid
		}
		id, e := s.LookupPath(ctx, operands[0], verb == "cat")
		if e != nil {
			return e
		}
		switch verb {
		case "stat":
			n, e := s.Stat(ctx, id)
			if e != nil {
				return e
			}
			if common.json {
				return json.NewEncoder(out).Encode(n)
			}
			_, e = fmt.Fprintf(out, "%s: mode %06o, uid %d, gid %d, flags %#x, size %d\nBirth: %s; modify: %s; change: %s; access: %s\n", operands[0], n.Metadata.Mode.Value, n.Metadata.UID.Value, n.Metadata.GID.Value, n.Metadata.BSDFlags.Value, n.Size, n.Metadata.BirthTime.Value.Format(time.RFC3339Nano), n.Metadata.ModifyTime.Value.Format(time.RFC3339Nano), n.Metadata.ChangeTime.Value.Format(time.RFC3339Nano), n.Metadata.AccessTime.Value.Format(time.RFC3339Nano))
			return e
		case "list":
			return s.ReadDir(ctx, id, func(e filesystem.DirEntry) error {
				if common.json {
					return json.NewEncoder(out).Encode(e)
				}
				_, err := fmt.Fprintln(out, e.Name)
				return err
			})
		case "cat":
			if common.json {
				return fs.ErrInvalid
			}
			var v filesystem.Value
			if fork {
				v, e = s.OpenAttribute(ctx, id, filesystem.ResourceFork)
			} else {
				v, e = s.OpenData(ctx, id)
			}
			if e != nil {
				return e
			}
			_, e = io.Copy(out, io.NewSectionReader(v, 0, v.Size()))
			return errors.Join(e, v.Close())
		}
	}
	if err != nil {
		return err
	}
	return printSessionReport(out, report, common.json, false)
}
func sessionAttributes(ctx context.Context, s *session.Session, args []string, read, write, remove, hexadecimal, noFollow bool, valueFile string, jsonOutput bool, out io.Writer) (err error) {
	operations := 0
	for _, b := range []bool{read, write, remove} {
		if b {
			operations++
		}
	}
	if operations > 1 || len(args) == 0 {
		return fs.ErrInvalid
	}
	if valueFile != "" && !write {
		return fs.ErrInvalid
	}
	if hexadecimal && valueFile != "" {
		return fs.ErrInvalid
	}
	o := session.AttributeOptions{NoFollow: noFollow}
	if write {
		count := 3
		if valueFile != "" {
			count = 2
		}
		if len(args) < count {
			return fs.ErrInvalid
		}
		var source block.Source
		paths := args[2:]
		if valueFile != "" {
			f, e := block.Open(valueFile)
			if e != nil {
				return e
			}
			defer func() { err = errors.Join(err, f.Close()) }()
			source = f
			paths = args[1:]
		} else {
			data := []byte(args[1])
			if hexadecimal {
				var e error
				data, e = hex.DecodeString(strings.ReplaceAll(args[1], " ", ""))
				if e != nil {
					return e
				}
			}
			source = bytes.NewReader(data)
		}
		r, e := s.SetAttribute(ctx, paths, args[0], source, o)
		if e != nil {
			return e
		}
		return printSessionReport(out, r, jsonOutput, false)
	}
	if remove {
		if len(args) < 2 || hexadecimal {
			return fs.ErrInvalid
		}
		r, e := s.RemoveAttribute(ctx, args[1:], args[0], o)
		if e != nil {
			return e
		}
		return printSessionReport(out, r, jsonOutput, false)
	}
	if read {
		if len(args) != 2 || jsonOutput {
			return fs.ErrInvalid
		}
		id, e := s.LookupPath(ctx, args[1], !noFollow)
		if e != nil {
			return e
		}
		v, e := s.OpenAttribute(ctx, id, args[0])
		if e != nil {
			return e
		}
		var dst = out
		if hexadecimal {
			dst = hex.NewEncoder(out)
		}
		_, e = io.Copy(dst, io.NewSectionReader(v, 0, v.Size()))
		return errors.Join(e, v.Close())
	}
	if len(args) != 1 || hexadecimal {
		return fs.ErrInvalid
	}
	id, e := s.LookupPath(ctx, args[0], !noFollow)
	if e != nil {
		return e
	}
	return s.ListAttributes(ctx, id, func(name string) error {
		if jsonOutput {
			return json.NewEncoder(out).Encode(name)
		}
		_, e := fmt.Fprintln(out, name)
		return e
	})
}

type archiveFlag struct{ options *session.CopyOptions }

func (f archiveFlag) String() string   { return strconv.FormatBool(f.options.Archive) }
func (f archiveFlag) IsBoolFlag() bool { return true }
func (f archiveFlag) Set(value string) error {
	yes, err := strconv.ParseBool(value)
	if err != nil {
		return err
	}
	f.options.Archive = yes
	if yes {
		f.options.Follow = "P"
	}
	return nil
}
