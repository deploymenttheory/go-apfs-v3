package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/internal/metadata"
)

func attributeSource(args []string, valueFile string, hexadecimal bool) (block.Source, []string, func() error, error) {
	close := func() error { return nil }
	count := 3
	if valueFile != "" {
		count = 2
	}
	if len(args) < count || valueFile != "" && hexadecimal {
		return nil, nil, close, fs.ErrInvalid
	}
	if valueFile != "" {
		source, err := block.Open(valueFile)
		if err != nil {
			return nil, nil, close, err
		}
		return source, args[1:], source.Close, nil
	}
	data := []byte(args[1])
	if hexadecimal {
		var err error
		data, err = hex.DecodeString(strings.ReplaceAll(args[1], " ", ""))
		if err != nil {
			return nil, nil, close, err
		}
	}
	return bytes.NewReader(data), args[2:], close, nil
}

func imageMetadataChanges(verb string, f *flag.FlagSet, args []string) ([]imageedit.Change, func() error, error) {
	close := func() error { return nil }
	boolean := func(name string) bool { return f.Lookup(name) != nil && f.Lookup(name).Value.String() == "true" }
	text := func(name string) string {
		if v := f.Lookup(name); v != nil {
			return v.Value.String()
		}
		return ""
	}
	var changes []imageedit.Change
	switch verb {
	case "chown", "chflags":
		if len(args) < 2 {
			return nil, close, fs.ErrInvalid
		}
		for _, path := range args[1:] {
			c := imageedit.Change{Operation: verb, Path: path, Recursive: boolean("R"), NoFollow: boolean("h")}
			if verb == "chown" {
				p, err := metadata.Owner(args[0])
				if err != nil {
					return nil, close, err
				}
				c.Metadata = &p
			} else {
				c.Flags = args[0]
			}
			changes = append(changes, c)
		}
	case "touch":
		if len(args) == 0 || text("d") != "" && text("r") != "" {
			return nil, close, fs.ErrInvalid
		}
		var patch *filesystem.Metadata
		if text("d") != "" {
			date, err := time.Parse(time.RFC3339Nano, text("d"))
			if err != nil {
				return nil, close, err
			}
			patch = &filesystem.Metadata{AccessTime: filesystem.Observed(date), ModifyTime: filesystem.Observed(date)}
		}
		for _, path := range args {
			changes = append(changes, imageedit.Change{Operation: verb, Path: path, Metadata: patch, Reference: text("r"), Access: boolean("a"), Modify: boolean("m"), NoCreate: boolean("c"), NoFollow: boolean("h")})
		}
	case "xattr":
		if boolean("w") == boolean("d") || boolean("p") || len(args) < 2 {
			return nil, close, fs.ErrInvalid
		}
		var source block.Source
		paths := args[1:]
		if boolean("w") {
			var err error
			source, paths, close, err = attributeSource(args, text("value-file"), boolean("x"))
			if err != nil {
				return nil, close, err
			}
		} else if boolean("x") || text("value-file") != "" {
			return nil, close, fs.ErrInvalid
		}
		for _, path := range paths {
			changes = append(changes, imageedit.Change{Operation: verb, Path: path, Attribute: args[0], Data: source, DeleteAttribute: boolean("d"), NoFollow: boolean("s")})
		}
	}
	for _, c := range changes {
		if err := metadata.ValidateChange(c); err != nil {
			return nil, close, err
		}
	}
	return changes, close, nil
}

func readImageAttributes(ctx context.Context, f *flag.FlagSet, common *sessionFlags, source string, partition int, args []string, input io.Reader, out io.Writer) (err error) {
	allowed := map[string]bool{"image": true, "partition": true, "volume": true, "p": true, "s": true, "x": true, "json": true, "image-password-file": true, "password-file": true}
	f.Visit(func(option *flag.Flag) {
		if !allowed[option.Name] {
			err = fs.ErrInvalid
		}
	})
	if err != nil || common.name != "" {
		return fs.ErrInvalid
	}
	read := f.Lookup("p").Value.String() == "true"
	hexadecimal := f.Lookup("x").Value.String() == "true"
	if read && (len(args) != 2 || common.json) || !read && (len(args) != 1 || hexadecimal) {
		return fs.ErrInvalid
	}
	reader, close, err := (&readerOptions{partition: partition, volume: f.Lookup("volume").Value.String(), imagePasswordFile: f.Lookup("image-password-file").Value.String(), passwordFile: f.Lookup("password-file").Value.String()}).open(ctx, source, input)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, close()) }()
	path := args[len(args)-1]
	id, err := filesystem.Lookup(ctx, reader, path)
	if err != nil {
		return err
	}
	node, err := reader.Stat(ctx, id)
	if err != nil {
		return err
	}
	if node.Metadata.Mode.Value&0170000 == 0120000 && f.Lookup("s").Value.String() != "true" {
		return filesystem.ErrUnsupported
	}
	if !read {
		return reader.ListAttributes(ctx, id, func(name string) error {
			if common.json {
				return json.NewEncoder(out).Encode(name)
			}
			_, err := io.WriteString(out, name+"\n")
			return err
		})
	}
	return attributeOutput(ctx, reader, id, args[0], hexadecimal, out)
}

func attributeOutput(ctx context.Context, r filesystem.Reader, id uint64, name string, hexadecimal bool, out io.Writer) error {
	value, err := r.OpenAttribute(ctx, id, name)
	if err != nil {
		return err
	}
	dst := out
	if hexadecimal {
		dst = hex.NewEncoder(out)
	}
	_, err = io.Copy(dst, io.NewSectionReader(value, 0, value.Size()))
	return errors.Join(err, value.Close())
}
