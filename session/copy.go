package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/edit"
)

// CopyOptions uses Apple cp's logical behavior. PreserveLinks is an explicit
// extension: Apple -a means -RpP and does not preserve hard-link relationships.
type CopyOptions struct {
	FromHost      bool
	Recursive     bool
	Preserve      bool
	Archive       bool
	NoClobber     bool
	NoAttributes  bool
	PreserveLinks bool
	Follow        string
}
type copyEntry struct {
	node      filesystem.Node
	path, key string
	info      fs.FileInfo
}
type copier struct {
	command     *command
	options     CopyOptions
	links       map[string]string
	active      map[string]bool
	count       int
	transferred int64
}

func (s *Session) Copy(ctx context.Context, sources []string, to string, options CopyOptions) (Report, error) {
	if len(sources) == 0 {
		return Report{}, fs.ErrInvalid
	}
	if options.Archive {
		options.Recursive = true
		options.Preserve = true
		if options.Follow == "" {
			options.Follow = "P"
		}
	}
	if options.Follow != "" && options.Follow != "P" && options.Follow != "H" && options.Follow != "L" {
		return Report{}, fs.ErrInvalid
	}
	return s.mutate(ctx, func(c *command) error {
		cp := copier{command: c, options: options, links: map[string]string{}, active: map[string]bool{}}
		if len(sources) > 1 {
			at, err := resolve(ctx, c.tree, to, true)
			if err != nil {
				return err
			}
			n, err := c.tree.Stat(ctx, at.id)
			if err != nil {
				return err
			}
			if n.Metadata.Mode.Value&0170000 != 0040000 {
				return fs.ErrInvalid
			}
		}
		for _, source := range sources {
			follow := !options.Recursive || options.Follow == "H" || options.Follow == "L"
			entry, err := cp.stat(ctx, source, follow)
			if err != nil {
				return err
			}
			basename := path.Base(strings.TrimRight(source, "/"))
			if options.FromHost {
				basename = filepath.Base(filepath.Clean(source))
			}
			dst, err := operandDestination(ctx, c.tree, basename, to)
			if err != nil {
				return err
			}
			if strings.HasSuffix(source, "/") && entry.node.Metadata.Mode.Value&0170000 == 0040000 {
				dst, err = destination(ctx, c.tree, to)
				if path.Clean(to) == "/" {
					dst = "/"
					err = nil
				}
				if err != nil {
					return err
				}
			}
			if !options.FromHost && (entry.path == "/" || entry.path == dst || strings.HasPrefix(dst, entry.path+"/")) {
				return filesystem.ErrConflict
			}
			if err = cp.copy(ctx, entry, dst, 0); err != nil {
				return fmt.Errorf("copy %q: %w", source, err)
			}
		}
		return nil
	})
}
func (c *copier) stat(ctx context.Context, p string, follow bool) (copyEntry, error) {
	if err := ctx.Err(); err != nil {
		return copyEntry{}, err
	}
	if !c.options.FromHost {
		at, err := resolve(ctx, c.command.tree, p, follow)
		if err != nil {
			return copyEntry{}, err
		}
		n, err := c.command.tree.Stat(ctx, at.id)
		return copyEntry{node: n, path: at.path, key: fmt.Sprintf("%s:%d:%d", n.Identity.Volume, n.Identity.View, at.id)}, err
	}
	p, err := filepath.Abs(p)
	if err != nil {
		return copyEntry{}, err
	}
	if follow {
		p, err = filepath.EvalSymlinks(p)
		if err != nil {
			return copyEntry{}, err
		}
	}
	info, err := os.Lstat(p)
	if err != nil {
		return copyEntry{}, err
	}
	m, key, err := hostMetadata(p)
	if err != nil {
		return copyEntry{}, err
	}
	kind := uint32(0100000)
	switch {
	case info.IsDir():
		kind = 0040000
	case info.Mode()&os.ModeSymlink != 0:
		kind = 0120000
	case !info.Mode().IsRegular():
		return copyEntry{}, filesystem.ErrUnsupported
	}
	m.Mode.Value = m.Mode.Value&07777 | kind
	n := filesystem.Node{Metadata: m, Size: uint64(info.Size()), Compression: filesystem.Observation[filesystem.Compression]{State: filesystem.Absent}}
	return copyEntry{node: n, path: p, key: key, info: info}, nil
}
func (c *copier) children(ctx context.Context, e copyEntry) ([]string, error) {
	var names []string
	if c.options.FromHost {
		directory, err := os.Open(e.path)
		if err != nil {
			return nil, err
		}
		for {
			entries, readErr := directory.ReadDir(128)
			for _, entry := range entries {
				if err := ctx.Err(); err != nil {
					return nil, errors.Join(err, directory.Close())
				}
				if len(names) >= c.command.s.document.Config.Limits.Entries {
					return nil, errors.Join(filesystem.ErrLimit, directory.Close())
				}
				names = append(names, entry.Name())
			}
			if readErr == io.EOF {
				break
			}
			if readErr != nil {
				return nil, errors.Join(readErr, directory.Close())
			}
		}
		if err := directory.Close(); err != nil {
			return nil, err
		}
	} else {
		if err := c.command.tree.ReadDir(ctx, e.node.Identity.Object, func(e filesystem.DirEntry) error { names = append(names, e.Name); return nil }); err != nil {
			return nil, err
		}
	}
	sort.Strings(names)
	return names, nil
}
func (c *copier) sourceData(ctx context.Context, e copyEntry) (filesystem.Value, error) {
	if !c.options.FromHost {
		return c.command.tree.OpenData(ctx, e.node.Identity.Object)
	}
	f, err := os.Open(e.path)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if !os.SameFile(info, e.info) || info.Size() != e.info.Size() || !info.ModTime().Equal(e.info.ModTime()) {
		return nil, errors.Join(filesystem.ErrConflict, f.Close())
	}
	return &hostValue{File: f, before: info}, nil
}

type hostValue struct {
	*os.File
	before fs.FileInfo
}

func (v *hostValue) Size() int64 { return v.before.Size() }
func (v *hostValue) Close() error {
	after, err := v.Stat()
	if err == nil && (!os.SameFile(after, v.before) || after.Size() != v.before.Size() || !after.ModTime().Equal(v.before.ModTime())) {
		err = filesystem.ErrConflict
	}
	return errors.Join(err, v.File.Close())
}
func (c *copier) own(ctx context.Context, v filesystem.Value) (block.Source, error) {
	b, err := c.command.s.store(ctx, v, &c.transferred)
	if err != nil {
		return nil, err
	}
	return &blobValue{owner: c.command.s, ctx: ctx, ref: b}, nil
}
func (c *copier) attributes(ctx context.Context, e *copyEntry) (map[string]block.Source, error) {
	attrs := map[string]block.Source{}
	if c.options.NoAttributes {
		return attrs, nil
	}
	var names []string
	if c.options.FromHost {
		var err error
		names, err = hostAttributes(e.path)
		if errors.Is(err, filesystem.ErrUnsupported) {
			e.node.AttributesUnavailable = true
			return attrs, nil
		}
		if err != nil {
			return nil, err
		}
	} else {
		if err := c.command.tree.ListAttributes(ctx, e.node.Identity.Object, func(name string) error { names = append(names, name); return nil }); err != nil {
			return nil, err
		}
	}
	if len(names) > 4096 {
		return nil, filesystem.ErrLimit
	}
	removed := map[string]bool{}
	if !c.options.FromHost && e.node.Metadata.Mode.Value&0170000 == 0100000 {
		_, r, err := edit.ReplacementNode(ctx, c.command.tree, e.node, e.node.Size)
		if err != nil {
			return nil, err
		}
		removed = r
	}
	for _, name := range names {
		if removed[name] {
			continue
		}
		var v filesystem.Value
		var err error
		if c.options.FromHost {
			v, err = hostAttribute(e.path, name, c.command.s.document.Config.Limits.ValueBytes)
		} else {
			v, err = c.command.tree.OpenAttribute(ctx, e.node.Identity.Object, name)
		}
		if err != nil {
			return nil, err
		}
		data, err := c.own(ctx, v)
		if err != nil {
			return nil, err
		}
		attrs[name] = data
	}
	return attrs, nil
}
func (c *copier) metadata(e copyEntry) (filesystem.Metadata, []string, error) {
	s := c.command.s
	m := c.command.creation(e.node.Metadata.Mode.Value & 0170000)
	src := e.node.Metadata
	var defaults []string
	kind := src.Mode.Value & 0170000
	bits := uint32(0644)
	switch kind {
	case 0040000:
		bits = 0755
	case 0120000:
		bits = 0777
	}
	if src.Mode.State == filesystem.Present {
		bits = src.Mode.Value & 07777
		if !c.options.Preserve && kind == 0100000 {
			bits &^= s.document.Config.Umask
			bits &^= 06000
		}
	} else {
		defaults = append(defaults, "mode")
	}
	m.Mode = filesystem.Observed(kind | bits)
	if c.options.Preserve {
		for _, field := range []struct {
			name string
			src  filesystem.Observation[uint32]
			dst  *filesystem.Observation[uint32]
		}{{"uid", src.UID, &m.UID}, {"gid", src.GID, &m.GID}, {"bsdFlags", src.BSDFlags, &m.BSDFlags}} {
			if field.src.State == filesystem.Present {
				*field.dst = field.src
			} else {
				defaults = append(defaults, field.name)
			}
		}
		for _, field := range []struct {
			name string
			src  filesystem.Observation[time.Time]
			dst  *filesystem.Observation[time.Time]
		}{{"birthTime", src.BirthTime, &m.BirthTime}, {"modifyTime", src.ModifyTime, &m.ModifyTime}, {"accessTime", src.AccessTime, &m.AccessTime}} {
			if field.src.State == filesystem.Present {
				v, err := edit.NativeTime(s.NameRules(), field.src.Value)
				if err != nil {
					return m, nil, err
				}
				*field.dst = filesystem.Observed(v)
			} else {
				defaults = append(defaults, field.name)
			}
		}
	} else {
		for _, field := range []struct {
			name  string
			state filesystem.State
		}{{"uid", src.UID.State}, {"gid", src.GID.State}, {"bsdFlags", src.BSDFlags.State}} {
			if field.state != filesystem.Present {
				defaults = append(defaults, field.name)
			}
		}
	}
	m.BSDFlags.Value &^= 32
	return m, defaults, nil
}
func (c *copier) copy(ctx context.Context, e copyEntry, dst string, depth int) error {
	c.count++
	if depth > c.command.s.document.Config.Limits.Depth || c.count > c.command.s.document.Config.Limits.Entries {
		return filesystem.ErrLimit
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	kind := e.node.Metadata.Mode.Value & 0170000
	current, err := resolve(ctx, c.command.tree, dst, kind == 0100000)
	exists := err == nil
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if !exists && current.path != "" {
		dst = current.path
	}
	if exists {
		n, err := c.command.tree.Stat(ctx, current.id)
		if err != nil {
			return err
		}
		if !c.options.FromHost && current.id == e.node.Identity.Object {
			return filesystem.ErrConflict
		}
		if kind == 0040000 && n.Metadata.Mode.Value&0170000 != 0040000 {
			return fs.ErrInvalid
		}
		if kind != 0040000 && n.Metadata.Mode.Value&0170000 == 0040000 {
			return fs.ErrInvalid
		}
		if c.options.NoClobber && kind != 0040000 {
			return fs.ErrExist
		}
	}
	m, defaults, err := c.metadata(e)
	if err != nil {
		return err
	}
	switch kind {
	case 0040000:
		if !c.options.Recursive {
			return fs.ErrInvalid
		}
		if c.active[e.key] {
			return filesystem.ErrConflict
		}
		c.active[e.key] = true
		defer delete(c.active, e.key)
		if !exists {
			if err = c.command.apply(ctx, edit.Change{Op: edit.CreateDirectory, Path: dst, Metadata: &m}); err != nil {
				return err
			}
			if err = c.command.parentTime(ctx, dst); err != nil {
				return err
			}
		}
		children, err := c.children(ctx, e)
		if err != nil {
			return err
		}
		keys := map[string]bool{}
		for _, name := range children {
			key := c.command.s.key(name)
			if keys[key] {
				return filesystem.ErrConflict
			}
			keys[key] = true
		}
		for _, name := range children {
			p := path.Join(e.path, name)
			if c.options.FromHost {
				p = filepath.Join(e.path, name)
			}
			child, err := c.stat(ctx, p, c.options.Follow == "L")
			if err != nil {
				return err
			}
			if err = c.copy(ctx, child, path.Join(dst, name), depth+1); err != nil {
				return err
			}
		}
	case 0120000:
		if exists {
			if err = c.command.apply(ctx, edit.Change{Op: edit.RemoveEntry, Path: dst}); err != nil {
				return err
			}
		}
		var target string
		if c.options.FromHost {
			target, err = os.Readlink(e.path)
		} else {
			target, err = c.command.tree.Readlink(ctx, e.node.Identity.Object)
		}
		if err != nil {
			return err
		}
		if err = c.command.apply(ctx, edit.Change{Op: edit.CreateSymlink, Path: dst, Target: target, Metadata: &m}); err != nil {
			return err
		}
		if err = c.command.parentTime(ctx, dst); err != nil {
			return err
		}
	default:
		if first := c.links[e.key]; c.options.PreserveLinks && first != "" {
			if exists {
				if err = c.command.apply(ctx, edit.Change{Op: edit.RemoveEntry, Path: dst}); err != nil {
					return err
				}
			}
			if err = c.command.apply(ctx, edit.Change{Op: edit.CreateHardLink, Path: first, To: dst}); err != nil {
				return err
			}
			return c.command.parentTime(ctx, dst)
		}
		v, err := c.sourceData(ctx, e)
		if err != nil {
			return err
		}
		data, err := c.own(ctx, v)
		if err != nil {
			return err
		}
		if exists {
			dst = current.path
			if err = c.command.apply(ctx, edit.Change{Op: edit.ReplaceFileData, Path: dst, Data: data}); err != nil {
				return err
			}
		} else {
			if err = c.command.apply(ctx, edit.Change{Op: edit.CreateFile, Path: dst, Data: data, Metadata: &m}); err != nil {
				return err
			}
			if err = c.command.parentTime(ctx, dst); err != nil {
				return err
			}
		}
		c.links[e.key] = dst
	}
	at, err := resolve(ctx, c.command.tree, dst, false)
	if err != nil {
		return err
	}
	attrs, err := c.attributes(ctx, &e)
	if err != nil {
		return err
	}
	if err = c.command.tree.CopyAttributes(ctx, at.id, attrs); err != nil {
		return err
	}
	if !c.options.NoAttributes {
		if err = c.command.tree.AttributeAvailability(ctx, at.id, e.node.AttributesUnavailable); err != nil {
			return err
		}
	}
	if c.options.Preserve {
		m.ChangeTime = filesystem.Observation[time.Time]{}
		// Birth time preservation is qualified independently from runtime ctime.
		if err = c.command.apply(ctx, edit.Change{Op: edit.SetMetadata, Path: at.path, Metadata: &m}); err != nil {
			return err
		}
	} else if kind == 0100000 {
		if err = c.command.tree.Times(ctx, at.id, nil, &c.command.now, nil); err != nil {
			return err
		}
	}
	if err = c.command.changeTime(ctx, at.id); err != nil {
		return err
	}
	if err = c.command.tree.Defaults(ctx, at.id, defaults); err != nil {
		return err
	}
	if c.options.FromHost {
		after, err := os.Lstat(e.path)
		if err != nil {
			return err
		}
		if !os.SameFile(after, e.info) || after.Size() != e.info.Size() || !after.ModTime().Equal(e.info.ModTime()) {
			return filesystem.ErrConflict
		}
		metadata, _, err := hostMetadata(e.path)
		if err != nil {
			return err
		}
		if metadata.ChangeTime.State == filesystem.Present && !metadata.ChangeTime.Value.Equal(e.node.Metadata.ChangeTime.Value) {
			return filesystem.ErrConflict
		}
	}
	c.command.changed = true
	return nil
}
