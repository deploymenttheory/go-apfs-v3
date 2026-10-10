package session

import (
	"bytes"
	"context"
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/edit"
	"github.com/deploymenttheory/go-apfs-v3/internal/mode"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"time"
)

func creationMetadata(c configuration, mode uint32, now time.Time) filesystem.Metadata {
	return filesystem.Metadata{Mode: filesystem.Observed(mode), UID: filesystem.Observed(c.UID), GID: filesystem.Observed(c.GID), BSDFlags: filesystem.Observed(uint32(0)), BirthTime: filesystem.Observed(now), ModifyTime: filesystem.Observed(now), ChangeTime: filesystem.Observed(now), AccessTime: filesystem.Observed(now)}
}

type command struct {
	s       *Session
	tree    *edit.Tree
	now     time.Time
	changed bool
}

func (s *Session) mutate(ctx context.Context, operation func(*command) error) (report Report, err error) {
	if s.closed {
		return report, fs.ErrClosed
	}
	if err := s.clean(ctx); err != nil {
		return report, err
	}
	now := time.Now().UTC()
	if s.document.Config.Time != nil {
		now = *s.document.Config.Time
	}
	now, err = edit.NativeTime(s.NameRules(), now)
	if err != nil {
		return report, err
	}
	tree, err := edit.New(ctx, s, s.document.Config.Limits)
	if err != nil {
		return report, err
	}
	c := &command{s: s, tree: tree, now: now}
	if err = operation(c); err != nil {
		return report, err
	}
	if c.changed {
		if err = s.save(ctx, tree); err != nil {
			return report, err
		}
	}
	return s.Report(), nil
}
func (c *command) apply(ctx context.Context, change edit.Change) error {
	if err := c.tree.ApplyCommand(ctx, change); err != nil {
		return err
	}
	c.changed = true
	return nil
}
func (c *command) changeTime(ctx context.Context, id uint64) error {
	return c.tree.Times(ctx, id, nil, nil, &c.now)
}
func (c *command) parentTime(ctx context.Context, p string) error {
	at, err := resolve(ctx, c.tree, path.Dir(p), true)
	if err != nil {
		return err
	}
	return c.tree.Times(ctx, at.id, nil, &c.now, &c.now)
}
func (c *command) creation(mode uint32) filesystem.Metadata {
	return creationMetadata(c.s.document.Config, mode, c.now)
}
func (s *Session) Chmod(ctx context.Context, paths []string, expression string, o WalkOptions) (Report, error) {
	program, err := mode.Parse(expression, s.document.Config.Umask)
	if err != nil {
		return Report{}, err
	}
	return s.patch(ctx, paths, o, func(n filesystem.Node) (filesystem.Metadata, error) {
		return filesystem.Metadata{Mode: filesystem.Observed(program.Apply(n.Metadata.Mode.Value))}, nil
	})
}
func (s *Session) Chown(ctx context.Context, paths []string, owner string, o WalkOptions) (Report, error) {
	o.includeLinks = true
	parts := strings.Split(owner, ":")
	if len(parts) > 2 || owner == "" || owner == ":" {
		return Report{}, fs.ErrInvalid
	}
	m := filesystem.Metadata{}
	if parts[0] != "" {
		v, e := strconv.ParseUint(parts[0], 10, 32)
		if e != nil || uint32(v) == ^uint32(0) {
			return Report{}, fs.ErrInvalid
		}
		m.UID = filesystem.Observed(uint32(v))
	}
	if len(parts) == 2 && parts[1] != "" {
		v, e := strconv.ParseUint(parts[1], 10, 32)
		if e != nil || uint32(v) == ^uint32(0) {
			return Report{}, fs.ErrInvalid
		}
		m.GID = filesystem.Observed(uint32(v))
	}
	return s.patch(ctx, paths, o, func(filesystem.Node) (filesystem.Metadata, error) { return m, nil })
}
func (s *Session) Chflags(ctx context.Context, paths []string, flags string, o WalkOptions) (Report, error) {
	names := map[string]uint32{"nodump": 1, "uchg": 2, "uchange": 2, "uimmutable": 2, "uappnd": 4, "uappend": 4, "opaque": 8, "hidden": 0x8000}
	if flags == "" {
		return Report{}, fs.ErrInvalid
	}
	return s.patch(ctx, paths, o, func(n filesystem.Node) (filesystem.Metadata, error) {
		if n.Metadata.BSDFlags.State != filesystem.Present {
			return filesystem.Metadata{}, filesystem.ErrUnsupported
		}
		v := n.Metadata.BSDFlags.Value
		if flags[0] >= '0' && flags[0] <= '9' {
			number, e := strconv.ParseUint(flags, 8, 32)
			if e != nil || uint32(number)&^uint32(0x800f) != 0 {
				return filesystem.Metadata{}, filesystem.ErrUnsupported
			}
			v = v&^uint32(0x800f) | uint32(number)
		} else {
			for _, name := range strings.Split(flags, ",") {
				bit, ok := names[name]
				remove := false
				if !ok && strings.HasPrefix(name, "no") {
					bit, ok = names[name[2:]]
					remove = true
				}
				if !ok {
					return filesystem.Metadata{}, filesystem.ErrUnsupported
				}
				if remove {
					v &^= bit
				} else {
					v |= bit
				}
			}
		}
		return filesystem.Metadata{BSDFlags: filesystem.Observed(v)}, nil
	})
}
func (s *Session) patch(ctx context.Context, paths []string, o WalkOptions, makePatch func(filesystem.Node) (filesystem.Metadata, error)) (Report, error) {
	return s.mutate(ctx, func(c *command) error {
		targets, err := collect(ctx, c.tree, paths, o)
		if err != nil {
			return err
		}
		for _, at := range targets {
			n, err := c.tree.Stat(ctx, at.id)
			if err != nil {
				return err
			}
			m, err := makePatch(n)
			if err != nil {
				return err
			}
			if err = c.apply(ctx, edit.Change{Op: edit.SetMetadata, Path: at.path, Metadata: &m}); err != nil {
				return err
			}
			if err = c.changeTime(ctx, at.id); err != nil {
				return err
			}
		}
		return nil
	})
}

type MkdirOptions struct {
	Parents bool
	Mode    string
}

func (s *Session) Mkdir(ctx context.Context, paths []string, o MkdirOptions) (Report, error) {
	if len(paths) == 0 {
		return Report{}, fs.ErrInvalid
	}
	return s.mutate(ctx, func(c *command) error {
		bits := uint32(0777) &^ s.document.Config.Umask
		if o.Mode != "" {
			program, err := mode.Parse(o.Mode, s.document.Config.Umask)
			if err != nil {
				return err
			}
			bits = program.Apply(0040000|bits) & 07777
		}
		for _, p := range paths {
			parts := []string{p}
			if o.Parents {
				parts = nil
				current := "/"
				for _, name := range strings.Split(p, "/") {
					if name == "" || name == "." {
						continue
					}
					current = strings.TrimRight(current, "/") + "/" + name
					parts = append(parts, current)
				}
			}
			for i, item := range parts {
				if at, err := resolve(ctx, c.tree, item, true); err == nil {
					n, err := c.tree.Stat(ctx, at.id)
					if err != nil {
						return err
					}
					if !o.Parents || n.Metadata.Mode.Value&0170000 != 0040000 {
						return fs.ErrExist
					}
					continue
				} else if !errors.Is(err, fs.ErrNotExist) {
					return err
				}
				dst, err := destination(ctx, c.tree, item)
				if err != nil {
					return err
				}
				permissions := bits
				if i < len(parts)-1 {
					permissions = 0777&^s.document.Config.Umask | 0300
				}
				m := c.creation(0040000 | permissions)
				if err = c.apply(ctx, edit.Change{Op: edit.CreateDirectory, Path: dst, Metadata: &m}); err != nil {
					return err
				}
				if err = c.parentTime(ctx, dst); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

type TouchOptions struct {
	Access, Modify, NoCreate, NoFollow bool
	Time                               *time.Time
	Reference                          string
}

func (s *Session) Touch(ctx context.Context, paths []string, o TouchOptions) (Report, error) {
	if len(paths) == 0 || (o.Time != nil && o.Reference != "") {
		return Report{}, fs.ErrInvalid
	}
	return s.mutate(ctx, func(c *command) error {
		access, modify := c.now, c.now
		if o.Time != nil {
			access, modify = *o.Time, *o.Time
		}
		if o.Reference != "" {
			at, err := resolve(ctx, c.tree, o.Reference, true)
			if err != nil {
				return err
			}
			n, err := c.tree.Stat(ctx, at.id)
			if err != nil {
				return err
			}
			if n.Metadata.AccessTime.State != filesystem.Present || n.Metadata.ModifyTime.State != filesystem.Present {
				return filesystem.ErrUnsupported
			}
			access, modify = n.Metadata.AccessTime.Value, n.Metadata.ModifyTime.Value
		}
		for _, p := range paths {
			at, err := resolve(ctx, c.tree, p, !o.NoFollow)
			if errors.Is(err, fs.ErrNotExist) {
				if o.NoCreate || o.NoFollow {
					continue
				}
				if strings.HasSuffix(p, "/") {
					return fs.ErrInvalid
				}
				if at.path != "" {
					p = at.path
				}
				dst, e := destination(ctx, c.tree, p)
				if e != nil {
					return e
				}
				m := c.creation(0100000 | 0666&^s.document.Config.Umask)
				if e = c.apply(ctx, edit.Change{Op: edit.CreateFile, Path: dst, Metadata: &m, Data: bytes.NewReader(nil)}); e != nil {
					return e
				}
				if e = c.parentTime(ctx, dst); e != nil {
					return e
				}
				at, err = resolve(ctx, c.tree, dst, false)
			}
			if err != nil {
				return err
			}
			m := filesystem.Metadata{}
			if o.Access || !o.Modify {
				m.AccessTime = filesystem.Observed(access)
			}
			if o.Modify || !o.Access {
				m.ModifyTime = filesystem.Observed(modify)
				n, e := c.tree.Stat(ctx, at.id)
				if e != nil {
					return e
				}
				// Darwin utimes moves birth time back when mtime precedes it.
				if n.Metadata.BirthTime.State == filesystem.Present && modify.Before(n.Metadata.BirthTime.Value) {
					m.BirthTime = filesystem.Observed(modify)
				}
			}
			if err = c.apply(ctx, edit.Change{Op: edit.SetMetadata, Path: at.path, Metadata: &m}); err != nil {
				return err
			}
			if err = c.changeTime(ctx, at.id); err != nil {
				return err
			}
		}
		return nil
	})
}

type RemoveOptions struct{ Recursive, Force bool }

func (s *Session) Remove(ctx context.Context, paths []string, o RemoveOptions) (Report, error) {
	if len(paths) == 0 && !o.Force {
		return Report{}, fs.ErrInvalid
	}
	return s.mutate(ctx, func(c *command) error {
		var remove func(string, int) error
		remove = func(p string, depth int) error {
			if depth > s.document.Config.Limits.Depth {
				return filesystem.ErrLimit
			}
			at, err := resolve(ctx, c.tree, p, false)
			if errors.Is(err, fs.ErrNotExist) && o.Force {
				return nil
			}
			if err != nil {
				return err
			}
			if at.id == c.tree.Root() {
				return fs.ErrInvalid
			}
			n, err := c.tree.Stat(ctx, at.id)
			if err != nil {
				return err
			}
			if n.Metadata.Mode.Value&0170000 == 0040000 {
				if !o.Recursive {
					return fs.ErrInvalid
				}
				var children []filesystem.DirEntry
				if err = c.tree.ReadDir(ctx, at.id, func(e filesystem.DirEntry) error { children = append(children, e); return nil }); err != nil {
					return err
				}
				for _, e := range children {
					if err = remove(path.Join(at.path, e.Name), depth+1); err != nil {
						return err
					}
				}
			}
			if err = c.parentTime(ctx, at.path); err != nil {
				return err
			}
			if n.Metadata.Mode.Value&0170000 != 0040000 {
				if err = c.changeTime(ctx, at.id); err != nil {
					return err
				}
			}
			return c.apply(ctx, edit.Change{Op: edit.RemoveEntry, Path: at.path})
		}
		for _, p := range paths {
			if err := remove(p, 0); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Session) Move(ctx context.Context, source, to string, noClobber bool) (Report, error) {
	return s.mutate(ctx, func(c *command) error {
		at, err := resolve(ctx, c.tree, source, false)
		if err != nil {
			return err
		}
		dst, err := operandDestination(ctx, c.tree, source, to)
		if err != nil {
			return err
		}
		existing, e := resolve(ctx, c.tree, dst, false)
		if e == nil {
			if noClobber {
				return nil
			}
			if existing.id == at.id && (existing.path != at.path || path.Base(dst) == path.Base(at.path)) {
				return nil
			}
		} else if !errors.Is(e, fs.ErrNotExist) {
			return e
		}
		if e == nil && existing.id != at.id {
			if err = c.changeTime(ctx, existing.id); err != nil {
				return err
			}
		}
		if err = c.apply(ctx, edit.Change{Op: edit.RenameEntry, Path: at.path, To: dst}); err != nil {
			return err
		}
		if err = c.changeTime(ctx, at.id); err != nil {
			return err
		}
		if err = c.parentTime(ctx, at.path); err != nil {
			return err
		}
		return c.parentTime(ctx, dst)
	})
}
func operandDestination(ctx context.Context, r filesystem.Reader, source, to string) (string, error) {
	at, err := resolve(ctx, r, to, true)
	if err == nil {
		n, err := r.Stat(ctx, at.id)
		if err != nil {
			return "", err
		}
		if n.Metadata.Mode.Value&0170000 == 0040000 {
			return destination(ctx, r, path.Join(at.path, path.Base(strings.TrimRight(source, "/"))))
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	return destination(ctx, r, to)
}

type LinkOptions struct{ Symbolic, Force bool }

func (s *Session) Link(ctx context.Context, source, to string, o LinkOptions) (Report, error) {
	return s.mutate(ctx, func(c *command) error {
		dst, err := operandDestination(ctx, c.tree, source, to)
		if err != nil {
			return err
		}
		if existing, e := resolve(ctx, c.tree, dst, false); e == nil && o.Force {
			if err = c.changeTime(ctx, existing.id); err != nil {
				return err
			}
			if err = c.apply(ctx, edit.Change{Op: edit.RemoveEntry, Path: dst}); err != nil {
				return err
			}
		} else if e != nil && !errors.Is(e, fs.ErrNotExist) {
			return e
		}
		if o.Symbolic {
			bits := uint32(0777) &^ s.document.Config.Umask
			m := c.creation(0120000 | bits)
			if err = c.apply(ctx, edit.Change{Op: edit.CreateSymlink, Path: dst, Target: source, Metadata: &m}); err != nil {
				return err
			}
		} else {
			at, err := resolve(ctx, c.tree, source, false)
			if err != nil {
				return err
			}
			if err = c.apply(ctx, edit.Change{Op: edit.CreateHardLink, Path: at.path, To: dst}); err != nil {
				return err
			}
			if err = c.changeTime(ctx, at.id); err != nil {
				return err
			}
		}
		return c.parentTime(ctx, dst)
	})
}

type AttributeOptions struct {
	NoFollow bool
	Mode     edit.AttributeMode
}

func (s *Session) SetAttribute(ctx context.Context, paths []string, name string, value block.Source, o AttributeOptions) (Report, error) {
	return s.attribute(ctx, paths, name, value, false, o)
}
func (s *Session) RemoveAttribute(ctx context.Context, paths []string, name string, o AttributeOptions) (Report, error) {
	return s.attribute(ctx, paths, name, nil, true, o)
}
func (s *Session) attribute(ctx context.Context, paths []string, name string, value block.Source, remove bool, o AttributeOptions) (Report, error) {
	if len(paths) == 0 {
		return Report{}, fs.ErrInvalid
	}
	return s.mutate(ctx, func(c *command) error {
		for _, p := range paths {
			at, err := resolve(ctx, c.tree, p, !o.NoFollow)
			if err != nil {
				return err
			}
			op := edit.SetAttribute
			if remove {
				op = edit.RemoveAttribute
			}
			if err = c.apply(ctx, edit.Change{Op: op, Path: at.path, Attribute: name, Data: value, AttributeMode: o.Mode}); err != nil {
				return err
			}
			if err = c.changeTime(ctx, at.id); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Session) ReplaceResourceFork(ctx context.Context, p string, value block.Source) (Report, error) {
	return s.mutate(ctx, func(c *command) error {
		at, err := resolve(ctx, c.tree, p, true)
		if err != nil {
			return err
		}
		if err = c.apply(ctx, edit.Change{Op: edit.ReplaceResourceFork, Path: at.path, Data: value}); err != nil {
			return err
		}
		// APFS named-fork truncation to zero changes the fork without touching
		// inode timestamps; HFS+ and nonempty writes update mtime and ctime.
		if s.NameRules().Format == "APFS" && value.Size() == 0 {
			return nil
		}
		return c.tree.Times(ctx, at.id, nil, &c.now, &c.now)
	})
}
