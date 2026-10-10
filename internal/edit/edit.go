// Package edit implements the shared logical filesystem edit engine.
package edit

import (
	"context"
	"fmt"
	"io/fs"
	"math"
	"strings"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/names"
)

// Operation selects one ordered tree, content, metadata or attribute edit.
type Operation string

const (
	CreateFile          Operation = "create"
	CreateDirectory     Operation = "mkdir"
	CreateSymlink       Operation = "symlink"
	CreateHardLink      Operation = "link"
	RenameEntry         Operation = "rename"
	RemoveEntry         Operation = "remove"
	ReplaceFileData     Operation = "replace"
	SetMetadata         Operation = "metadata"
	SetAttribute        Operation = "setxattr"
	RemoveAttribute     Operation = "removexattr"
	ReplaceResourceFork Operation = "resource-fork"
)

// Change uses original filesystem paths, relative to the workspace root. Link
// and rename use Path as their source and To as their destination. Symlink uses
// Path as its new name and Target as literal target bytes. Intermediate symlinks
// are never followed. Data is borrowed and must remain immutable until Edit ends.
// Creation requires explicit, fully observed metadata including the object type.
// SetMetadata uses Present fields as assignments and Uncaptured fields as omissions.
// Fields unrelated to the operation must be zero; directory removal is empty-only.
type Change struct {
	Op       Operation            `json:"op"`
	Path     string               `json:"path"`
	To       string               `json:"to,omitempty"`
	Target   string               `json:"target,omitempty"`
	Metadata *filesystem.Metadata `json:"metadata,omitempty"`
	Data     block.Source         `json:"-"`
	// Attributes are explicit initial values for a new object, including forks.
	Attributes map[string]block.Source `json:"-"`
	// Attribute names a setxattr/removexattr value. Resource forks use the
	// resource-fork operation for complete replacement, including truncation.
	Attribute     string        `json:"attribute,omitempty"`
	AttributeMode AttributeMode `json:"attributeMode,omitempty"`
}

type editedObject struct {
	node       filesystem.Node
	data       block.Source
	target     string
	removed    map[string]bool
	attributes map[string]block.Source
	fresh      bool
	refs       int
}
type Tree struct {
	filesystem.Reader
	key      func(string) string
	nodes    map[uint64]*editedObject
	entries  map[uint64]map[string]filesystem.DirEntry
	parents  map[uint64]uint64
	replaced map[uint64]bool
	next     uint64
	count    int
	supplied int64
	limits   Limits
}

// New borrows a reader and builds its bounded directory graph. The caller owns
// the reader and all supplied values for the lifetime of the tree.
func New(ctx context.Context, base filesystem.Reader, limits Limits) (*Tree, error) {
	limits, err := limits.Normalize()
	if err != nil {
		return nil, err
	}
	key, err := NameKey(base.NameRules())
	if err != nil {
		return nil, err
	}
	r := &Tree{Reader: base, key: key, nodes: map[uint64]*editedObject{}, entries: map[uint64]map[string]filesystem.DirEntry{}, parents: map[uint64]uint64{}, replaced: map[uint64]bool{}, limits: limits}
	var visit func(uint64, int) error
	visit = func(id uint64, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if depth > limits.Depth || r.count >= limits.Entries {
			return filesystem.ErrLimit
		}
		r.count++
		if o, ok := r.nodes[id]; ok {
			if o.node.Metadata.Mode.Value&0170000 == 0040000 {
				return filesystem.ErrCorrupt
			}
			o.refs++
			return nil
		}
		if len(r.nodes) >= limits.Objects {
			return filesystem.ErrLimit
		}
		n, err := base.Stat(ctx, id)
		if err != nil {
			return err
		}
		if n.Identity.Object != id {
			return filesystem.ErrCorrupt
		}
		r.nodes[id] = &editedObject{node: copyNode(n), refs: 1}
		if id > r.next {
			r.next = id
		}
		if n.Metadata.Mode.Value&0170000 != 0040000 {
			return nil
		}
		r.entries[id] = map[string]filesystem.DirEntry{}
		return base.ReadDir(ctx, id, func(e filesystem.DirEntry) error {
			if !validComponent(e.Name) || r.entries[id][key(e.Name)].Object != 0 {
				return filesystem.ErrCorrupt
			}
			r.entries[id][key(e.Name)] = e
			if err := visit(e.Object, depth+1); err != nil {
				return err
			}
			if r.nodes[e.Object].node.Metadata.Mode.Value&0170000 == 0040000 {
				r.parents[e.Object] = id
			}
			return nil
		})
	}
	if err := visit(base.Root(), 0); err != nil {
		return nil, err
	}
	for _, o := range r.nodes {
		if o.node.Metadata.Mode.Value&0170000 == 0100000 && o.node.Links.State == filesystem.Present && uint64(o.node.Links.Value) < uint64(o.refs) {
			return nil, filesystem.ErrCorrupt
		}
	}
	return r, nil
}

func (r *Tree) getNode(ctx context.Context, id uint64) (*editedObject, error) {
	if _, err := r.Reader.Stat(ctx, r.Root()); err != nil {
		return nil, err
	}
	o, ok := r.nodes[id]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return o, nil
}
func (r *Tree) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	o, err := r.getNode(ctx, id)
	if err != nil {
		return filesystem.Node{}, err
	}
	return copyNode(o.node), nil
}
func (r *Tree) ReadDir(ctx context.Context, id uint64, yield func(filesystem.DirEntry) error) error {
	if yield == nil {
		return fs.ErrInvalid
	}
	if _, err := r.getNode(ctx, id); err != nil {
		return err
	}
	entries, ok := r.entries[id]
	if !ok {
		return fs.ErrInvalid
	}
	for _, e := range entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := yield(e); err != nil {
			return err
		}
	}
	return ctx.Err()
}
func (r *Tree) Lookup(ctx context.Context, id uint64, name string) (filesystem.DirEntry, error) {
	if !validComponent(name) || !utf8.ValidString(name) {
		return filesystem.DirEntry{}, fs.ErrInvalid
	}
	if _, err := r.getNode(ctx, id); err != nil {
		return filesystem.DirEntry{}, err
	}
	entries, ok := r.entries[id]
	if !ok {
		return filesystem.DirEntry{}, fs.ErrInvalid
	}
	e, ok := entries[r.key(name)]
	if !ok {
		return e, fs.ErrNotExist
	}
	return e, nil
}
func (r *Tree) OpenData(ctx context.Context, id uint64) (filesystem.Value, error) {
	o, err := r.getNode(ctx, id)
	if err != nil {
		return nil, err
	}
	if o.data != nil {
		return &replacementValue{o.data, ctx}, nil
	}
	if o.fresh {
		return nil, fs.ErrInvalid
	}
	return r.Reader.OpenData(ctx, id)
}
func (r *Tree) OpenRawData(ctx context.Context, id uint64) (filesystem.Value, error) {
	o, err := r.getNode(ctx, id)
	if err != nil {
		return nil, err
	}
	if o.data != nil {
		return r.OpenData(ctx, id)
	}
	if o.fresh {
		return nil, fs.ErrInvalid
	}
	return r.Reader.OpenRawData(ctx, id)
}
func (r *Tree) ListAttributes(ctx context.Context, id uint64, yield func(string) error) error {
	if yield == nil {
		return fs.ErrInvalid
	}
	o, err := r.getNode(ctx, id)
	if err != nil {
		return err
	}
	if !o.fresh {
		if err := r.Reader.ListAttributes(ctx, id, func(name string) error {
			if o.removed[name] || o.attributes[name] != nil {
				return nil
			}
			return yield(name)
		}); err != nil {
			return err
		}
	}
	for name := range o.attributes {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := yield(name); err != nil {
			return err
		}
	}
	return nil
}
func (r *Tree) OpenAttribute(ctx context.Context, id uint64, name string) (filesystem.Value, error) {
	o, err := r.getNode(ctx, id)
	if err != nil {
		return nil, err
	}
	if value, ok := o.attributes[name]; ok {
		return &replacementValue{value, ctx}, nil
	}
	if o.fresh || o.removed[name] {
		return nil, fs.ErrNotExist
	}
	return r.Reader.OpenAttribute(ctx, id, name)
}
func (r *Tree) Readlink(ctx context.Context, id uint64) (string, error) {
	o, err := r.getNode(ctx, id)
	if err != nil {
		return "", err
	}
	if o.fresh {
		if o.node.Metadata.Mode.Value&0170000 != 0120000 {
			return "", fs.ErrInvalid
		}
		return o.target, nil
	}
	return r.Reader.Readlink(ctx, id)
}

func (r *Tree) parent(ctx context.Context, p string) (uint64, string, error) {
	p = strings.TrimPrefix(p, "/")
	if len(p) > r.limits.Depth*1025 {
		return 0, "", filesystem.ErrLimit
	}
	if !fs.ValidPath(p) || p == "." {
		return 0, "", fs.ErrInvalid
	}
	parts := strings.Split(p, "/")
	if len(parts) > r.limits.Depth {
		return 0, "", filesystem.ErrLimit
	}
	id := r.Root()
	for _, part := range parts[:len(parts)-1] {
		e, err := r.Lookup(ctx, id, part)
		if err != nil {
			return 0, "", err
		}
		id = e.Object
	}
	if _, err := r.getNode(ctx, id); err != nil {
		return 0, "", err
	}
	if _, ok := r.entries[id]; !ok {
		return 0, "", fs.ErrInvalid
	}
	name := parts[len(parts)-1]
	if !validComponent(name) || !utf8.ValidString(name) {
		return 0, "", fs.ErrInvalid
	}
	return id, name, nil
}
func (r *Tree) storedName(name string) (string, error) {
	return names.Stored(name, r.NameRules().Format)
}
func (r *Tree) supply(data block.Source) error {
	if data == nil || data.Size() < 0 {
		return fs.ErrInvalid
	}
	size := data.Size()
	if size > r.limits.ValueBytes || size > r.limits.TotalBytes-r.supplied {
		return filesystem.ErrLimit
	}
	r.supplied += size
	return nil
}
func (r *Tree) Apply(ctx context.Context, c Change) error {
	if err := c.valid(); err != nil {
		return err
	}
	if c.Op == SetMetadata || c.Op == SetAttribute || c.Op == RemoveAttribute || c.Op == ReplaceResourceFork {
		return r.editMetadata(ctx, c)
	}
	parent, name, err := r.parent(ctx, c.Path)
	if err != nil {
		return err
	}
	key := r.key(name)
	entry, exists := r.entries[parent][key]
	switch c.Op {
	case CreateFile, CreateDirectory, CreateSymlink:
		if exists {
			return fs.ErrExist
		}
		stored, err := r.storedName(name)
		if err != nil {
			return err
		}
		return r.create(parent, stored, c)
	case RemoveEntry:
		if !exists {
			return fs.ErrNotExist
		}
		return r.unlink(parent, key)
	case ReplaceFileData:
		if !exists {
			return fs.ErrNotExist
		}
		if r.replaced[entry.Object] {
			return filesystem.ErrConflict
		}
		if err := r.supply(c.Data); err != nil {
			return err
		}
		o := r.nodes[entry.Object]
		n, removed, err := ReplacementNode(ctx, r, o.node, uint64(c.Data.Size()))
		if err != nil {
			return err
		}
		o.node, o.data = n, c.Data
		for name := range removed {
			o.removeAttribute(name)
		}
		r.replaced[entry.Object] = true
		return nil
	case CreateHardLink, RenameEntry:
		if !exists {
			return fs.ErrNotExist
		}
		to, name, err := r.parent(ctx, c.To)
		if err != nil {
			return err
		}
		stored, err := r.storedName(name)
		if err != nil {
			return err
		}
		toKey := r.key(stored)
		target, occupied := r.entries[to][toKey]
		o := r.nodes[entry.Object]
		if c.Op == CreateHardLink {
			if occupied {
				return fs.ErrExist
			}
			if o.node.Metadata.Mode.Value&0170000 != 0100000 {
				return fs.ErrInvalid
			}
			if r.count >= r.limits.Entries {
				return filesystem.ErrLimit
			}
			if err := r.linkCount(o, 1); err != nil {
				return err
			}
			r.entries[to][toKey] = filesystem.DirEntry{Name: stored, Object: entry.Object}
			o.refs++
			r.count++
			return nil
		}
		if occupied && target.Object == entry.Object {
			if parent == to && key == toKey {
				r.entries[parent][key] = filesystem.DirEntry{Name: stored, Object: entry.Object}
			}
			return nil
		}
		if o.node.Metadata.Mode.Value&0170000 == 0040000 {
			for p := to; p != 0; p = r.parents[p] {
				if p == entry.Object {
					return fs.ErrInvalid
				}
			}
		}
		if occupied {
			oldDir := o.node.Metadata.Mode.Value&0170000 == 0040000
			newDir := r.nodes[target.Object].node.Metadata.Mode.Value&0170000 == 0040000
			if oldDir != newDir {
				return fs.ErrInvalid
			}
			if err := r.unlink(to, toKey); err != nil {
				return err
			}
		}
		delete(r.entries[parent], key)
		r.entries[to][toKey] = filesystem.DirEntry{Name: stored, Object: entry.Object}
		if o.node.Metadata.Mode.Value&0170000 == 0040000 {
			r.parents[entry.Object] = to
		}
		return nil
	default:
		return fs.ErrInvalid
	}
}
func (c Change) valid() error {
	if c.Op != SetAttribute && c.Op != RemoveAttribute && (c.Attribute != "" || c.AttributeMode != "") {
		return fs.ErrInvalid
	}
	if c.Op != CreateFile && c.Op != CreateDirectory && c.Op != CreateSymlink && c.Attributes != nil {
		return fs.ErrInvalid
	}
	switch c.Op {
	case SetMetadata:
		if c.Metadata == nil || c.Data != nil || c.To != "" || c.Target != "" {
			return fs.ErrInvalid
		}
	case SetAttribute:
		if c.Attribute == "" || c.Data == nil || c.Metadata != nil || c.To != "" || c.Target != "" {
			return fs.ErrInvalid
		}
		if c.AttributeMode != AttributeUpsert && c.AttributeMode != AttributeCreate && c.AttributeMode != AttributeReplace {
			return fs.ErrInvalid
		}
	case RemoveAttribute:
		if c.Attribute == "" || c.AttributeMode != "" || c.Data != nil || c.Metadata != nil || c.To != "" || c.Target != "" {
			return fs.ErrInvalid
		}
	case ReplaceResourceFork:
		if c.Data == nil || c.Metadata != nil || c.To != "" || c.Target != "" {
			return fs.ErrInvalid
		}
	case CreateFile:
		if c.Data == nil || c.Metadata == nil || c.To != "" || c.Target != "" {
			return fs.ErrInvalid
		}
	case CreateDirectory:
		if c.Data != nil || c.Metadata == nil || c.To != "" || c.Target != "" {
			return fs.ErrInvalid
		}
	case CreateSymlink:
		if c.Data != nil || c.Metadata == nil || c.To != "" || c.Target == "" || len(c.Target) > 1024 || strings.ContainsRune(c.Target, 0) {
			return fs.ErrInvalid
		}
	case ReplaceFileData:
		if c.Data == nil || c.Metadata != nil || c.To != "" || c.Target != "" {
			return fs.ErrInvalid
		}
	case RemoveEntry:
		if c.Data != nil || c.Metadata != nil || c.To != "" || c.Target != "" {
			return fs.ErrInvalid
		}
	case RenameEntry, CreateHardLink:
		if c.Data != nil || c.Metadata != nil || c.To == "" || c.Target != "" {
			return fs.ErrInvalid
		}
	default:
		return fs.ErrInvalid
	}
	return nil
}
func (r *Tree) create(parent uint64, name string, c Change) error {
	if r.next == math.MaxUint64 || len(r.nodes) >= r.limits.Objects || r.count >= r.limits.Entries {
		return filesystem.ErrLimit
	}
	m := *c.Metadata
	for _, s := range []filesystem.State{m.Mode.State, m.UID.State, m.GID.State, m.BSDFlags.State, m.BirthTime.State, m.ModifyTime.State, m.ChangeTime.State, m.AccessTime.State} {
		if s != filesystem.Present {
			return fs.ErrInvalid
		}
	}
	want := map[Operation]uint32{CreateFile: 0100000, CreateDirectory: 0040000, CreateSymlink: 0120000}[c.Op]
	if m.Mode.Value&0170000 != want || m.Mode.Value&^uint32(0177777) != 0 || m.BSDFlags.Value&32 != 0 {
		return fs.ErrInvalid
	}
	if c.Op == CreateFile {
		if err := r.supply(c.Data); err != nil {
			return err
		}
	}
	if len(c.Attributes) > maxAttributes {
		return filesystem.ErrLimit
	}
	attrs := map[string]block.Source{}
	for name, value := range c.Attributes {
		if name == "" || len(name) > 1024 || strings.ContainsRune(name, 0) {
			return fs.ErrInvalid
		}
		if err := r.supply(value); err != nil {
			return err
		}
		attrs[name] = value
	}
	r.next++
	n := filesystem.Node{Created: true, Identity: filesystem.Identity{Object: r.next}, Metadata: m, Compression: filesystem.Observation[filesystem.Compression]{State: filesystem.Absent}, Links: filesystem.Observed(uint32(1))}
	if c.Op == CreateFile {
		n.Size = uint64(c.Data.Size())
		n.DataModified = true
	}
	if c.Op == CreateSymlink {
		n.Size = uint64(len(c.Target))
	}
	if c.Op == CreateDirectory {
		n.Links = filesystem.Observation[uint32]{}
		r.entries[r.next] = map[string]filesystem.DirEntry{}
		r.parents[r.next] = parent
	}
	r.nodes[r.next] = &editedObject{node: n, data: c.Data, target: c.Target, fresh: true, refs: 1, attributes: attrs}
	r.entries[parent][r.key(name)] = filesystem.DirEntry{Name: name, Object: r.next}
	r.count++
	return nil
}
func (r *Tree) linkCount(o *editedObject, delta int) error {
	n := &o.node
	if n.Links.State != filesystem.Present {
		return filesystem.ErrUnsupported
	}
	if n.Links.Value == 0 {
		return filesystem.ErrCorrupt
	}
	if delta > 0 && n.Links.Value == math.MaxUint32 {
		return filesystem.ErrLimit
	}
	n.Links.Value = uint32(int64(n.Links.Value) + int64(delta))
	n.LinksModified = true
	return nil
}
func (r *Tree) unlink(parent uint64, key string) error {
	e := r.entries[parent][key]
	o := r.nodes[e.Object]
	if o.node.Metadata.Mode.Value&0170000 == 0040000 {
		if len(r.entries[e.Object]) != 0 {
			return fmt.Errorf("directory is not empty: %w", filesystem.ErrConflict)
		}
		delete(r.entries, e.Object)
		delete(r.parents, e.Object)
	} else if err := r.linkCount(o, -1); err != nil {
		return err
	}
	o.refs--
	if o.refs == 0 {
		delete(r.nodes, e.Object)
	}
	delete(r.entries[parent], key)
	r.count--
	return nil
}
