// Package session supplies persistent logical filesystem commands backed by
// private scratch storage. A handle holds an exclusive process lock. Its methods
// must not be called concurrently. Values borrow the current revision and must
// be closed before mutation. Close releases the lock without deleting data.
package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/edit"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

const maxManifest = 64 << 20

// Options define logical creation defaults, never the host process's credentials.
// Nil Umask uses 022; nil Time samples one clock value for each command.
type Options struct {
	Names  filesystem.NameRules
	UID    uint32
	GID    uint32
	Umask  *uint32
	Time   *time.Time
	Limits workspace.Limits
}

type configuration struct {
	UID    uint32           `json:"uid"`
	GID    uint32           `json:"gid"`
	Umask  uint32           `json:"umask"`
	Time   *time.Time       `json:"time,omitempty"`
	Limits workspace.Limits `json:"limits"`
}

type blob struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type attribute struct {
	Name  string `json:"name"`
	Value blob   `json:"value"`
}
type object struct {
	Node       filesystem.Node       `json:"node"`
	Data       *blob                 `json:"data,omitempty"`
	Raw        *blob                 `json:"raw,omitempty"`
	Target     []byte                `json:"target,omitempty"`
	Attributes []attribute           `json:"attributes"`
	Children   []filesystem.DirEntry `json:"children,omitempty"`
}
type revision struct {
	Schema  int                  `json:"schema"`
	Parent  string               `json:"parent,omitempty"`
	Root    uint64               `json:"root"`
	Names   filesystem.NameRules `json:"names"`
	Config  configuration        `json:"config"`
	Objects []object             `json:"objects"`
}

// Report describes canonical state separately from scratch storage placement.
type Report struct {
	Location              string               `json:"location"`
	Names                 filesystem.NameRules `json:"names"`
	Source                filesystem.Identity  `json:"source"`
	AttributesUnavailable []uint64             `json:"attributesUnavailable,omitempty"`
	Revision              string               `json:"revision"`
	Objects               int                  `json:"objects"`
	Entries               int                  `json:"entries"`
	BlobBytes             int64                `json:"blobBytes"`
	Defaulted             []Default            `json:"defaulted,omitempty"`
}
type Default struct {
	Object uint64   `json:"object"`
	Fields []string `json:"fields"`
}

type Session struct {
	directory string
	root      *os.Root
	lock      *os.File
	document  revision
	digest    string
	objects   map[uint64]object
	key       func(string) string
	closed    bool
	verified  map[string]bool
	// beforePublish is an internal fault-injection seam, after all flushes.
	beforePublish func() error
}

var _ filesystem.Reader = (*Session)(nil)

func config(o Options) (configuration, error) {
	limits, err := o.Limits.Normalize()
	if err != nil {
		return configuration{}, err
	}
	c := configuration{UID: o.UID, GID: o.GID, Umask: 022, Time: o.Time, Limits: limits}
	if o.Umask != nil {
		c.Umask = *o.Umask
	}
	if c.Umask > 0777 || c.UID == ^uint32(0) || c.GID == ^uint32(0) {
		return c, fs.ErrInvalid
	}
	if c.Time != nil {
		v := c.Time.UTC()
		c.Time = &v
	}
	return c, nil
}

// Create starts an empty session in a new directory.
func Create(ctx context.Context, directory string, options Options) (*Session, error) {
	c, err := config(options)
	if err != nil {
		return nil, err
	}
	if _, err = edit.NameKey(options.Names); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if c.Time != nil {
		now = *c.Time
	}
	now, err = edit.NativeTime(options.Names, now)
	if err != nil {
		return nil, err
	}
	m := creationMetadata(c, 0040000|0755, now)
	root := object{Node: filesystem.Node{Created: true, Identity: filesystem.Identity{Object: 1}, Metadata: m, Compression: filesystem.Observation[filesystem.Compression]{State: filesystem.Absent}}}
	seed := &Session{document: revision{Root: 1, Names: options.Names, Config: c}, objects: map[uint64]object{1: root}}
	seed.key, _ = edit.NameKey(options.Names)
	return capture(ctx, directory, seed, c)
}

// Capture owns one complete copy of the supplied reader's tree. Subsequent
// commands do not need its image, unlock credentials or open descriptors.
func Capture(ctx context.Context, source filesystem.Reader, directory string, options Options) (*Session, error) {
	c, err := config(options)
	if err != nil {
		return nil, err
	}
	return capture(ctx, directory, source, c)
}
func capture(ctx context.Context, directory string, source filesystem.Reader, c configuration) (result *Session, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	if err = os.Mkdir(directory, 0700); err != nil {
		return nil, err
	}
	s, err := acquire(directory)
	if err != nil {
		return nil, errors.Join(err, os.RemoveAll(directory))
	}
	defer func(owned *Session) {
		if err != nil {
			err = errors.Join(err, owned.Close(), os.RemoveAll(directory))
		}
	}(s)
	if err = s.root.Mkdir("blobs", 0700); err != nil {
		return nil, err
	}
	if err = s.root.Mkdir("pending", 0700); err != nil {
		return nil, err
	}
	s.document = revision{Schema: 1, Root: source.Root(), Names: source.NameRules(), Config: c}
	s.key, err = edit.NameKey(source.NameRules())
	if err != nil {
		return nil, err
	}
	tree, err := edit.New(ctx, source, c.Limits)
	if err != nil {
		return nil, err
	}
	if err = s.save(ctx, tree); err != nil {
		return nil, err
	}
	return s, nil
}

func acquire(directory string) (s *Session, err error) {
	info, err := os.Lstat(directory)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, fs.ErrInvalid
	}
	directory, err = filepath.Abs(directory)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	s = &Session{directory: directory, root: root, verified: map[string]bool{}}
	defer func(owned *Session) {
		if err != nil {
			err = errors.Join(err, owned.Close())
		}
	}(s)
	// Lock files and the session directory are private and exclude external edits.
	s.lock, err = root.OpenFile("lock", os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err = lockFile(s.lock); err != nil {
		return nil, fmt.Errorf("session is in use: %w", errors.Join(filesystem.ErrConflict, err))
	}
	return s, nil
}

// Open validates the current metadata revision without reading payload bytes.
// Values validate their hashes on first use. Verify checks every stored value.
func Open(ctx context.Context, directory string) (s *Session, err error) {
	s, err = acquire(directory)
	if err != nil {
		return nil, err
	}
	defer func(owned *Session) {
		if err != nil {
			err = errors.Join(err, owned.Close())
		}
	}(s)
	data, err := readBounded(s.root, "current", maxManifest)
	if err != nil {
		return nil, err
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err = d.Decode(&s.document); err != nil {
		return nil, errors.Join(filesystem.ErrCorrupt, err)
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, filesystem.ErrCorrupt
	}
	sum := sha256.Sum256(data)
	s.digest = hex.EncodeToString(sum[:])
	if err = s.index(ctx); err != nil {
		return nil, err
	}
	if err = s.clean(ctx); err != nil {
		return nil, err
	}
	return s, nil
}

// clean recovers abandoned command staging and reclaims unreachable immutable
// blobs before a new transaction, while the exclusive lock is held.
func (s *Session) clean(ctx context.Context) (err error) {
	keep := map[string]bool{}
	for _, o := range s.document.Objects {
		for _, b := range values(o) {
			keep[b.SHA256] = true
		}
	}
	dir, err := s.root.Open("blobs")
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, dir.Close()) }()
	for {
		entries, e := dir.ReadDir(128)
		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}
			name := entry.Name()
			if validBlob(blob{SHA256: name}) && !keep[name] {
				if err := s.root.Remove("blobs/" + name); err != nil {
					return err
				}
				delete(s.verified, name)
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
	}
	if err = s.root.RemoveAll("pending"); err != nil {
		return err
	}
	return s.root.Mkdir("pending", 0700)
}
func readBounded(root *os.Root, name string, limit int64) ([]byte, error) {
	info, err := root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return nil, filesystem.ErrCorrupt
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	b, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	err = errors.Join(readErr, f.Close())
	if int64(len(b)) > limit {
		return nil, filesystem.ErrLimit
	}
	return b, err
}
func validBlob(b blob) bool {
	x, e := hex.DecodeString(b.SHA256)
	return e == nil && len(x) == 32 && hex.EncodeToString(x) == b.SHA256 && b.Size >= 0
}
func (s *Session) index(ctx context.Context) error {
	d := s.document
	if d.Schema != 1 || len(d.Objects) == 0 || len(d.Objects) > workspace.DefaultLimits().Objects {
		return fmt.Errorf("session schema or object count: %w", filesystem.ErrCorrupt)
	}
	c, err := config(Options{UID: d.Config.UID, GID: d.Config.GID, Umask: &d.Config.Umask, Time: d.Config.Time, Limits: d.Config.Limits})
	if err != nil {
		return err
	}
	s.document.Config = c
	s.key, err = edit.NameKey(d.Names)
	if err != nil {
		return err
	}
	if c.Time != nil {
		if _, err = edit.NativeTime(d.Names, *c.Time); err != nil {
			return err
		}
	}
	s.objects = map[uint64]object{}
	var reachable int64
	for _, o := range d.Objects {
		if !edit.ValidNode(o.Node) || s.objects[o.Node.Identity.Object].Node.Identity.Object != 0 {
			return fmt.Errorf("invalid session object metadata: %w", filesystem.ErrCorrupt)
		}
		if o.Node.Created {
			if !strings.HasPrefix(o.Node.Identity.Volume, "workspace:") || !validBlob(blob{SHA256: strings.TrimPrefix(o.Node.Identity.Volume, "workspace:")}) {
				return fmt.Errorf("invalid session object metadata: %w", filesystem.ErrCorrupt)
			}
		}
		kind := o.Node.Metadata.Mode.Value & 0170000
		switch kind {
		case 0100000:
			if o.Data == nil || o.Raw == nil || o.Node.Size != uint64(o.Data.Size) || len(o.Children) != 0 || len(o.Target) != 0 {
				return fmt.Errorf("session data/raw fork metadata: %w", filesystem.ErrCorrupt)
			}
		case 0040000:
			if o.Data != nil || o.Raw != nil || len(o.Target) != 0 {
				return fmt.Errorf("invalid session object metadata: %w", filesystem.ErrCorrupt)
			}
		case 0120000:
			if o.Data != nil || o.Raw != nil || len(o.Children) != 0 || uint64(len(o.Target)) != o.Node.Size {
				return fmt.Errorf("invalid session object metadata: %w", filesystem.ErrCorrupt)
			}
		default:
			return filesystem.ErrUnsupported
		}
		if len(o.Attributes) > 4096 {
			return filesystem.ErrLimit
		}
		for i, a := range o.Attributes {
			if !utf8.ValidString(a.Name) || a.Name == "" || strings.ContainsRune(a.Name, 0) || (i > 0 && o.Attributes[i-1].Name >= a.Name) {
				return fmt.Errorf("invalid session object metadata: %w", filesystem.ErrCorrupt)
			}
		}
		for _, b := range values(o) {
			if b.Size > c.Limits.TotalBytes-reachable {
				return filesystem.ErrLimit
			}
			reachable += b.Size
			if !validBlob(b) || b.Size > c.Limits.ValueBytes {
				return fmt.Errorf("invalid session object metadata: %w", filesystem.ErrCorrupt)
			}
		}
		s.objects[o.Node.Identity.Object] = o
	}
	tree, err := edit.New(ctx, s, c.Limits)
	if err != nil {
		return err
	}
	var count int
	err = walk(ctx, tree, tree.Root(), 0, c.Limits, func(id uint64) error { count++; return nil })
	if err != nil {
		return err
	}
	if count != len(s.objects) {
		return fmt.Errorf("invalid session object metadata: %w", filesystem.ErrCorrupt)
	}
	return nil
}
func values(o object) []blob {
	var b []blob
	if o.Data != nil {
		b = append(b, *o.Data)
	}
	if o.Raw != nil {
		b = append(b, *o.Raw)
	}
	for _, a := range o.Attributes {
		b = append(b, a.Value)
	}
	return b
}

func (s *Session) save(ctx context.Context, r filesystem.Reader) error {
	next := revision{Schema: 1, Parent: s.digest, Root: r.Root(), Names: r.NameRules(), Config: s.document.Config}
	var transferred, reachable int64
	metadataBytes := 0
	err := walk(ctx, r, r.Root(), 0, next.Config.Limits, func(id uint64) error {
		n, err := r.Stat(ctx, id)
		if err != nil {
			return err
		}
		o := object{Node: edit.CopyNode(n)}
		metadataBytes += 2048
		if metadataBytes > maxManifest {
			return filesystem.ErrLimit
		}
		switch n.Metadata.Mode.Value & 0170000 {
		case 0100000:
			v, err := r.OpenData(ctx, id)
			if err != nil {
				return err
			}
			b, err := s.store(ctx, v, &transferred)
			if err != nil {
				return err
			}
			logical := b
			o.Data = &logical
			v, err = r.OpenRawData(ctx, id)
			if err != nil {
				return err
			}
			b, err = s.store(ctx, v, &transferred)
			if err != nil {
				return err
			}
			o.Raw = &b
		case 0040000:
			if err = r.ReadDir(ctx, id, func(e filesystem.DirEntry) error {
				metadataBytes += 256 + 6*len(e.Name)
				if metadataBytes > maxManifest || !utf8.ValidString(e.Name) {
					return filesystem.ErrLimit
				}
				o.Children = append(o.Children, e)
				return nil
			}); err != nil {
				return err
			}
			sort.Slice(o.Children, func(i, j int) bool { return o.Children[i].Name < o.Children[j].Name })
		case 0120000:
			var target string
			target, err = r.Readlink(ctx, id)
			o.Target = []byte(target)
			if err != nil {
				return err
			}
		default:
			return filesystem.ErrUnsupported
		}
		if err = r.ListAttributes(ctx, id, func(name string) error {
			if !utf8.ValidString(name) {
				return filesystem.ErrUnsupported
			}
			metadataBytes += 256 + 6*len(name)
			if metadataBytes > maxManifest {
				return filesystem.ErrLimit
			}
			if len(o.Attributes) >= 4096 {
				return filesystem.ErrLimit
			}
			v, err := r.OpenAttribute(ctx, id, name)
			if err != nil {
				return err
			}
			b, err := s.store(ctx, v, &transferred)
			if err != nil {
				return err
			}
			o.Attributes = append(o.Attributes, attribute{name, b})
			return nil
		}); err != nil {
			return err
		}
		sort.Slice(o.Attributes, func(i, j int) bool { return o.Attributes[i].Name < o.Attributes[j].Name })
		if o.Node.Created && o.Node.Identity.Volume == "" {
			encoded, err := json.Marshal(struct {
				Parent string
				Object object
			}{s.digest, o})
			if err != nil {
				return err
			}
			sum := sha256.Sum256(encoded)
			o.Node.Identity.Volume = "workspace:" + hex.EncodeToString(sum[:])
		}
		if !edit.ValidNode(o.Node) {
			return filesystem.ErrCorrupt
		}
		for _, b := range values(o) {
			if b.Size > next.Config.Limits.TotalBytes-reachable {
				return filesystem.ErrLimit
			}
			reachable += b.Size
		}
		next.Objects = append(next.Objects, o)
		return nil
	})
	if err != nil {
		return err
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if len(data) > maxManifest {
		return filesystem.ErrLimit
	}
	data = append(data, '\n')
	if err = s.writePending("current", data); err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	if s.beforePublish != nil {
		if err = s.beforePublish(); err != nil {
			return err
		}
	}
	if err = publish(filepath.Join(s.directory, "pending", "current"), filepath.Join(s.directory, "current")); err != nil {
		return err
	}
	// Publication is the commit boundary. No fallible work follows it.
	s.document = next
	s.objects = map[uint64]object{}
	for _, o := range next.Objects {
		s.objects[o.Node.Identity.Object] = o
	}
	sum := sha256.Sum256(data)
	s.digest = hex.EncodeToString(sum[:])
	return nil
}
func (s *Session) writePending(name string, b []byte) error {
	f, err := s.root.OpenFile("pending/"+name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if err == nil {
		err = f.Sync()
	}
	return errors.Join(err, f.Close())
}
func (s *Session) store(ctx context.Context, v filesystem.Value, total *int64) (result blob, err error) {
	defer func() { err = errors.Join(err, v.Close()) }()
	var source block.Source = v
	for depth := 0; ; depth++ {
		if depth >= 32 {
			return result, filesystem.ErrLimit
		}
		u, ok := source.(interface{ Unwrap() block.Source })
		if !ok {
			break
		}
		source = u.Unwrap()
	}
	if b, ok := source.(*blobValue); ok && b.owner == s {
		return b.ref, nil
	}
	size := v.Size()
	if size < 0 {
		return result, filesystem.ErrCorrupt
	}
	limits := s.document.Config.Limits
	if size > limits.ValueBytes || size > limits.TotalBytes-*total {
		return result, filesystem.ErrLimit
	}
	*total += size
	f, err := s.root.OpenFile("pending/value", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return result, err
	}
	h := sha256.New()
	err = copyValue(ctx, io.MultiWriter(f, h), v, size)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return result, err
	}
	result = blob{hex.EncodeToString(h.Sum(nil)), size}
	name := "blobs/" + result.SHA256
	if info, e := s.root.Lstat(name); e == nil {
		if !info.Mode().IsRegular() || info.Size() != size {
			return result, filesystem.ErrCorrupt
		}
		check := &blobValue{owner: s, ctx: ctx, ref: result}
		_, checkErr := check.ReadAt(nil, 0)
		if e := errors.Join(checkErr, check.Close()); e != nil {
			return result, e
		}
		return result, s.root.Remove("pending/value")
	} else if !errors.Is(e, fs.ErrNotExist) {
		return result, e
	}
	err = s.root.Rename("pending/value", name)
	if err == nil {
		s.verified[result.SHA256] = true
	}
	return result, err
}
func copyValue(ctx context.Context, w io.Writer, r io.ReaderAt, size int64) error {
	buf := make([]byte, 64<<10)
	for off := int64(0); off < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		p := buf[:min(int64(len(buf)), size-off)]
		n, err := r.ReadAt(p, off)
		if n != len(p) {
			return errors.Join(io.ErrUnexpectedEOF, err)
		}
		if err != nil && (!errors.Is(err, io.EOF) || off+int64(n) != size) {
			return err
		}
		if n, err = w.Write(p); err != nil {
			return err
		} else if n != len(p) {
			return io.ErrShortWrite
		}
		off += int64(len(p))
	}
	return ctx.Err()
}
func walk(ctx context.Context, r filesystem.Reader, root uint64, depth int, limits workspace.Limits, yield func(uint64) error) error {
	seen := map[uint64]bool{}
	dirs := map[uint64]bool{}
	count := 0
	var visit func(uint64, int) error
	visit = func(id uint64, level int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		count++
		if count > limits.Entries || level > limits.Depth {
			return filesystem.ErrLimit
		}
		if seen[id] {
			if dirs[id] {
				return filesystem.ErrCorrupt
			}
			return nil
		}
		if len(seen) >= limits.Objects {
			return filesystem.ErrLimit
		}
		seen[id] = true
		n, err := r.Stat(ctx, id)
		if err != nil {
			return err
		}
		if n.Identity.Object != id {
			return filesystem.ErrCorrupt
		}
		if err = yield(id); err != nil {
			return err
		}
		if n.Metadata.Mode.Value&0170000 != 0040000 {
			return nil
		}
		dirs[id] = true
		var entries []filesystem.DirEntry
		if err = r.ReadDir(ctx, id, func(e filesystem.DirEntry) error {
			if len(entries) >= limits.Entries {
				return filesystem.ErrLimit
			}
			entries = append(entries, e)
			return nil
		}); err != nil {
			return err
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
		for _, e := range entries {
			if err = visit(e.Object, level+1); err != nil {
				return err
			}
		}
		return nil
	}
	return visit(root, depth)
}
func (s *Session) Root() uint64                    { return s.document.Root }
func (s *Session) NameRules() filesystem.NameRules { return s.document.Names }
func (s *Session) get(ctx context.Context, id uint64) (object, error) {
	if s.closed {
		return object{}, fs.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return object{}, err
	}
	o, ok := s.objects[id]
	if !ok {
		return o, fs.ErrNotExist
	}
	return o, nil
}
func (s *Session) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	o, err := s.get(ctx, id)
	return edit.CopyNode(o.Node), err
}
func (s *Session) ReadDir(ctx context.Context, id uint64, yield func(filesystem.DirEntry) error) error {
	o, err := s.get(ctx, id)
	if err != nil {
		return err
	}
	if o.Node.Metadata.Mode.Value&0170000 != 0040000 || yield == nil {
		return fs.ErrInvalid
	}
	for _, e := range o.Children {
		if err = ctx.Err(); err != nil {
			return err
		}
		if err = yield(e); err != nil {
			return err
		}
	}
	return nil
}
func (s *Session) Lookup(ctx context.Context, id uint64, name string) (filesystem.DirEntry, error) {
	if name == "" || strings.ContainsAny(name, "/\x00") || name == "." || name == ".." {
		return filesystem.DirEntry{}, fs.ErrInvalid
	}
	o, err := s.get(ctx, id)
	if err != nil {
		return filesystem.DirEntry{}, err
	}
	if o.Node.Metadata.Mode.Value&0170000 != 0040000 {
		return filesystem.DirEntry{}, fs.ErrInvalid
	}
	for _, e := range o.Children {
		if s.key(e.Name) == s.key(name) {
			return e, nil
		}
	}
	return filesystem.DirEntry{}, fs.ErrNotExist
}
func (s *Session) OpenData(ctx context.Context, id uint64) (filesystem.Value, error) {
	o, e := s.get(ctx, id)
	if e != nil {
		return nil, e
	}
	return s.value(ctx, o.Data)
}
func (s *Session) OpenRawData(ctx context.Context, id uint64) (filesystem.Value, error) {
	o, e := s.get(ctx, id)
	if e != nil {
		return nil, e
	}
	return s.value(ctx, o.Raw)
}
func (s *Session) OpenAttribute(ctx context.Context, id uint64, name string) (filesystem.Value, error) {
	o, e := s.get(ctx, id)
	if e != nil {
		return nil, e
	}
	for _, a := range o.Attributes {
		if a.Name == name {
			return s.value(ctx, &a.Value)
		}
	}
	return nil, fs.ErrNotExist
}
func (s *Session) ListAttributes(ctx context.Context, id uint64, yield func(string) error) error {
	o, e := s.get(ctx, id)
	if e != nil {
		return e
	}
	if yield == nil {
		return fs.ErrInvalid
	}
	for _, a := range o.Attributes {
		if e = ctx.Err(); e != nil {
			return e
		}
		if e = yield(a.Name); e != nil {
			return e
		}
	}
	return nil
}
func (s *Session) Readlink(ctx context.Context, id uint64) (string, error) {
	o, e := s.get(ctx, id)
	if e != nil {
		return "", e
	}
	if o.Node.Metadata.Mode.Value&0170000 != 0120000 {
		return "", fs.ErrInvalid
	}
	return string(o.Target), nil
}
func (s *Session) value(ctx context.Context, b *blob) (filesystem.Value, error) {
	if b == nil {
		return nil, fs.ErrInvalid
	}
	return &blobValue{owner: s, ctx: ctx, ref: *b}, nil
}

type blobValue struct {
	owner  *Session
	ctx    context.Context
	ref    blob
	file   *os.File
	closed bool
}

func (v *blobValue) Size() int64 { return v.ref.Size }
func (v *blobValue) Close() error {
	v.closed = true
	if v.file != nil {
		return v.file.Close()
	}
	return nil
}
func (v *blobValue) ReadAt(p []byte, off int64) (int, error) {
	if v.closed || v.owner.closed {
		return 0, fs.ErrClosed
	}
	if e := v.ctx.Err(); e != nil {
		return 0, e
	}
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if v.file == nil {
		name := "blobs/" + v.ref.SHA256
		info, err := v.owner.root.Lstat(name)
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() || info.Size() != v.ref.Size {
			return 0, filesystem.ErrCorrupt
		}
		f, err := v.owner.root.Open(name)
		if err != nil {
			return 0, err
		}
		if !v.owner.verified[v.ref.SHA256] {
			h := sha256.New()
			err = copyValue(v.ctx, h, f, v.ref.Size)
			if err == nil && hex.EncodeToString(h.Sum(nil)) != v.ref.SHA256 {
				err = filesystem.ErrCorrupt
			}
			if err != nil {
				return 0, errors.Join(err, f.Close())
			}
			v.owner.verified[v.ref.SHA256] = true
		}
		v.file = f
	}
	return v.file.ReadAt(p, off)
}
func (s *Session) Verify(ctx context.Context) error {
	if s.closed {
		return fs.ErrClosed
	}
	s.verified = map[string]bool{}
	for _, o := range s.document.Objects {
		for _, b := range values(o) {
			if s.verified[b.SHA256] {
				continue
			}
			v := &blobValue{owner: s, ctx: ctx, ref: b}
			_, err := v.ReadAt(nil, 0)
			err = errors.Join(err, v.Close())
			if err != nil {
				return err
			}
		}
	}
	return ctx.Err()
}
func (s *Session) Report() Report {
	result := Report{Location: s.directory, Names: s.NameRules(), Source: s.objects[s.Root()].Node.Identity, Revision: s.digest, Objects: len(s.objects), Entries: 1}
	seen := map[string]bool{}
	for _, o := range s.document.Objects {
		result.Entries += len(o.Children)
		if o.Node.AttributesUnavailable {
			result.AttributesUnavailable = append(result.AttributesUnavailable, o.Node.Identity.Object)
		}
		if len(o.Node.MetadataDefaulted) > 0 {
			result.Defaulted = append(result.Defaulted, Default{o.Node.Identity.Object, slices.Clone(o.Node.MetadataDefaulted)})
		}
		for _, b := range values(o) {
			if !seen[b.SHA256] {
				result.BlobBytes += b.Size
				seen[b.SHA256] = true
			}
		}
	}
	return result
}
func (s *Session) Export(ctx context.Context, destination string) (workspace.Report, error) {
	if err := s.Verify(ctx); err != nil {
		return workspace.Report{}, err
	}
	original, err := s.root.Stat(".")
	if err != nil {
		return workspace.Report{}, err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil {
		return workspace.Report{}, err
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return workspace.Report{}, err
	}
	for {
		info, err := os.Stat(parent)
		if err != nil {
			return workspace.Report{}, err
		}
		if os.SameFile(original, info) {
			return workspace.Report{}, fs.ErrInvalid
		}
		next := filepath.Dir(parent)
		if next == parent {
			break
		}
		parent = next
	}
	return workspace.Extract(ctx, s, s.Root(), destination, s.document.Config.Limits)
}
func (s *Session) Close() error {
	if s.closed {
		return nil
	}
	s.closed = true
	var err error
	if s.lock != nil {
		err = s.lock.Close()
	}
	if s.root != nil {
		err = errors.Join(err, s.root.Close())
	}
	return err
}

// Remove deletes only a recognized session while holding its exclusive lock.
func Remove(ctx context.Context, directory string) error {
	s, err := Open(ctx, directory)
	if err != nil {
		return err
	}
	// Rename while locked on Unix. Windows requires closing the lock handle before
	// deleting the directory; a tombstone prevents a new opener from accepting it.
	if err = s.root.Rename("current", "removed"); err != nil {
		return errors.Join(err, s.Close())
	}
	if err = s.Close(); err != nil {
		return err
	}
	return os.RemoveAll(directory)
}
