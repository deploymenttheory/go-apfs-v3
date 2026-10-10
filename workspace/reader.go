package workspace

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
	"path"
	"strings"
	"sync"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/names"
)

// Workspace is an immutable filesystem view. Keep it open while using borrowed
// values. External edits are conflicts, not implicit imports into preserved data.
type Workspace struct {
	mu       sync.RWMutex
	root     *os.Root
	closed   bool
	digest   string
	document manifest
	objects  map[uint64]object
	children map[uint64][]filesystem.DirEntry
	key      func(string) string
	values   map[*value]bool
}

var _ filesystem.Reader = (*Workspace)(nil)

// Open validates the complete manifest, all blob hashes and the host projection.
// An edited, missing or incomplete projection fails explicitly. This performs
// streaming verification; callers must exclude external mutation until Close.
func Open(ctx context.Context, directory string) (result *Workspace, err error) {
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	w := &Workspace{root: root, objects: map[uint64]object{}, children: map[uint64][]filesystem.DirEntry{}, values: map[*value]bool{}}
	defer func() {
		if err != nil {
			err = errors.Join(err, w.Close())
		}
	}()
	for _, dir := range []string{"metadata", "metadata/blobs"} {
		info, err := root.Lstat(dir)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("workspace metadata directory: %w", filesystem.ErrCorrupt)
		}
	}
	manifestInfo, err := root.Lstat("metadata/manifest.json")
	if err != nil {
		return nil, err
	}
	if !manifestInfo.Mode().IsRegular() {
		return nil, filesystem.ErrCorrupt
	}
	f, err := root.Open("metadata/manifest.json")
	if err != nil {
		return nil, err
	}
	info, statErr := f.Stat()
	if statErr != nil {
		return nil, errors.Join(statErr, f.Close())
	}
	if !os.SameFile(manifestInfo, info) {
		return nil, errors.Join(filesystem.ErrConflict, f.Close())
	}
	if !info.Mode().IsRegular() || info.Size() > maxManifest {
		return nil, errors.Join(filesystem.ErrLimit, f.Close())
	}
	hash := sha256.New()
	d := json.NewDecoder(io.TeeReader(io.LimitReader(f, maxManifest+1), hash))
	d.DisallowUnknownFields()
	decodeErr := d.Decode(&w.document)
	if decodeErr == nil {
		var extra any
		if d.Decode(&extra) != io.EOF {
			decodeErr = filesystem.ErrCorrupt
		}
	}
	if err = errors.Join(decodeErr, f.Close()); err != nil {
		return nil, fmt.Errorf("workspace manifest: %w", errors.Join(filesystem.ErrCorrupt, err))
	}
	w.digest = hex.EncodeToString(hash.Sum(nil))
	if err = w.validate(ctx); err != nil {
		return nil, err
	}
	if err = w.verify(ctx); err != nil {
		return nil, err
	}
	return w, nil
}

func (w *Workspace) validate(ctx context.Context) (err error) {
	at := "manifest"
	defer func() {
		if err != nil {
			err = fmt.Errorf("workspace %s: %w", at, err)
		}
	}()
	m := w.document
	if m.Schema != 1 && m.Schema != 2 {
		return fmt.Errorf("workspace schema %d: %w", m.Schema, filesystem.ErrUnsupported)
	}
	if m.ParentManifestSHA256 != "" && (m.Schema != 2 || !validBlob(blob{SHA256: m.ParentManifestSHA256})) {
		return filesystem.ErrCorrupt
	}
	w.key, err = nameKey(m.Names)
	if err != nil {
		return err
	}
	if len(m.Objects) == 0 || len(m.Entries) == 0 || len(m.Objects) > DefaultLimits().Objects || len(m.Entries) > DefaultLimits().Entries {
		return filesystem.ErrLimit
	}
	modified := 0
	for _, o := range m.Objects {
		if err := ctx.Err(); err != nil {
			return err
		}
		id := o.Node.Identity.Object
		at = fmt.Sprintf("object %d", id)
		if !validNode(o.Node) || w.objects[id].Node.Identity.Object != 0 || len(o.Attributes) > maxAttributes {
			return filesystem.ErrCorrupt
		}
		if o.Node.DataModified {
			modified++
			if m.Schema != 2 || kind(o) != 0100000 || o.Data == nil || o.RawData == nil || *o.Data != *o.RawData || o.Node.Compression.State != filesystem.Absent || o.Node.Metadata.BSDFlags.State != filesystem.Present || o.Node.Metadata.BSDFlags.Value&32 != 0 {
				return filesystem.ErrCorrupt
			}
		}
		switch kind(o) {
		case 0100000:
			if o.Data == nil || o.RawData == nil || uint64(o.Data.Size) != o.Node.Size || len(o.Target) != 0 {
				return filesystem.ErrCorrupt
			}
		case 0040000, 0120000:
			if o.Data != nil || o.RawData != nil {
				return filesystem.ErrCorrupt
			}
			if kind(o) == 0120000 && (uint64(len(o.Target)) != o.Node.Size || len(o.Target) > 1<<20) {
				return filesystem.ErrCorrupt
			}
			if kind(o) == 0040000 && len(o.Target) != 0 {
				return filesystem.ErrCorrupt
			}
		default:
			return filesystem.ErrUnsupported
		}
		for i, a := range o.Attributes {
			if len(a.Name) == 0 || len(a.Name) > 1024 || bytes.IndexByte(a.Name, 0) >= 0 || (i > 0 && bytes.Compare(o.Attributes[i-1].Name, a.Name) >= 0) {
				return filesystem.ErrCorrupt
			}
		}
		for _, b := range allBlobs(o) {
			if !validBlob(b) {
				return filesystem.ErrCorrupt
			}
		}
		w.objects[id] = o
	}
	origin, ok := w.objects[m.Root]
	if !ok {
		return filesystem.ErrCorrupt
	}
	for _, o := range m.Objects {
		if o.Node.Identity.Volume != origin.Node.Identity.Volume || o.Node.Identity.View != origin.Node.Identity.View {
			return filesystem.ErrCorrupt
		}
	}
	directories := map[uint64]string{}
	used := map[uint64]bool{}
	host := map[string]bool{}
	native := map[uint64]map[string]bool{}
	depth := map[uint64]int{}
	calculated := Report{Objects: len(m.Objects), Entries: len(m.Entries), Metadata: metadataPolicy, ModifiedFiles: modified}
	for i, e := range m.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		at = fmt.Sprintf("entry %q", e.HostPath)
		o, ok := w.objects[e.Object]
		if !ok || !validHostPath(e.HostPath) {
			return filesystem.ErrCorrupt
		}
		if i == 0 {
			if e.Parent != 0 || len(e.Name) != 0 || e.Object != m.Root || e.HostPath != "files" {
				return filesystem.ErrCorrupt
			}
		} else {
			if !validComponent(string(e.Name)) || directories[e.Parent] == "" || path.Dir(e.HostPath) != directories[e.Parent] {
				return filesystem.ErrCorrupt
			}
			depth[e.Object] = depth[e.Parent] + 1
			if depth[e.Object] > DefaultLimits().Depth {
				return filesystem.ErrLimit
			}
			if native[e.Parent] == nil {
				native[e.Parent] = map[string]bool{}
			}
			key := w.key(string(e.Name))
			if native[e.Parent][key] {
				return filesystem.ErrCorrupt
			}
			native[e.Parent][key] = true
			w.children[e.Parent] = append(w.children[e.Parent], filesystem.DirEntry{Name: string(e.Name), Object: e.Object})
		}
		if i != 0 && path.Base(e.HostPath) != string(e.Name) {
			calculated.MappedNames++
		}
		switch e.Materialized {
		case "hard-link":
			calculated.HardLinks++
		case "hard-link-copy":
			calculated.HardLinksCopied++
		case "symlink-record":
			calculated.SymlinksRecorded++
		}
		key := strings.ToLower(e.HostPath)
		if host[key] {
			return filesystem.ErrCorrupt
		}
		host[key] = true
		switch kind(o) {
		case 0040000:
			if used[e.Object] || e.Materialized != "directory" {
				return filesystem.ErrCorrupt
			}
			directories[e.Object] = e.HostPath
		case 0100000:
			if (!used[e.Object] && e.Materialized != "file") || (used[e.Object] && e.Materialized != "hard-link" && e.Materialized != "hard-link-copy") {
				return filesystem.ErrCorrupt
			}
		case 0120000:
			if e.Materialized != "symlink-record" {
				return filesystem.ErrCorrupt
			}
		}
		used[e.Object] = true
	}
	at = "preservation report"
	calculated.StoredBytes = m.Report.StoredBytes // verified against unique blobs below
	if len(used) != len(w.objects) || m.Report != calculated {
		return filesystem.ErrCorrupt
	}
	return nil
}

func validHostPath(p string) bool {
	if p != "files" && !strings.HasPrefix(p, "files/") {
		return false
	}
	for _, part := range strings.Split(p, "/") {
		if !validComponent(part) {
			return false
		}
		if strings.HasPrefix(part, "~") {
			if len(part) != 65 || !validBlob(blob{SHA256: part[1:]}) {
				return false
			}
		} else if portableName(part) != part {
			return false
		}
	}
	return true
}

func (w *Workspace) verify(ctx context.Context) error {
	verified := map[string]int64{}
	var transferred, stored int64
	for _, o := range w.document.Objects {
		for _, b := range allBlobs(o) {
			if b.Size > DefaultLimits().ValueBytes || b.Size > DefaultLimits().TotalBytes-transferred {
				return filesystem.ErrLimit
			}
			transferred += b.Size
			if size, ok := verified[b.SHA256]; ok {
				if size != b.Size {
					return filesystem.ErrCorrupt
				}
				continue
			}
			if _, err := w.verifyFile(ctx, "metadata/blobs/"+b.SHA256, b); err != nil {
				return err
			}
			verified[b.SHA256] = b.Size
			stored += b.Size
		}
	}
	if stored != w.document.Report.StoredBytes {
		return fmt.Errorf("workspace stored bytes: %w", filesystem.ErrCorrupt)
	}
	directoryNames := map[string]map[string]bool{}
	for _, e := range w.document.Entries {
		if e.HostPath != "files" {
			parent := path.Dir(e.HostPath)
			if directoryNames[parent] == nil {
				directoryNames[parent] = map[string]bool{}
			}
			directoryNames[parent][path.Base(e.HostPath)] = true
		}
	}
	for _, e := range w.document.Entries {
		if err := ctx.Err(); err != nil {
			return err
		}
		o := w.objects[e.Object]
		if kind(o) == 0040000 {
			info, err := w.root.Lstat(e.HostPath)
			if err != nil {
				return err
			}
			if !info.IsDir() {
				return filesystem.ErrConflict
			}
			f, err := w.root.Open(e.HostPath)
			if err != nil {
				return err
			}
			actual, readErr := f.Readdirnames(-1)
			if err = errors.Join(readErr, f.Close()); err != nil {
				return err
			}
			if len(actual) != len(directoryNames[e.HostPath]) {
				return filesystem.ErrConflict
			}
			for _, name := range actual {
				if !directoryNames[e.HostPath][name] {
					return filesystem.ErrConflict
				}
			}
			continue
		}
		b := o.Data
		if kind(o) == 0120000 {
			sum := sha256.Sum256(o.Target)
			b = &blob{hex.EncodeToString(sum[:]), int64(len(o.Target))}
		}
		_, err := w.verifyFile(ctx, e.HostPath, *b)
		if err != nil {
			return fmt.Errorf("workspace projection: %w", errors.Join(filesystem.ErrConflict, err))
		}
	}
	return ctx.Err()
}

func (w *Workspace) verifyFile(ctx context.Context, name string, b blob) (info fs.FileInfo, err error) {
	info, err = w.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != b.Size {
		return nil, filesystem.ErrCorrupt
	}
	f, err := w.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(info, opened) {
		return nil, filesystem.ErrConflict
	}
	h := sha256.New()
	if err = copyValue(ctx, h, f, b.Size); err != nil {
		return nil, err
	}
	if hex.EncodeToString(h.Sum(nil)) != b.SHA256 {
		return nil, fmt.Errorf("workspace digest %s: %w", name, filesystem.ErrCorrupt)
	}
	return info, nil
}

// ManifestSHA256 identifies this immutable manifest, including its source metadata.
func (w *Workspace) ManifestSHA256() string { return w.digest }

// ParentManifestSHA256 identifies the input workspace of a derived capture.
// The parent remains external; this workspace is self-contained for reading.
func (w *Workspace) ParentManifestSHA256() string { return w.document.ParentManifestSHA256 }

func (w *Workspace) Root() uint64                    { return w.document.Root }
func (w *Workspace) NameRules() filesystem.NameRules { return w.document.Names }
func (w *Workspace) Report() Report                  { return w.document.Report }

func (w *Workspace) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil
	}
	w.closed = true
	var err error
	for v := range w.values {
		v.closed = true
		err = errors.Join(err, v.file.Close())
	}
	w.values = nil
	return errors.Join(err, w.root.Close())
}

func (w *Workspace) get(ctx context.Context, id uint64) (object, error) {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return object{}, fs.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return object{}, err
	}
	o, ok := w.objects[id]
	if !ok {
		return o, fs.ErrNotExist
	}
	return o, nil
}

func (w *Workspace) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	o, err := w.get(ctx, id)
	return o.Node, err
}
func (w *Workspace) Lookup(ctx context.Context, parent uint64, name string) (filesystem.DirEntry, error) {
	return names.Lookup(ctx, w, parent, name, w.key)
}
func (w *Workspace) ReadDir(ctx context.Context, id uint64, yield func(filesystem.DirEntry) error) error {
	if yield == nil {
		return fs.ErrInvalid
	}
	o, err := w.get(ctx, id)
	if err != nil {
		return err
	}
	if kind(o) != 0040000 {
		return fs.ErrInvalid
	}
	for _, e := range w.children[id] {
		if _, err = w.get(ctx, id); err != nil {
			return err
		}
		if err = yield(e); err != nil {
			return err
		}
	}
	return ctx.Err()
}
func (w *Workspace) ListAttributes(ctx context.Context, id uint64, yield func(string) error) error {
	if yield == nil {
		return fs.ErrInvalid
	}
	o, err := w.get(ctx, id)
	if err != nil {
		return err
	}
	for _, a := range o.Attributes {
		if _, err = w.get(ctx, id); err != nil {
			return err
		}
		if err = yield(string(a.Name)); err != nil {
			return err
		}
	}
	return ctx.Err()
}
func (w *Workspace) Readlink(ctx context.Context, id uint64) (string, error) {
	o, err := w.get(ctx, id)
	if err != nil {
		return "", err
	}
	if kind(o) != 0120000 {
		return "", fs.ErrInvalid
	}
	return string(o.Target), nil
}
func (w *Workspace) OpenData(ctx context.Context, id uint64) (filesystem.Value, error) {
	o, err := w.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if o.Data == nil {
		return nil, fs.ErrInvalid
	}
	return w.openValue(ctx, *o.Data)
}
func (w *Workspace) OpenRawData(ctx context.Context, id uint64) (filesystem.Value, error) {
	o, err := w.get(ctx, id)
	if err != nil {
		return nil, err
	}
	if o.RawData == nil {
		return nil, fs.ErrInvalid
	}
	return w.openValue(ctx, *o.RawData)
}
func (w *Workspace) OpenAttribute(ctx context.Context, id uint64, name string) (filesystem.Value, error) {
	o, err := w.get(ctx, id)
	if err != nil {
		return nil, err
	}
	for _, a := range o.Attributes {
		if string(a.Name) == name {
			return w.openValue(ctx, a.Value)
		}
	}
	return nil, fs.ErrNotExist
}

func (w *Workspace) openValue(ctx context.Context, b blob) (filesystem.Value, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, fs.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	f, err := w.root.Open("metadata/blobs/" + b.SHA256)
	if err != nil {
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if !info.Mode().IsRegular() || info.Size() != b.Size {
		return nil, errors.Join(filesystem.ErrConflict, f.Close())
	}
	v := &value{owner: w, file: f, ctx: ctx, size: b.Size}
	w.values[v] = true
	return v, nil
}

type value struct {
	owner  *Workspace
	file   *os.File
	ctx    context.Context
	size   int64
	closed bool
}

func (v *value) Size() int64 { return v.size }
func (v *value) ReadAt(p []byte, off int64) (int, error) {
	v.owner.mu.RLock()
	defer v.owner.mu.RUnlock()
	if v.closed || v.owner.closed {
		return 0, fs.ErrClosed
	}
	if err := v.ctx.Err(); err != nil {
		return 0, err
	}
	return v.file.ReadAt(p, off)
}
func (v *value) Close() error {
	v.owner.mu.Lock()
	defer v.owner.mu.Unlock()
	if v.closed {
		return nil
	}
	v.closed = true
	delete(v.owner.values, v)
	return v.file.Close()
}
