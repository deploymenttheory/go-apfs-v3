package workspace

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Extract creates a new workspace containing the selected node and descendants.
// It refuses an existing destination. A failure may leave an incomplete directory
// for diagnosis, but Open never admits it without a complete manifest. The source
// must remain immutable and open. The destination must exclude external mutation.
// Host files are a projection; the verified blobs and manifest retain authority.
func Extract(ctx context.Context, reader filesystem.Reader, rootID uint64, destination string, limits Limits) (Report, error) {
	parent := ""
	if w, ok := reader.(*Workspace); ok {
		if err := w.checkDestination(destination); err != nil {
			return Report{}, err
		}
		parent = w.ManifestSHA256()
	}
	return extract(ctx, reader, rootID, destination, limits, parent)
}

func extract(ctx context.Context, reader filesystem.Reader, rootID uint64, destination string, limits Limits, parent string) (report Report, err error) {
	limits, err = limits.normalize()
	if err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	key, err := nameKey(reader.NameRules())
	if err != nil {
		return report, err
	}
	if err = os.Mkdir(destination, 0700); err != nil {
		return report, err
	}
	root, err := os.OpenRoot(destination)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, root.Close()) }()
	if err = root.Mkdir("metadata", 0700); err != nil {
		return report, err
	}
	if err = root.Mkdir("metadata/blobs", 0700); err != nil {
		return report, err
	}
	x := capture{ctx: ctx, reader: reader, root: root, limits: limits, objects: map[uint64]int{}, links: map[uint64]string{}, stored: map[string]int64{}, key: key}
	x.manifest = manifest{Schema: 1, Root: rootID, Names: reader.NameRules(), ParentManifestSHA256: parent}
	if parent != "" {
		x.manifest.Schema = 2
	}
	x.manifest.Report.Metadata = metadataPolicy
	if err = x.walk(rootID, 0, nil, "files", 0); err != nil {
		return x.manifest.Report, err
	}
	x.manifest.Report.Objects = len(x.manifest.Objects)
	x.manifest.Report.Entries = len(x.manifest.Entries)
	b, err := json.MarshalIndent(x.manifest, "", "  ")
	if err != nil {
		return report, err
	}
	if len(b) > maxManifest {
		return report, filesystem.ErrLimit
	}
	b = append(b, '\n')
	f, err := root.OpenFile("metadata/manifest.tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return report, err
	}
	_, writeErr := f.Write(b)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	if err = errors.Join(writeErr, f.Close()); err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = root.Rename("metadata/manifest.tmp", "metadata/manifest.json"); err != nil {
		return report, err
	}
	return x.manifest.Report, nil
}

type capture struct {
	ctx           context.Context
	reader        filesystem.Reader
	root          *os.Root
	limits        Limits
	manifest      manifest
	objects       map[uint64]int
	links         map[uint64]string
	stored        map[string]int64
	transferred   int64
	metadataBytes int
	key           func(string) string
	source        filesystem.Identity
	haveSource    bool
}

func (x *capture) walk(id, parent uint64, name []byte, host string, depth int) error {
	if err := x.ctx.Err(); err != nil {
		return err
	}
	if depth > x.limits.Depth || len(x.manifest.Entries) >= x.limits.Entries {
		return filesystem.ErrLimit
	}
	index, seen := x.objects[id]
	if !seen {
		if err := x.metadata(2048); err != nil {
			return err
		}
		if len(x.objects) >= x.limits.Objects {
			return filesystem.ErrLimit
		}
		n, err := x.reader.Stat(x.ctx, id)
		if err != nil {
			return err
		}
		if n.Identity.Object != id || !validNode(n) {
			return fmt.Errorf("workspace object identity or mode: %w", filesystem.ErrCorrupt)
		}
		if !n.Created {
			if x.haveSource && (n.Identity.Volume != x.source.Volume || n.Identity.View != x.source.View) {
				return fmt.Errorf("mixed source views: %w", filesystem.ErrCorrupt)
			}
			x.source = n.Identity
			x.haveSource = true
		} else if n.Identity.View != 0 || (n.Identity.Volume != "" && !createdIdentity(n.Identity)) {
			return filesystem.ErrCorrupt
		}

		o := object{Node: n, Attributes: []attribute{}}
		if n.DataModified {
			x.manifest.Schema = max(x.manifest.Schema, 2)
			x.manifest.Report.ModifiedFiles++
		}
		if n.Created || n.LinksModified {
			x.manifest.Schema = 3
		}
		if n.Created {
			x.manifest.Report.CreatedObjects++
		}
		switch kind(o) {
		case 0040000:
		case 0100000:
			v, err := x.reader.OpenData(x.ctx, id)
			if err != nil {
				return err
			}
			b, err := x.store(v)
			if err != nil {
				return err
			}
			o.Data = &b
			if uint64(b.Size) != n.Size {
				return fmt.Errorf("logical data size: %w", filesystem.ErrCorrupt)
			}
			v, err = x.reader.OpenRawData(x.ctx, id)
			if err != nil {
				return err
			}
			raw, err := x.store(v)
			if err != nil {
				return err
			}
			o.RawData = &raw
			if n.DataModified && (b != raw || n.Compression.State != filesystem.Absent || n.Metadata.BSDFlags.State != filesystem.Present || n.Metadata.BSDFlags.Value&32 != 0) {
				return fmt.Errorf("inconsistent replacement storage: %w", filesystem.ErrConflict)
			}
		case 0120000:
			target, err := x.reader.Readlink(x.ctx, id)
			if err != nil {
				return err
			}
			if len(target) > 1<<20 || uint64(len(target)) != n.Size {
				return fmt.Errorf("symlink target size: %w", filesystem.ErrCorrupt)
			}
			if err := x.metadata(2 * len(target)); err != nil {
				return err
			}
			o.Target = []byte(target)
		default:
			return fmt.Errorf("extract object type %#o: %w", kind(o), filesystem.ErrUnsupported)
		}
		var attrs []string
		if err := x.reader.ListAttributes(x.ctx, id, func(name string) error {
			if len(attrs) >= maxAttributes {
				return filesystem.ErrLimit
			}
			if name == "" || len(name) > 1024 || strings.ContainsRune(name, 0) {
				return filesystem.ErrCorrupt
			}
			attrs = append(attrs, name)
			return nil
		}); err != nil {
			return err
		}
		sort.Strings(attrs)
		for i, name := range attrs {
			if err := x.metadata(2*len(name) + 256); err != nil {
				return err
			}
			if i > 0 && attrs[i-1] == name {
				return fmt.Errorf("duplicate attribute: %w", filesystem.ErrCorrupt)
			}
			v, err := x.reader.OpenAttribute(x.ctx, id, name)
			if err != nil {
				return err
			}
			b, err := x.store(v)
			if err != nil {
				return err
			}
			o.Attributes = append(o.Attributes, attribute{[]byte(name), b})
		}
		if n.Created && n.Identity.Volume == "" {
			// Derive a stable creation namespace from this parent and captured object.
			// The data/fork hashes are already available; no extra payload pass is needed.
			encoded, err := json.Marshal(struct {
				Parent string
				Object object
			}{x.manifest.ParentManifestSHA256, o})
			if err != nil {
				return err
			}
			sum := sha256.Sum256(encoded)
			o.Node.Identity.Volume = "workspace:" + hex.EncodeToString(sum[:])
		}
		index = len(x.manifest.Objects)
		x.objects[id] = index
		x.manifest.Objects = append(x.manifest.Objects, o)
	}
	o := x.manifest.Objects[index]
	if err := x.metadata(2*(len(name)+len(host)) + 256); err != nil {
		return err
	}
	e := entry{Parent: parent, Name: name, Object: id, HostPath: host}
	switch kind(o) {
	case 0040000:
		if seen {
			return fmt.Errorf("directory cycle or alias: %w", filesystem.ErrCorrupt)
		}
		if err := x.root.Mkdir(host, 0700); err != nil {
			return err
		}
		e.Materialized = "directory"
	case 0100000:
		e.Materialized = "file"
		if first, ok := x.links[id]; ok {
			if err := x.root.Link(first, host); err == nil {
				e.Materialized = "hard-link"
				x.manifest.Report.HardLinks++
			} else {
				if err := x.project(*o.Data, host); err != nil {
					return err
				}
				e.Materialized = "hard-link-copy"
				x.manifest.Report.HardLinksCopied++
			}
		} else {
			if err := x.project(*o.Data, host); err != nil {
				return err
			}
			x.links[id] = host
		}
	case 0120000:
		// Record targets as bytes; never create a path that extraction could follow.
		f, err := x.root.OpenFile(host, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, writeErr := f.Write(o.Target)
		if err = errors.Join(writeErr, f.Close()); err != nil {
			return err
		}
		e.Materialized = "symlink-record"
		x.manifest.Report.SymlinksRecorded++
	}
	x.manifest.Entries = append(x.manifest.Entries, e)
	if kind(o) != 0040000 {
		return nil
	}
	var children []filesystem.DirEntry
	if err := x.reader.ReadDir(x.ctx, id, func(e filesystem.DirEntry) error {
		if len(children) >= x.limits.Entries-len(x.manifest.Entries) {
			return filesystem.ErrLimit
		}
		if !validComponent(e.Name) {
			return fmt.Errorf("unsafe source component: %w", filesystem.ErrCorrupt)
		}
		children = append(children, e)
		return nil
	}); err != nil {
		return err
	}
	sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })
	native := map[string]bool{}
	portable := map[string]int{}
	for _, child := range children {
		key := x.key(child.Name)
		if native[key] {
			return fmt.Errorf("ambiguous source names: %w", filesystem.ErrCorrupt)
		}
		native[key] = true
		portable[strings.ToLower(portableName(child.Name))]++
	}
	for _, child := range children {
		mapped := portableName(child.Name)
		if portable[strings.ToLower(mapped)] > 1 {
			mapped = escapedName(child.Name)
		}
		if mapped != child.Name {
			x.manifest.Report.MappedNames++
		}
		if err := x.walk(child.Object, id, []byte(child.Name), path.Join(host, mapped), depth+1); err != nil {
			return err
		}
	}
	return nil
}

func (x *capture) metadata(n int) error {
	if n > maxManifest-x.metadataBytes {
		return filesystem.ErrLimit
	}
	x.metadataBytes += n
	return nil
}

func (x *capture) store(v filesystem.Value) (result blob, err error) {
	defer func() { err = errors.Join(err, v.Close()) }()
	size := v.Size()
	if size < 0 {
		return result, filesystem.ErrCorrupt
	}
	if size > x.limits.ValueBytes || size > x.limits.TotalBytes-x.transferred {
		return result, filesystem.ErrLimit
	}
	x.transferred += size
	f, err := x.root.OpenFile("metadata/value.tmp", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return result, err
	}
	h := sha256.New()
	err = copyValue(x.ctx, io.MultiWriter(f, h), v, size)
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return result, err
	}
	result = blob{hex.EncodeToString(h.Sum(nil)), size}
	if previous, exists := x.stored[result.SHA256]; exists {
		if previous != size {
			return result, filesystem.ErrCorrupt
		}
		return result, x.root.Remove("metadata/value.tmp")
	}
	if err = x.root.Rename("metadata/value.tmp", "metadata/blobs/"+result.SHA256); err != nil {
		return result, err
	}
	x.stored[result.SHA256] = size
	x.manifest.Report.StoredBytes += size
	return result, nil
}

func (x *capture) project(b blob, host string) (err error) {
	source, err := x.root.Open("metadata/blobs/" + b.SHA256)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	dst, err := x.root.OpenFile(host, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	err = copyValue(x.ctx, dst, source, b.Size)
	if err == nil {
		err = dst.Sync()
	}
	return errors.Join(err, dst.Close())
}

func copyValue(ctx context.Context, dst io.Writer, source io.ReaderAt, size int64) error {
	buffer := make([]byte, 64<<10)
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := buffer[:min(int64(len(buffer)), size-offset)]
		n, err := source.ReadAt(b, offset)
		if n != len(b) {
			return errors.Join(io.ErrUnexpectedEOF, err)
		}
		if err != nil && (!errors.Is(err, io.EOF) || offset+int64(n) != size) {
			return err
		}
		if written, err := dst.Write(b); err != nil {
			return err
		} else if written != len(b) {
			return io.ErrShortWrite
		}
		offset += int64(n)
	}
	return ctx.Err()
}
