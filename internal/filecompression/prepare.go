// Package filecompression prepares one shared storage view for fresh builders.
// It borrows an immutable source; scratch contains only encoded resource bytes.
package filecompression

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v3/internal/fork"
)

type Outcome struct {
	Volume       string `json:"volume,omitempty"`
	Path         string `json:"path"`
	Object       uint64 `json:"object"`
	Action       string `json:"action"`
	Reason       string `json:"reason,omitempty"`
	Type         uint32 `json:"type,omitempty"`
	LogicalBytes uint64 `json:"logicalBytes"`
	StoredBytes  int64  `json:"storedBytes"`
}

type object struct {
	node           filesystem.Node
	attribute      []byte
	resource       string
	removeResource bool
	logicalRaw     bool
	digest         [32]byte
}

type Reader struct {
	filesystem.Reader
	objects   map[uint64]*object
	directory string
	outcomes  []Outcome
	budget    *int64
}

func Validate(policy string) error {
	if policy != "" && policy != "preserve" && policy != "zlib" && policy != "none" {
		return fmt.Errorf("file compression must be preserve, zlib or none: %w", fs.ErrInvalid)
	}
	return nil
}

// Prepare owns its managed scratch until Close. It never closes source.
func Prepare(ctx context.Context, source filesystem.Reader, policy, scratch string, budget *int64) (_ *Reader, err error) {
	if source == nil || budget == nil {
		return nil, fs.ErrInvalid
	}
	if err = Validate(policy); err != nil {
		return nil, err
	}
	r := &Reader{Reader: source, objects: map[uint64]*object{}, budget: budget}
	if policy == "" || policy == "preserve" {
		return r, ctx.Err()
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, r.Close())
		}
	}()
	seen := map[uint64]bool{}
	entries := 0
	var visit func(uint64, string, int) error
	visit = func(id uint64, path string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > 100000 || depth > 256 {
			return filesystem.ErrLimit
		}
		if seen[id] {
			return nil
		}
		seen[id] = true
		*r.budget += 512 + int64(len(path))*4
		if *r.budget > 64<<20 {
			return filesystem.ErrLimit
		}
		n, err := source.Stat(ctx, id)
		if err != nil {
			return err
		}
		if n.Identity.Object != id || n.Metadata.Mode.State != filesystem.Present {
			return filesystem.ErrCorrupt
		}
		switch n.Metadata.Mode.Value & 0170000 {
		case 0100000:
			return r.prepareFile(ctx, id, path, n, policy, scratch)
		case 0040000:
			var children []filesystem.DirEntry
			if err = source.ReadDir(ctx, id, func(e filesystem.DirEntry) error {
				if len(children) >= 100000 {
					return filesystem.ErrLimit
				}
				children = append(children, e)
				return nil
			}); err != nil {
				return err
			}
			sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })
			for _, e := range children {
				child := path + e.Name
				if path != "/" {
					child = path + "/" + e.Name
				}
				if err = visit(e.Object, child, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err = visit(source.Root(), "/", 0); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Reader) prepareFile(ctx context.Context, id uint64, path string, n filesystem.Node, policy, scratch string) (err error) {
	if n.Size > 1<<40 {
		return filesystem.ErrLimit
	}
	if n.Metadata.BSDFlags.State != filesystem.Present || (n.Compression.State != filesystem.Absent && n.Compression.State != filesystem.Present) {
		return filesystem.ErrUnsupported
	}
	active := n.Metadata.BSDFlags.Value&32 != 0
	if active != (n.Compression.State == filesystem.Present) {
		return filesystem.ErrCorrupt
	}
	var attributes []string
	if err = r.Reader.ListAttributes(ctx, id, func(name string) error {
		if len(attributes) >= 4096 {
			return filesystem.ErrLimit
		}
		attributes = append(attributes, name)
		return nil
	}); err != nil {
		return err
	}
	sort.Strings(attributes)
	hasResource, hasDecmpfs := false, false
	for i, name := range attributes {
		if i > 0 && attributes[i-1] == name {
			return filesystem.ErrCorrupt
		}
		hasResource = hasResource || name == filesystem.ResourceFork
		hasDecmpfs = hasDecmpfs || name == filesystem.Decmpfs
	}
	o := &object{node: n}
	if active {
		open := func(name string) (filesystem.Value, error) { return r.Reader.OpenAttribute(ctx, id, name) }
		h, err := decmpfs.Inspect(open)
		if err != nil {
			return err
		}
		if h.Type != n.Compression.Value.Type || h.Size != n.Size {
			return filesystem.ErrCorrupt
		}
		o.removeResource, err = decmpfs.UsesResourceFork(h.Type)
		if err != nil {
			return err
		}
		if o.removeResource && !hasResource {
			return filesystem.ErrCorrupt
		}
		o.logicalRaw = true
		o.node.Metadata.BSDFlags.Value &^= 32
		o.node.Compression = filesystem.Observation[filesystem.Compression]{State: filesystem.Absent}
		r.objects[id] = o
	}
	if policy == "none" {
		if active {
			r.outcomes = append(r.outcomes, Outcome{Path: path, Object: id, Action: "decompressed", LogicalBytes: n.Size, StoredBytes: int64(n.Size)})
		}
		return nil
	}
	outcome := Outcome{Path: path, Object: id, Action: "uncompressed", LogicalBytes: n.Size, StoredBytes: int64(n.Size)}
	if hasDecmpfs && !active {
		outcome.Reason = "inactive-decmpfs-attribute"
		r.outcomes = append(r.outcomes, outcome)
		return nil
	}
	if hasResource && !o.removeResource {
		// Apple's decmpfs_hides_rsrc hides every compressed file's resource
		// fork, even with type-3 attribute storage. Keeping its raw bytes
		// would still remove the independent fork from native applications.
		outcome.Reason = "independent-resource-fork"
		r.outcomes = append(r.outcomes, outcome)
		return nil
	}
	if r.directory == "" {
		r.directory, err = os.MkdirTemp(scratch, "apfs-file-compression-")
		if err != nil {
			return err
		}
	}
	encodedPath := filepath.Join(r.directory, fmt.Sprintf("%d.resource", id))
	resource, err := os.OpenFile(encodedPath, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	v, err := r.OpenData(ctx, id)
	if err != nil {
		return errors.Join(err, resource.Close())
	}
	if v.Size() < 0 || uint64(v.Size()) != n.Size {
		return errors.Join(filesystem.ErrCorrupt, v.Close(), resource.Close())
	}
	encoded, encodeErr := decmpfs.Encode(ctx, v, resource)
	err = errors.Join(encodeErr, v.Close(), resource.Close())
	if err != nil {
		return err
	}
	if encoded.Reason != "" {
		if err = os.Remove(encodedPath); err != nil {
			return err
		}
		outcome.Reason = encoded.Reason
		r.outcomes = append(r.outcomes, outcome)
		return nil
	}
	*r.budget += int64(len(encoded.Attribute))
	if *r.budget > 64<<20 {
		return filesystem.ErrLimit
	}
	o.attribute, o.digest = encoded.Attribute, encoded.LogicalSHA256
	o.logicalRaw = false
	o.node.Metadata.BSDFlags.Value |= 32
	o.node.Compression = filesystem.Observed(filesystem.Compression{Type: uint32(encoded.Attribute[4])})
	if encoded.ResourceBytes != 0 {
		o.resource = encodedPath
	} else if err = os.Remove(encodedPath); err != nil {
		return err
	}
	r.objects[id] = o
	outcome.Action, outcome.Type = "compressed", o.node.Compression.Value.Type
	outcome.StoredBytes = int64(len(o.attribute)) + encoded.ResourceBytes
	r.outcomes = append(r.outcomes, outcome)
	return nil
}

func (r *Reader) Outcomes() []Outcome { return append([]Outcome(nil), r.outcomes...) }

func (r *Reader) Close() error {
	if r.directory == "" {
		return nil
	}
	err := os.RemoveAll(r.directory)
	if err == nil {
		r.directory = ""
	}
	return err
}

// Verify rechecks borrowed logical contents after encoded output, so scratch
// cannot hide a source change from the builders' normal payload verification.
func (r *Reader) Verify(ctx context.Context) (err error) {
	buffer := make([]byte, 65536)
	for _, outcome := range r.outcomes {
		o := r.objects[outcome.Object]
		if o == nil || o.attribute == nil {
			continue
		}
		v, err := r.OpenData(ctx, outcome.Object)
		if err != nil {
			return err
		}
		digest := sha256.New()
		if v.Size() < 0 || uint64(v.Size()) != o.node.Size {
			err = filesystem.ErrConflict
		}
		for off := int64(0); err == nil && off < v.Size(); {
			if err = ctx.Err(); err != nil {
				break
			}
			b := buffer[:min(int64(len(buffer)), v.Size()-off)]
			err = block.ReadFull(v, b, off)
			if err == nil {
				_, _ = digest.Write(b)
				off += int64(len(b))
			}
		}
		var got [32]byte
		digest.Sum(got[:0])
		if err == nil && got != o.digest {
			err = filesystem.ErrConflict
		}
		if err = errors.Join(err, v.Close()); err != nil {
			return err
		}
	}
	return ctx.Err()
}

func (r *Reader) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	if err := ctx.Err(); err != nil {
		return filesystem.Node{}, err
	}
	if o := r.objects[id]; o != nil {
		return o.node, nil
	}
	return r.Reader.Stat(ctx, id)
}

func (r *Reader) OpenRawData(ctx context.Context, id uint64) (filesystem.Value, error) {
	if o := r.objects[id]; o != nil {
		if o.logicalRaw {
			return r.OpenData(ctx, id)
		}
		if o.attribute != nil {
			return fork.Bytes(ctx, nil)
		}
	}
	return r.Reader.OpenRawData(ctx, id)
}

func (r *Reader) ListAttributes(ctx context.Context, id uint64, yield func(string) error) error {
	o := r.objects[id]
	if o == nil {
		return r.Reader.ListAttributes(ctx, id, yield)
	}
	err := r.Reader.ListAttributes(ctx, id, func(name string) error {
		if name == filesystem.Decmpfs || name == filesystem.ResourceFork && (o.removeResource || o.resource != "") {
			return nil
		}
		return yield(name)
	})
	if err != nil {
		return err
	}
	if o.attribute != nil {
		if err = yield(filesystem.Decmpfs); err != nil {
			return err
		}
	}
	if o.resource != "" {
		return yield(filesystem.ResourceFork)
	}
	return nil
}

func (r *Reader) OpenAttribute(ctx context.Context, id uint64, name string) (filesystem.Value, error) {
	if o := r.objects[id]; o != nil {
		if name == filesystem.Decmpfs {
			if o.attribute == nil {
				return nil, fs.ErrNotExist
			}
			return fork.Bytes(ctx, o.attribute)
		}
		if name == filesystem.ResourceFork {
			if o.resource != "" {
				if err := ctx.Err(); err != nil {
					return nil, err
				}
				return block.Open(o.resource)
			}
			if o.removeResource {
				return nil, fs.ErrNotExist
			}
		}
	}
	return r.Reader.OpenAttribute(ctx, id, name)
}
