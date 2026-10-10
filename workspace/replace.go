package workspace

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/decmpfs"
)

// DataReplacement supplies complete logical contents for one existing object.
// Data is borrowed, must remain immutable for the call, and is never closed.
// Every hard-link alias of Object receives the replacement. Duplicate objects
// are conflicts, even if selected through different directory entries.
type DataReplacement struct {
	Object uint64
	Data   block.Source
}

// ReplaceData captures replacements and all unchanged files into a NEW workspace.
// It preserves the input, object identity, links, recorded timestamps and other
// metadata. Active compression becomes ordinary data; only compression-owned
// attributes/forks are removed. Inactive compression attributes remain opaque.
// Changed nodes carry DataModified and the new manifest names its parent hash.
//
// There is no in-place commit or host-file import. Keep this workspace and the
// replacement sources immutable and open until the call returns. Failure may
// leave incomplete output without a completion manifest, as with Extract.
func (w *Workspace) ReplaceData(ctx context.Context, replacements []DataReplacement, destination string, limits Limits) (Report, error) {
	limits, err := limits.normalize()
	if err != nil {
		return Report{}, err
	}
	if len(replacements) == 0 {
		return Report{}, fs.ErrInvalid
	}
	if len(replacements) > limits.Objects {
		return Report{}, filesystem.ErrLimit
	}
	if err := w.checkDestination(destination); err != nil {
		return Report{}, err
	}
	view := &replacementReader{Workspace: w, replacements: make(map[uint64]replacement, len(replacements))}
	var total int64
	for _, change := range replacements {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		if _, duplicate := view.replacements[change.Object]; duplicate {
			return Report{}, fmt.Errorf("duplicate replacement object %d: %w", change.Object, filesystem.ErrConflict)
		}
		if change.Data == nil || change.Data.Size() < 0 {
			return Report{}, fs.ErrInvalid
		}
		size := change.Data.Size()
		if size > limits.ValueBytes || size > limits.TotalBytes-total {
			return Report{}, filesystem.ErrLimit
		}
		total += size
		original, err := w.Stat(ctx, change.Object)
		if err != nil {
			return Report{}, err
		}
		updated, removed, err := replacementNode(ctx, w, original, uint64(size))
		if err != nil {
			return Report{}, fmt.Errorf("replace object %d: %w", change.Object, err)
		}
		view.replacements[change.Object] = replacement{updated, change.Data, removed}
	}
	return extract(ctx, view, w.Root(), destination, limits, w.ManifestSHA256())
}

type replacement struct {
	node    filesystem.Node
	data    block.Source
	removed map[string]bool
}
type replacementReader struct {
	*Workspace
	replacements map[uint64]replacement
}

func replacementNode(ctx context.Context, reader filesystem.Reader, node filesystem.Node, size uint64) (filesystem.Node, map[string]bool, error) {
	if node.Metadata.Mode.State != filesystem.Present || node.Metadata.Mode.Value&0170000 != 0100000 {
		return node, nil, fs.ErrInvalid
	}
	if node.Metadata.BSDFlags.State != filesystem.Present || node.Compression.State == filesystem.Uncaptured {
		return node, nil, filesystem.ErrUnsupported
	}
	active := node.Metadata.BSDFlags.Value&32 != 0
	if active != (node.Compression.State == filesystem.Present) {
		return node, nil, filesystem.ErrCorrupt
	}
	removed := map[string]bool{}
	if active {
		header, err := decmpfs.Inspect(func(name string) (filesystem.Value, error) {
			return reader.OpenAttribute(ctx, node.Identity.Object, name)
		})
		if err != nil {
			return node, nil, err
		}
		if header.Type != node.Compression.Value.Type || header.Size != node.Size {
			return node, nil, filesystem.ErrCorrupt
		}
		resource, err := decmpfs.UsesResourceFork(header.Type)
		if err != nil {
			return node, nil, err
		}
		removed[filesystem.Decmpfs] = true
		if resource {
			removed[filesystem.ResourceFork] = true
		}
		node.Metadata.BSDFlags.Value &^= 32
	}
	node.Compression = filesystem.Observation[filesystem.Compression]{State: filesystem.Absent}
	node.Size = size
	node.DataModified = true
	return node, removed, nil
}

func (r *replacementReader) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	n, err := r.Workspace.Stat(ctx, id)
	if err != nil {
		return n, err
	}
	if replacement, ok := r.replacements[id]; ok {
		return replacement.node, nil
	}
	return n, nil
}
func (r *replacementReader) OpenData(ctx context.Context, id uint64) (filesystem.Value, error) {
	if _, err := r.get(ctx, id); err != nil {
		return nil, err
	}
	if replacement, ok := r.replacements[id]; ok {
		return &replacementValue{replacement.data, ctx}, nil
	}
	return r.Workspace.OpenData(ctx, id)
}
func (r *replacementReader) OpenRawData(ctx context.Context, id uint64) (filesystem.Value, error) {
	if _, ok := r.replacements[id]; ok {
		return r.OpenData(ctx, id)
	}
	return r.Workspace.OpenRawData(ctx, id)
}
func (r *replacementReader) ListAttributes(ctx context.Context, id uint64, yield func(string) error) error {
	if yield == nil {
		return fs.ErrInvalid
	}
	return r.Workspace.ListAttributes(ctx, id, func(name string) error {
		if r.replacements[id].removed[name] {
			return nil
		}
		return yield(name)
	})
}
func (r *replacementReader) OpenAttribute(ctx context.Context, id uint64, name string) (filesystem.Value, error) {
	if _, err := r.get(ctx, id); err != nil {
		return nil, err
	}
	if r.replacements[id].removed[name] {
		return nil, fs.ErrNotExist
	}
	return r.Workspace.OpenAttribute(ctx, id, name)
}

type replacementValue struct {
	block.Source
	ctx context.Context
}

func (v *replacementValue) Close() error { return nil }
func (v *replacementValue) ReadAt(p []byte, off int64) (int, error) {
	if err := v.ctx.Err(); err != nil {
		return 0, err
	}
	return v.Source.ReadAt(p, off)
}

// Compare actual directory identities so aliases, symlinked parents and native
// case folding cannot turn an output path into a mutation of the baseline.
func (w *Workspace) checkDestination(destination string) error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.closed {
		return fs.ErrClosed
	}
	original, err := w.root.Stat(".")
	if err != nil {
		return err
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil {
		return err
	}
	parent, err = filepath.Abs(parent)
	if err != nil {
		return err
	}
	for {
		info, err := os.Stat(parent)
		if err != nil {
			return err
		}
		if os.SameFile(original, info) {
			return fmt.Errorf("destination is inside source workspace: %w", fs.ErrInvalid)
		}
		next := filepath.Dir(parent)
		if next == parent {
			return nil
		}
		parent = next
	}
}
