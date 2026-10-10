package edit

import (
	"context"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/decmpfs"
	"io/fs"
)

func ReplacementNode(ctx context.Context, reader filesystem.Reader, node filesystem.Node, size uint64) (filesystem.Node, map[string]bool, error) {
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

func (v *replacementValue) Unwrap() block.Source { return v.Source }
