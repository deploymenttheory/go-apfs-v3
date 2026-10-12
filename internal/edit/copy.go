package edit

import (
	"context"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"slices"
)

// RemoveCopiedCompression clears inactive metadata under complete copy policy.
// Public attribute commands remain unable to manipulate decoding state.
func (r *Tree) RemoveCopiedCompression(ctx context.Context, id uint64) error {
	o, err := r.getNode(ctx, id)
	if err != nil {
		return err
	}
	if o.node.Metadata.BSDFlags.State != filesystem.Present || o.node.Metadata.BSDFlags.Value&32 != 0 {
		return filesystem.ErrUnsupported
	}
	if !slices.Contains(o.node.AttributesModified, filesystem.Decmpfs) && len(o.node.AttributesModified) >= maxAttributes {
		return filesystem.ErrLimit
	}
	o.removeAttribute(filesystem.Decmpfs)
	o.node.AttributesModified = markField(o.node.AttributesModified, filesystem.Decmpfs)
	return nil
}
