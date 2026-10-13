package edit

import (
	"bytes"
	"context"
	"slices"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/filesec"
)

// CopySecurity is cp's dedicated COPYFILE_ACL operation. Ordinary attribute
// commands cannot edit filesec. Direct source ACEs precede inherited destination
// ACEs; explicit empty ACLs remain distinct from absent ones.
func (r *Tree) CopySecurity(ctx context.Context, id uint64, source []byte) error {
	destination, err := filesec.Read(ctx, r, id)
	if err != nil {
		return err
	}
	result, err := filesec.CopyACL(source, destination)
	if err != nil {
		return err
	}
	if bytes.Equal(result, destination) {
		return nil
	}
	o, err := r.getNode(ctx, id)
	if err != nil {
		return err
	}
	if !slices.Contains(o.node.AttributesModified, filesec.Attribute) && len(o.node.AttributesModified) >= maxAttributes {
		return filesystem.ErrLimit
	}
	if result == nil {
		o.removeAttribute(filesec.Attribute)
	} else {
		o.putAttribute(filesec.Attribute, bytes.NewReader(result))
	}
	o.node.AttributesModified = markField(o.node.AttributesModified, filesec.Attribute)
	return nil
}
