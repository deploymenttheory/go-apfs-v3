package edit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"maps"
	"math"
	"slices"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/filesec"
)

func (o *editedObject) detachCloneStream(name string) {
	if o.node.CloneStreams == nil {
		return
	}
	if name == "" {
		o.node.CloneStreams.Data = ""
	} else {
		delete(o.node.CloneStreams.Attributes, name)
	}
	o.node.CloneStreams.Partial = slices.DeleteFunc(o.node.CloneStreams.Partial, func(s string) bool { return s == name })
	if o.node.CloneStreams.Data == "" && len(o.node.CloneStreams.Attributes) == 0 && len(o.node.CloneStreams.Partial) == 0 {
		o.node.CloneStreams = nil
	}
}

func cloneLineage(namespace string, source filesystem.Identity, destination uint64, stream string) string {
	// This hashes lineage, never contents. A revision namespace prevents object
	// ID reuse in a later tree from identifying an unrelated replacement stream.
	value, _ := json.Marshal(struct {
		Namespace   string
		Source      filesystem.Identity
		Destination uint64
		Stream      string
	}{namespace, source, destination, stream})
	sum := sha256.Sum256(value)
	return "clone:" + hex.EncodeToString(sum[:])
}

func (r *Tree) cloneFile(ctx context.Context, c Change) error {
	if r.NameRules().Format != "APFS" {
		return filesystem.ErrUnsupported
	}
	from, name, err := r.parent(ctx, c.Path)
	if err != nil {
		return err
	}
	entry, err := r.Lookup(ctx, from, name)
	if err != nil {
		return err
	}
	source, err := r.getNode(ctx, entry.Object)
	if err != nil {
		return err
	}
	if source.node.Metadata.Mode.Value&0170000 != 0100000 || c.Metadata.Mode.Value&0170000 != 0100000 {
		return fs.ErrInvalid
	}
	parent, name, err := r.parent(ctx, c.To)
	if err != nil {
		return err
	}
	if _, present := r.entries[parent][r.key(name)]; present {
		return fs.ErrExist
	}
	name, err = r.storedName(name)
	if err != nil {
		return err
	}
	if r.next == math.MaxUint64 || len(r.nodes) >= r.limits.Objects || r.count >= r.limits.Entries {
		return filesystem.ErrLimit
	}
	for _, state := range []filesystem.State{c.Metadata.Mode.State, c.Metadata.UID.State, c.Metadata.GID.State, c.Metadata.BSDFlags.State, c.Metadata.BirthTime.State, c.Metadata.ModifyTime.State, c.Metadata.ChangeTime.State, c.Metadata.AccessTime.State} {
		if state != filesystem.Present {
			return fs.ErrInvalid
		}
	}
	var names []string
	if err := r.ListAttributes(ctx, entry.Object, func(name string) error { names = append(names, name); return nil }); err != nil {
		return err
	}
	if len(names) > maxAttributes {
		return filesystem.ErrLimit
	}
	security, err := filesec.Read(ctx, r, parent)
	if err != nil {
		return err
	}
	inherited, err := filesec.Inherit(security, false)
	if err != nil {
		return err
	}
	cloned := &editedObject{node: copyNode(source.node), data: source.data, origin: source.origin, attributes: maps.Clone(source.attributes), removed: maps.Clone(source.removed), fresh: true, refs: 1}
	if !source.fresh {
		cloned.origin = entry.Object
	}
	if cloned.attributes == nil {
		cloned.attributes = map[string]block.Source{}
	}
	if cloned.removed == nil {
		cloned.removed = map[string]bool{}
	}
	// clonefile without CLONE_ACL inherits the destination directory ACL;
	// the source ACL is never copied as an ordinary opaque attribute.
	delete(cloned.attributes, filesec.Attribute)
	cloned.removed[filesec.Attribute] = true
	if inherited != nil {
		cloned.attributes[filesec.Attribute] = bytes.NewReader(inherited)
		delete(cloned.removed, filesec.Attribute)
	}
	sharing := source.node.CloneStreams
	if sharing == nil {
		sharing = &filesystem.CloneStreams{}
	}
	sharing = &filesystem.CloneStreams{Data: sharing.Data, Attributes: maps.Clone(sharing.Attributes), Partial: slices.Clone(sharing.Partial)}
	if sharing.Attributes == nil {
		sharing.Attributes = map[string]string{}
	}
	next := r.next + 1
	if sharing.Data == "" && !slices.Contains(sharing.Partial, "") {
		sharing.Data = cloneLineage(c.CloneNamespace, source.node.Identity, next, "")
	}
	for _, name := range names {
		if name == filesec.Attribute {
			continue
		}
		if sharing.Attributes[name] == "" && !slices.Contains(sharing.Partial, name) {
			sharing.Attributes[name] = cloneLineage(c.CloneNamespace, source.node.Identity, next, name)
		}
	}
	source.node.CloneStreams = sharing
	cloned.node.CloneStreams = copyNode(source.node).CloneStreams
	// ACL inheritance changes only the destination stream. Existing source
	// and peer ACL sharing remains an untouched captured relationship.
	cloned.detachCloneStream(filesec.Attribute)
	cloned.node.Identity = filesystem.Identity{Object: next}
	cloned.node.Created, cloned.node.DataModified, cloned.node.LinksModified = true, true, false
	cloned.node.Links = filesystem.Observed(uint32(1))
	cloned.node.Metadata = *c.Metadata
	r.next = next
	r.nodes[next] = cloned
	r.entries[parent][r.key(name)] = filesystem.DirEntry{Name: name, Object: next}
	r.count++
	return ctx.Err()
}
