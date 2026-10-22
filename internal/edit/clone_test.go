package edit

import (
	"bytes"
	"context"
	"io"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestCloneKeepsIndependentInodesAndDetachesOnlyChangedStreams(t *testing.T) {
	ctx := context.Background()
	base := newCountingVolume(0)
	tree, err := New(ctx, base, DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	metadata := base.nodes[smallDir].Metadata
	metadata.Mode = filesystem.Observed(uint32(0100640))
	apply := func(c Change) {
		t.Helper()
		if err := tree.ApplyCommand(ctx, c); err != nil {
			t.Fatal(c.Op, err)
		}
	}
	apply(Change{Op: CreateFile, Path: "/Small/source", Metadata: &metadata, Data: bytes.NewReader([]byte("shared data")), Attributes: map[string]block.Source{filesystem.ResourceFork: bytes.NewReader([]byte("shared fork")), "org.go-apfs.attr": bytes.NewReader([]byte("shared attribute"))}})
	apply(Change{Op: CloneFile, Path: "/Small/source", To: "/Small/clone", Metadata: &metadata, CloneNamespace: "immutable-revision"})
	id := func(p string) uint64 {
		t.Helper()
		id, err := filesystem.Lookup(ctx, tree, p)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	sourceID, cloneID := id("/Small/source"), id("/Small/clone")
	source, _ := tree.Stat(ctx, sourceID)
	clone, _ := tree.Stat(ctx, cloneID)
	if sourceID == cloneID || source.CloneStreams == nil || clone.CloneStreams == nil || source.CloneStreams.Data == "" || source.CloneStreams.Data != clone.CloneStreams.Data || source.CloneStreams.Attributes[filesystem.ResourceFork] != clone.CloneStreams.Attributes[filesystem.ResourceFork] {
		t.Fatal("clone did not declare distinct inode/shared stream identity", source, clone)
	}
	apply(Change{Op: CreateHardLink, Path: "/Small/clone", To: "/Small/alias"})
	apply(Change{Op: ReplaceFileData, Path: "/Small/source", Data: bytes.NewReader([]byte("private source"))})
	source, _ = tree.Stat(ctx, sourceID)
	clone, _ = tree.Stat(ctx, cloneID)
	if source.CloneStreams.Data != "" || clone.CloneStreams.Data == "" || source.CloneStreams.Attributes[filesystem.ResourceFork] != clone.CloneStreams.Attributes[filesystem.ResourceFork] {
		t.Fatal("data replacement detached the wrong streams")
	}
	apply(Change{Op: ReplaceResourceFork, Path: "/Small/clone", Data: bytes.NewReader([]byte("private fork"))})
	clone, _ = tree.Stat(ctx, cloneID)
	if clone.CloneStreams.Attributes[filesystem.ResourceFork] != "" || clone.CloneStreams.Attributes["org.go-apfs.attr"] == "" {
		t.Fatal("fork replacement detached another attribute")
	}
	apply(Change{Op: RemoveEntry, Path: "/Small/source"})
	value, err := tree.OpenData(ctx, cloneID)
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
	if err != nil || string(got) != "shared data" {
		t.Fatal(string(got), err)
	}
	if err := value.Close(); err != nil {
		t.Fatal(err)
	}
	if id("/Small/alias") != cloneID {
		t.Fatal("hardlink identity changed")
	}
}

func TestWholeStreamReplacementClearsOnlyItsPartialSharingMarker(t *testing.T) {
	object := editedObject{node: filesystem.Node{CloneStreams: &filesystem.CloneStreams{Attributes: map[string]string{"org.go-apfs.attr": "unchanged"}, Partial: []string{"", filesystem.ResourceFork}}}}
	object.detachCloneStream("")
	if object.node.CloneStreams == nil || len(object.node.CloneStreams.Partial) != 1 || object.node.CloneStreams.Partial[0] != filesystem.ResourceFork || object.node.CloneStreams.Attributes["org.go-apfs.attr"] != "unchanged" {
		t.Fatal("data replacement lost an untouched partial/attribute declaration")
	}
	object.detachCloneStream(filesystem.ResourceFork)
	if len(object.node.CloneStreams.Partial) != 0 || object.node.CloneStreams.Attributes["org.go-apfs.attr"] != "unchanged" {
		t.Fatal("fork replacement lost another stream declaration")
	}
}
