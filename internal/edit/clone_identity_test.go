package edit

import (
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestCopiedNodeOwnsItsCloneStreamDeclarations(t *testing.T) {
	source := filesystem.Node{CloneStreams: &filesystem.CloneStreams{Data: "explicit-data", Attributes: map[string]string{filesystem.ResourceFork: "explicit-fork"}}}
	clone := CopyNode(source)
	clone.CloneStreams.Data = "private-data"
	clone.CloneStreams.Attributes[filesystem.ResourceFork] = "private-fork"
	if source.CloneStreams.Data != "explicit-data" || source.CloneStreams.Attributes[filesystem.ResourceFork] != "explicit-fork" {
		t.Fatal("editing cloned metadata changed another node's stream declarations")
	}
}
