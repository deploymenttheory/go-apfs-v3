package filecompression

import (
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestCompressionLineageUsesOnlyItsActualStorageAndKeepsIndependentFork(t *testing.T) {
	node := filesystem.Node{Size: 100, Compression: filesystem.Observed(filesystem.Compression{Type: 3}), CloneStreams: &filesystem.CloneStreams{Attributes: map[string]string{
		filesystem.ResourceFork: "independent-resource", filesystem.Decmpfs: "compressed-data", "org.go-apfs": "opaque-attribute",
	}}}
	token := logicalCloneToken(node)
	node.CloneStreams.Attributes[filesystem.ResourceFork] = "another-independent-resource"
	if token == "" || logicalCloneToken(node) != token {
		t.Fatal("inline compressed data identity came from an unrelated fork")
	}
	before := *node.CloneStreams
	before.Attributes = map[string]string{filesystem.ResourceFork: "another-independent-resource", filesystem.Decmpfs: "compressed-data", "org.go-apfs": "opaque-attribute"}
	transformCloneStreams(&node, token, false, false, false)
	if node.CloneStreams.Data != token || node.CloneStreams.Attributes[filesystem.Decmpfs] != "" || node.CloneStreams.Attributes[filesystem.ResourceFork] != "another-independent-resource" || node.CloneStreams.Attributes["org.go-apfs"] != "opaque-attribute" {
		t.Fatal("compression transformation detached unrelated stream lineage", node.CloneStreams)
	}
	if reflect.DeepEqual(before, *node.CloneStreams) {
		t.Fatal("compression representation did not change")
	}
}
