package filecompression

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"slices"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/decmpfs"
)

func transformedCloneToken(label, token string) string {
	if token == "" {
		return ""
	}
	// This derives a new representation of explicit source lineage. Equal
	// encoded or logical payloads never create a group.
	digest := sha256.Sum256([]byte("clone representation:" + label + ":" + token))
	return hex.EncodeToString(digest[:])
}

func logicalCloneToken(node filesystem.Node) string {
	clones := node.CloneStreams
	if clones == nil {
		return ""
	}
	if node.Compression.State != filesystem.Present {
		return clones.Data
	}
	token := clones.Attributes[filesystem.Decmpfs]
	resource, err := decmpfs.UsesResourceFork(node.Compression.Value.Type)
	if err != nil {
		return ""
	}
	if resource {
		token = clones.Attributes[filesystem.ResourceFork]
	}
	return transformedCloneToken(fmt.Sprintf("decoded:%d:%d", node.Compression.Value.Type, node.Size), token)
}

func transformCloneStreams(node *filesystem.Node, logical string, compressed, resource, replaceResource bool) {
	if node.CloneStreams == nil {
		return
	}
	clones := *node.CloneStreams
	clones.Attributes = maps.Clone(clones.Attributes)
	clones.Partial = slices.Clone(clones.Partial)
	clones.Data = ""
	delete(clones.Attributes, filesystem.Decmpfs)
	if replaceResource {
		delete(clones.Attributes, filesystem.ResourceFork)
	}
	clones.Partial = slices.DeleteFunc(clones.Partial, func(name string) bool {
		return name == "" || name == filesystem.Decmpfs || replaceResource && name == filesystem.ResourceFork
	})
	if compressed && logical != "" {
		if clones.Attributes == nil {
			clones.Attributes = map[string]string{}
		}
		clones.Attributes[filesystem.Decmpfs] = transformedCloneToken("zlib-descriptor", logical)
		if resource {
			clones.Attributes[filesystem.ResourceFork] = transformedCloneToken("zlib-resource", logical)
		}
	} else {
		clones.Data = logical
	}
	if clones.Data == "" && len(clones.Attributes) == 0 && len(clones.Partial) == 0 {
		node.CloneStreams = nil
	} else {
		node.CloneStreams = &clones
	}
}
