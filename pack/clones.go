package pack

import (
	"context"
	"fmt"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// CloneOutcome describes what happened to explicit logical sharing. Stream is
// empty for raw data and otherwise names an attribute, including a resource
// fork. Equal independent payloads never create outcomes or shared allocations.
type CloneOutcome struct {
	Volume string `json:"volume,omitempty"`
	Path   string `json:"path"`
	Stream string `json:"stream,omitempty"`
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
}

func cloneOutcomes(ctx context.Context, reader filesystem.Reader) ([]CloneOutcome, error) {
	type member struct {
		path, name string
		copied     string
	}
	groups := map[string][]member{}
	var outcomes []CloneOutcome
	seen := map[uint64]bool{}
	entries, metadataBytes := 0, 0
	var visit func(uint64, string, int) error
	visit = func(id uint64, path string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		metadataBytes += 256 + len(path)
		if entries > 100000 || depth > 256 || metadataBytes > 64<<20 {
			return filesystem.ErrLimit
		}
		if seen[id] {
			return nil
		}
		seen[id] = true
		node, err := reader.Stat(ctx, id)
		if err != nil {
			return err
		}
		if err := filesystem.ValidateCloneStreams(node.CloneStreams); err != nil {
			return err
		}
		if clones := node.CloneStreams; clones != nil {
			if node.Metadata.Mode.Value&0170000 != 0100000 {
				return filesystem.ErrCorrupt
			}
			if len(clones.Partial) != 0 && reader.NameRules().Format == "APFS" {
				return fmt.Errorf("APFS pack cannot preserve partially shared streams: %w", filesystem.ErrUnsupported)
			}
			for _, name := range clones.Partial {
				outcomes = append(outcomes, CloneOutcome{Path: path, Stream: name, Action: "copied", Reason: "filesystem-does-not-support-clones"})
			}
			if clones.Data != "" {
				value, err := reader.OpenRawData(ctx, id)
				if err != nil {
					return err
				}
				copied := ""
				if value.Size() == 0 {
					copied = "empty-stream"
				}
				if err := value.Close(); err != nil {
					return err
				}
				groups[clones.Data] = append(groups[clones.Data], member{path: path, copied: copied})
			}
			for name, token := range clones.Attributes {
				metadataBytes += 512 + len(name) + len(token)
				if metadataBytes > 64<<20 {
					return filesystem.ErrLimit
				}
				value, err := reader.OpenAttribute(ctx, id, name)
				if err != nil {
					return err
				}
				copied := ""
				if (value.Size() <= 1024 || name == filesystem.Decmpfs && value.Size() <= 3802) && name != filesystem.ResourceFork {
					copied = "embedded-attribute"
				}
				if err := value.Close(); err != nil {
					return err
				}
				groups[token] = append(groups[token], member{path: path, name: name, copied: copied})
			}
		}
		if node.Metadata.Mode.Value&0170000 == 0040000 {
			var children []filesystem.DirEntry
			if err := reader.ReadDir(ctx, id, func(entry filesystem.DirEntry) error {
				if len(children) >= 100000 {
					return filesystem.ErrLimit
				}
				children = append(children, entry)
				return nil
			}); err != nil {
				return err
			}
			sort.Slice(children, func(i, j int) bool { return children[i].Name < children[j].Name })
			for _, child := range children {
				childPath := path + "/" + child.Name
				if path == "/" {
					childPath = "/" + child.Name
				}
				if err := visit(child.Object, childPath, depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := visit(reader.Root(), "/", 0); err != nil {
		return nil, err
	}
	for _, members := range groups {
		if len(members) < 2 {
			continue
		}
		for _, member := range members {
			outcome := CloneOutcome{Path: member.path, Stream: member.name, Action: "shared"}
			if member.copied != "" {
				outcome.Action, outcome.Reason = "copied", member.copied
			}
			if reader.NameRules().Format != "APFS" {
				outcome.Action, outcome.Reason = "copied", "filesystem-does-not-support-clones"
			}
			outcomes = append(outcomes, outcome)
		}
	}
	sort.Slice(outcomes, func(i, j int) bool {
		if outcomes[i].Path != outcomes[j].Path {
			return outcomes[i].Path < outcomes[j].Path
		}
		return outcomes[i].Stream < outcomes[j].Stream
	})
	return outcomes, nil
}
