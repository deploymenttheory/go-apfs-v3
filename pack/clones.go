package pack

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/block"
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

func cloneOutcomes(ctx context.Context, reader filesystem.Reader, verify bool) ([]CloneOutcome, error) {
	type member struct {
		path, name string
		copied     string
		object     uint64
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
				groups[clones.Data] = append(groups[clones.Data], member{path: path, copied: copied, object: id})
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
				groups[token] = append(groups[token], member{path: path, name: name, copied: copied, object: id})
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
	var verifiedBytes int64
	for _, members := range groups {
		if len(members) < 2 {
			continue
		}
		if verify {
			var first [32]byte
			var size int64
			for i, member := range members {
				if member.name != members[0].name {
					return nil, fmt.Errorf("incompatible declared clone stream kind: %w", filesystem.ErrCorrupt)
				}
				digest, bytes, err := cloneValueDigest(ctx, reader, member.object, member.name, &verifiedBytes)
				if err != nil {
					return nil, err
				}
				if i > 0 && (digest != first || bytes != size) {
					return nil, fmt.Errorf("conflicting declared clone payload before compression: %w", filesystem.ErrCorrupt)
				}
				first, size = digest, bytes
			}
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

// Validate original raw values before a storage policy can replace their
// representation. Hashes verify an existing declaration; they never form one.
func cloneValueDigest(ctx context.Context, reader filesystem.Reader, object uint64, name string, total *int64) (digest [32]byte, size int64, err error) {
	var value filesystem.Value
	if name == "" {
		value, err = reader.OpenRawData(ctx, object)
	} else {
		value, err = reader.OpenAttribute(ctx, object, name)
	}
	if err != nil {
		return digest, 0, err
	}
	defer func() { err = errors.Join(err, value.Close()) }()
	size = value.Size()
	if size < 0 {
		return digest, size, filesystem.ErrCorrupt
	}
	if size > 1<<40 || size > (1<<40)-*total {
		return digest, size, filesystem.ErrLimit
	}
	*total += size
	if size == 0 {
		return sha256.Sum256(nil), size, ctx.Err()
	}
	hash := sha256.New()
	buffer := make([]byte, 64<<10)
	for offset := int64(0); offset < size; {
		if err := ctx.Err(); err != nil {
			return digest, size, err
		}
		chunk := buffer[:min(int64(len(buffer)), size-offset)]
		if err := block.ReadFull(value, chunk, offset); err != nil {
			return digest, size, err
		}
		_, _ = hash.Write(chunk)
		offset += int64(len(chunk))
	}
	copy(digest[:], hash.Sum(nil))
	return digest, size, ctx.Err()
}
