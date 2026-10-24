package imageedit

import (
	"context"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/copyfile"
)

// COPY outcomes describe only destinations completed by this call. A lazy
// existing image may be much larger than the bounded paths the copy touches;
// reporting must never enumerate unrelated directories or earlier imports.
func copyMetadataOmissions(ctx context.Context, reader filesystem.Reader, destinations map[string]bool) ([]filesystem.MetadataOmissionRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	paths := map[uint64]string{}
	for text := range destinations {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		id, canonical, err := copyfile.Resolve(ctx, reader, text, false)
		if err != nil {
			return nil, err
		}
		if first, ok := paths[id]; !ok || canonical < first {
			paths[id] = canonical
		}
	}
	type objectPath struct {
		id   uint64
		path string
	}
	ordered := make([]objectPath, 0, len(paths))
	for id, text := range paths {
		ordered = append(ordered, objectPath{id, text})
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].path < ordered[j].path })
	var result []filesystem.MetadataOmissionRecord
	metadata := 0
	for _, entry := range ordered {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		node, err := reader.Stat(ctx, entry.id)
		if err != nil {
			return nil, err
		}
		if node.Identity.Object != entry.id {
			return nil, filesystem.ErrCorrupt
		}
		if err := filesystem.ValidateMetadataOmissions(node.MetadataOmissions); err != nil {
			return nil, err
		}
		metadata += len(entry.path) + 256
		if metadata > 64<<20 {
			return nil, filesystem.ErrLimit
		}
		for _, value := range node.MetadataOmissions {
			metadata += len(value.Reason) + len(value.SourceFormat) + 64
			if metadata > 64<<20 {
				return nil, filesystem.ErrLimit
			}
			result = append(result, filesystem.MetadataOmissionRecord{Object: entry.id, Path: entry.path, MetadataOmission: value})
		}
	}
	return result, nil
}
