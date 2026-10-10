package workspace

import (
	"context"
	"fmt"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/edit"
	"io/fs"
)

// Operation and Change retain the typed preservation API. The shared engine
// also serves managed command sessions without recapturing file payloads.
type Operation = edit.Operation
type Change = edit.Change

const (
	CreateFile          = edit.CreateFile
	CreateDirectory     = edit.CreateDirectory
	CreateSymlink       = edit.CreateSymlink
	CreateHardLink      = edit.CreateHardLink
	RenameEntry         = edit.RenameEntry
	RemoveEntry         = edit.RemoveEntry
	ReplaceFileData     = edit.ReplaceFileData
	SetMetadata         = edit.SetMetadata
	SetAttribute        = edit.SetAttribute
	RemoveAttribute     = edit.RemoveAttribute
	ReplaceResourceFork = edit.ReplaceResourceFork
)

// Edit applies an ordered batch and captures its final tree once, in a NEW
// workspace outside the baseline. Later paths see earlier edits. Rename follows
// native replacement semantics, including the same-inode no-op. Existing source
// metadata/timestamps stay recorded unless explicitly edited; link counts change by the number of aliases
// added/removed, including when the source has aliases outside this workspace.
// New objects have explicit workspace identities; they are not native inode IDs.
// A completion manifest is published only after the batch and all streamed values
// succeed. Failure may leave incomplete output, as with Extract.
func (w *Workspace) Edit(ctx context.Context, changes []Change, destination string, limits Limits) (Report, error) {
	limits, err := limits.Normalize()
	if err != nil {
		return Report{}, err
	}
	if len(changes) == 0 {
		return Report{}, fs.ErrInvalid
	}
	if len(changes) > limits.Entries {
		return Report{}, filesystem.ErrLimit
	}
	if err := w.checkDestination(destination); err != nil {
		return Report{}, err
	}
	r, err := edit.New(ctx, w, limits)
	if err != nil {
		return Report{}, err
	}
	for i, c := range changes {
		if err := ctx.Err(); err != nil {
			return Report{}, err
		}
		if err := r.Apply(ctx, c); err != nil {
			return Report{}, fmt.Errorf("edit %d (%s %q): %w", i, c.Op, c.Path, err)
		}
	}
	return extract(ctx, r, r.Root(), destination, limits, w.ManifestSHA256())
}
