package copyfile

import (
	"context"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/edit"
)

func (c *copier) clone(ctx context.Context, source copyEntry, destination string) error {
	if c.backend.CloneNamespace == "" {
		return fs.ErrInvalid
	}
	metadata := source.node.Metadata
	for _, state := range []filesystem.State{metadata.Mode.State, metadata.UID.State, metadata.GID.State, metadata.BSDFlags.State, metadata.BirthTime.State, metadata.ModifyTime.State, metadata.ChangeTime.State, metadata.AccessTime.State} {
		if state != filesystem.Present {
			return filesystem.ErrUnsupported
		}
	}
	// clonefile copies times and flags regardless of cp -p, clears set-ID,
	// and copies ownership only for an explicitly privileged logical actor.
	metadata.Mode.Value &^= 06000
	metadata.ChangeTime = filesystem.Observed(c.backend.Time)
	if c.backend.ActorUID.State != filesystem.Present || c.backend.ActorUID.Value != 0 {
		created, err := c.creation(ctx, destination, 0100000)
		if err != nil {
			return err
		}
		metadata.UID, metadata.GID = created.UID, created.GID
	}
	if err := c.backend.Apply(ctx, edit.Change{Op: edit.CloneFile, Path: source.path, To: destination, Metadata: &metadata, CloneNamespace: c.backend.CloneNamespace}); err != nil {
		return err
	}
	if err := c.parentTime(ctx, destination); err != nil {
		return err
	}
	if c.backend.Modified != nil {
		if err := c.backend.Modified(ctx, destination); err != nil {
			return err
		}
	}
	if c.backend.CloneResult != nil {
		c.backend.CloneResult(CloneResult{Source: source.path, Destination: destination, Cloned: true})
	}
	return nil
}
