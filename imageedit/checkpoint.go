package imageedit

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type CheckpointRecoveryOptions struct {
	Partition int
	Format    string // UDRO or UDZO; default UDZO.
}

// RecoverCheckpoint preserves original evidence and publishes a fully validated
// recovered APFS image. Source/decoded-disk admission and final publication use
// the same managed scratch and no-overwrite path as other image operations.
func RecoverCheckpoint(ctx context.Context, sourcePath, destination string, o CheckpointRecoveryOptions) (Report, error) {
	return transformImage(ctx, sourcePath, destination, Options{Partition: o.Partition, Format: o.Format}, func(source block.Source, isAPFS bool) error {
		if !isAPFS {
			return fmt.Errorf("checkpoint recovery requires APFS: %w", filesystem.ErrUnsupported)
		}
		_, err := apfs.ValidateCheckpointRecovery(ctx, source)
		return err
	}, func(view *mutablePartition, _ bool) (Report, error) {
		checkpoint, err := apfs.RecoverCheckpoint(ctx, view)
		if err != nil {
			return Report{}, err
		}
		container, err := apfs.Open(view)
		if err != nil {
			return Report{}, err
		}
		return Report{VolumeID: container.Volumes[0].UUID, FreeBlocks: checkpoint.FreeBlocks,
			Transaction: uint64(checkpoint.SelectedTransaction), Checkpoint: &checkpoint}, nil
	})
}
