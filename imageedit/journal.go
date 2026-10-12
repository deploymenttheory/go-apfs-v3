package imageedit

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
)

type JournalRecoveryOptions struct {
	Partition int
	Format    string // UDRO or UDZO; default UDZO.
}

// RecoverJournal preserves the original image read-only, replays one selected
// HFS+/HFSX internal journal into managed scratch and validates the recovered
// graph before publishing a flushed new image without overwrite. Other disk
// partitions/sectors remain unchanged. No implicit replay occurs on normal
// reader or editing paths. APFS recovery is a separate unsupported operation.
func RecoverJournal(ctx context.Context, sourcePath, destination string, o JournalRecoveryOptions) (Report, error) {
	return transformImage(ctx, sourcePath, destination, Options{Partition: o.Partition, Format: o.Format}, func(source block.Source, isAPFS bool) error {
		if isAPFS {
			return fmt.Errorf("APFS journal replay: %w", filesystem.ErrUnsupported)
		}
		_, err := hfsplus.ValidateJournalReplay(ctx, source)
		return err
	}, func(view *mutablePartition, _ bool) (Report, error) {
		journal, err := hfsplus.RecoverJournal(ctx, view)
		if err != nil {
			return Report{}, err
		}
		volume, err := hfsplus.Open(view)
		if err != nil {
			return Report{}, err
		}
		return Report{VolumeID: volume.VolumeID, FreeBlocks: uint64(volume.FreeBlocks), Journal: &journal}, nil
	})
}
