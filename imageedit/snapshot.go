package imageedit

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// DeleteSnapshot removes one explicitly selected retained APFS snapshot from a
// private image copy. Name selection is exact; an XID is never parsed from a
// name. The source stays read-only and only the validated completed image is
// published, using Options' partition, volume, time and envelope policies.
func DeleteSnapshot(ctx context.Context, source, destination string, options Options, selector apfs.SnapshotSelector) (Report, error) {
	return Edit(ctx, source, destination, options, func(editor *Editor) error {
		_, err := editor.DeleteSnapshot(selector)
		return err
	})
}

// DeleteSnapshot removes a retained snapshot from the current unpublished APFS
// copy. Later commands see its removal. Any deletion error invalidates the whole
// Edit transaction, even if the callback ignores the error.
func (e *Editor) DeleteSnapshot(selector apfs.SnapshotSelector) (Report, error) {
	if err := e.ready(); err != nil {
		return Report{}, err
	}
	e.command++
	if !e.isAPFS {
		e.failed = fmt.Errorf("snapshot deletion requires APFS: %w", filesystem.ErrUnsupported)
		return Report{}, e.failed
	}
	changed, err := apfs.DeleteSnapshot(e.ctx, e.view, e.options.Volume, selector, e.options.Time)
	if err != nil {
		e.failed = err
		return Report{}, err
	}
	report := Report{VolumeID: changed.VolumeID, Changed: changed.Changed, FreeBlocks: changed.FreeBlocks, Transaction: changed.Transaction}
	e.collect(report)
	return report, nil
}
