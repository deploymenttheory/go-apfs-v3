package imageedit

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// ChangeVolumePassword publishes a new image after replacing one admitted APFS
// crypto user's password. OldPassword authenticates the selected volume unless
// Options already supplies its credential. Independently encrypted peers use
// Options.VolumeCredentials. Image-envelope encryption follows ordinary policy.
func ChangeVolumePassword(ctx context.Context, source, destination string, options Options, change apfs.PasswordChange) (Report, error) {
	if options.VolumePassword == nil {
		options.VolumePassword = change.OldPassword
	}
	return Edit(ctx, source, destination, options, func(editor *Editor) error {
		_, err := editor.ChangeVolumePassword(change)
		return err
	})
}

// ChangeVolumePassword participates in the same unpublished ordered transaction
// as file edits. Keys remain owned by that transaction; no password is retained
// by the Editor or report. Any error invalidates the entire transaction.
func (e *Editor) ChangeVolumePassword(change apfs.PasswordChange) (Report, error) {
	if err := e.ready(); err != nil {
		return Report{}, err
	}
	e.command++
	if !e.isAPFS {
		e.failed = fmt.Errorf("volume password changes require APFS: %w", filesystem.ErrUnsupported)
		return Report{}, e.failed
	}
	changed, err := apfs.ChangeVolumePassword(e.ctx, e.view.mutationSource(), e.options.Volume, change, e.options.Time)
	if err != nil {
		e.failed = err
		return Report{}, err
	}
	report := Report{VolumeID: changed.VolumeID, FreeBlocks: changed.FreeBlocks, Transaction: changed.Transaction, CryptoUser: changed.CryptoUser}
	e.collect(report)
	return report, nil
}
