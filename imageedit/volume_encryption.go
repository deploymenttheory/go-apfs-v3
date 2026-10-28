package imageedit

import (
	"context"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// ConvertVolumeEncryption publishes a completed conversion of one existing
// volume. Options supplies source/peer credentials and independent DMG policy;
// conversion.Password supplies only the new APFS encryption credential.
func ConvertVolumeEncryption(ctx context.Context, source, destination string, options Options, conversion apfs.EncryptionConversion) (Report, error) {
	return Edit(ctx, source, destination, options, func(editor *Editor) error {
		_, err := editor.ConvertVolumeEncryption(conversion)
		return err
	})
}

// ConvertVolumeEncryption participates in the same private ordered transaction
// as file edits and password changes. The transaction owns the completed keys;
// neither an expired Editor nor a report retains borrowed password bytes.
func (e *Editor) ConvertVolumeEncryption(conversion apfs.EncryptionConversion) (Report, error) {
	if err := e.ready(); err != nil {
		return Report{}, err
	}
	e.command++
	if !e.isAPFS {
		e.failed = fmt.Errorf("volume conversion requires APFS: %w", filesystem.ErrUnsupported)
		return Report{}, e.failed
	}
	changed, err := apfs.ConvertVolumeEncryption(e.ctx, e.view.authenticated, e.options.Volume, conversion, e.options.Time)
	if err != nil {
		e.failed = err
		return Report{}, err
	}
	report := Report{VolumeID: changed.VolumeID, FreeBlocks: changed.FreeBlocks, Transaction: changed.Transaction, VolumeEncryption: &changed.Encryption}
	e.collect(report)
	return report, nil
}
