package fixture

import (
	"context"
)

// recordBusyDetachEvidence observes only a failed attachment's ownership and
// open-file holders. It never changes the failed verdict or attempts a close.
func (d *HostDisk) recordBusyDetachEvidence(ctx context.Context, a *Attachment) error {
	ctx, cancel := context.WithTimeout(ctx, busyEvidenceTimeout)
	defer cancel()
	capture := newAttachmentDiagnostics(d, a)
	capture.collect(ctx)
	return capture.finish()
}
