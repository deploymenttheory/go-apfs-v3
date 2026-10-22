package fixture

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// recordBusyDetachEvidence observes only a failed attachment's ownership and
// open-file holders. It never changes the failed verdict or attempts a close.
func (d *HostDisk) recordBusyDetachEvidence(ctx context.Context, a *Attachment) error {
	if ctx.Err() != nil {
		return nil
	}
	owned, err := d.attachedTo(ctx, a)
	if err != nil {
		return fmt.Errorf("retain busy attachment ownership: %w", err)
	}
	if !owned {
		return nil
	}
	paths := []string{a.Image, a.Dev}
	if a.RDev != "" {
		paths = append(paths, a.RDev)
	}
	var evidenceErr error
	for _, cmd := range []Command{
		{Label: "busy-detach-device", Argv: []string{"diskutil", "info", "-plist", a.Dev}, Expected: "record", Timeout: 10 * time.Second},
		{Label: "busy-detach-open-files", Argv: append([]string{"/usr/sbin/lsof", "-nP", "--"}, paths...), Sudo: true, Expected: "record", Timeout: 10 * time.Second},
	} {
		// lsof's no-open-files exit is useful evidence too. Only command launch
		// and deadline failures add another error to the existing fatal result.
		if err := d.T.Record(cmd, d.C.Run(ctx, cmd)); err != nil {
			evidenceErr = errors.Join(evidenceErr, fmt.Errorf("retain busy attachment evidence: %w", err))
		}
	}
	return evidenceErr
}
