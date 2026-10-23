package fixture

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

func (d *HostDisk) Detach(ctx context.Context, a *Attachment) error {
	err := Settle(ctx, d.T, "detach-busy", BusyWait, func() (bool, string, error) {
		if err := ctx.Err(); err != nil {
			return false, "", err
		}
		// A device number can be reused before the first cleanup call as
		// well as after a busy report. Bind every action to this image's
		// exact full path; unknown ownership never permits a detach.
		ownership, err := d.attachmentOwnership(ctx, a)
		if err != nil {
			return false, "", &AttachmentOwnershipError{State: OwnershipUnknown, Device: a.Dev, Image: a.Image, Cause: errors.Join(fmt.Errorf("confirm attachment ownership before detaching %s: %w", a.Dev, err), ctx.Err())}
		}
		if err := ctx.Err(); err != nil {
			return false, "", err
		}
		switch ownership {
		case OwnershipAbsent:
			return true, "", nil
		case OwnershipOwned:
			// The exact owner permits this normal detach request.
		default:
			return false, "", &AttachmentOwnershipError{State: ownership, Device: a.Dev, Image: a.Image}
		}
		if err := ctx.Err(); err != nil {
			return false, "", err
		}
		cmd := Command{Label: "detach", Argv: []string{"hdiutil", "detach", a.Dev}, Expected: "record"}
		result := d.C.Run(ctx, cmd)
		err = d.T.Record(cmd, result)
		if ctx.Err() != nil {
			return false, "", errors.Join(err, ctx.Err())
		}
		if err != nil {
			return false, "", err
		}
		err = fmt.Errorf("hdiutil detach %s: exit %d: %s", a.Dev, result.Status, strings.TrimSpace(string(result.Stderr)))
		switch result.Status {
		case 0:
			return true, "", nil
		case 16: // EBUSY.
			return false, err.Error(), nil
		default:
			return false, "", err
		}
	})
	var unsettled *NotSettledError
	if errors.As(err, &unsettled) {
		return errors.Join(err, d.recordBusyDetachEvidence(ctx, a))
	}
	return err
}

// attachmentOwnership binds the device to the complete image path, using an independent
// kernel association when the framework inventory has no usable target binding.
// Distinct continuation directories all use writable.raw, so a basename cannot
// establish ownership.
func (d *HostDisk) attachmentOwnership(ctx context.Context, a *Attachment) (AttachmentOwnership, error) {
	cmd := Command{Label: "hdiutil-info", Argv: []string{"hdiutil", "info", "-plist"}, Expected: "0"}
	result := d.C.Run(ctx, cmd)
	if err := d.T.Record(cmd, result); err != nil {
		return OwnershipUnknown, err
	}
	info, err := d.plist(ctx, result.Stdout)
	if err != nil {
		return OwnershipUnknown, err
	}
	images, ok := info["images"].([]any)
	if !ok {
		return OwnershipUnknown, errors.New("hdiutil inventory has no valid image list")
	}
	var owners []map[string]any
	for _, img := range images {
		image, ok := img.(map[string]any)
		if !ok {
			continue
		}
		entities, ok := image["system-entities"].([]any)
		if !ok {
			continue
		}
		for _, e := range entities {
			entity, ok := e.(map[string]any)
			dev, identified := entity["dev-entry"].(string)
			if !ok || !identified || dev == "" {
				continue
			}
			if dev == a.Dev {
				owners = append(owners, image)
			}
		}
	}
	if len(owners) > 1 {
		return OwnershipUnknown, fmt.Errorf("hdiutil inventory has ambiguous owners for %s", a.Dev)
	}
	if len(owners) == 0 {
		// A framework inventory omitted a raw attachment after successful
		// unmounts in native CI. Its absence cannot mean detached. Require
		// an independent kernel binding, or corroborated kernel-media absence.
		return d.kernelAttachmentOwnership(ctx, a)
	}
	// Incomplete metadata for unrelated images cannot invalidate a positively
	// identified device. Resolve only this owner's path and the expected image.
	path, _ := owners[0]["image-path"].(string)
	return d.imageOwnership(path, a.Image)
}
