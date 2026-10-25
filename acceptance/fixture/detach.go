package fixture

import (
	"context"
	"errors"
	"fmt"
	"time"
)

func (d *HostDisk) Detach(ctx context.Context, a *Attachment) error {
	started := time.Now()
	// The per-call observer cannot replace the caller's commander or leak into
	// other attachments. A first successful or permanent-failure request keeps
	// its original argv, transcript and behavior.
	observed := *d
	capture := newAttachmentDiagnostics(&observed, a)
	capture.started = started
	observed.C = &detachOperationCommander{delegate: d.C, evidence: capture}
	attempts := 0
	_, err := observed.imageOperation(ctx, "detach-busy", func() (Command, bool, error) {
		// A device number can be reused before the first cleanup call as
		// well as after a busy report. Bind every action to this image's
		// exact full path; unknown ownership never permits a detach.
		ownership, err := observed.attachmentOwnership(ctx, a)
		if err != nil {
			return Command{}, false, &AttachmentOwnershipError{State: OwnershipUnknown, Device: a.Dev, Image: a.Image, Cause: errors.Join(fmt.Errorf("confirm attachment ownership before detaching %s: %w", a.Dev, err), ctx.Err())}
		}
		if err := ctx.Err(); err != nil {
			return Command{}, false, err
		}
		switch ownership {
		case OwnershipAbsent:
			return Command{}, true, nil
		case OwnershipOwned:
			// The exact owner permits this normal detach request.
		default:
			return Command{}, false, &AttachmentOwnershipError{State: ownership, Device: a.Dev, Image: a.Image}
		}
		argv := []string{"hdiutil", "detach"}
		if attempts != 0 {
			// imageOperation permits another action only after an explicit
			// busy result. Debug implies verbose; it adds observations, not
			// force, another request, or a different cleanup policy.
			argv = append(argv, "-debug")
		}
		if attempts == BusyWait.Attempts-1 {
			// macOS 27 can keep refusing the deprecated detach path after
			// unmount. Use its recommended normal eject for the final
			// permitted request, under the same fresh ownership check.
			argv = []string{"diskutil", "eject"}
		}
		attempts++
		return Command{Label: "detach", Argv: append(argv, a.Dev)}, false, nil
	})
	var unsettled *NotSettledError
	if errors.As(err, &unsettled) {
		probeCtx, cancel := context.WithTimeout(ctx, busyEvidenceTimeout)
		defer cancel()
		capture.collect(probeCtx)
	}
	if capture.busy {
		return errors.Join(err, capture.finish())
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
		state, err := d.kernelAttachmentOwnership(ctx, a)
		if err != nil || state != OwnershipAbsent {
			return state, err
		}
		// A missing old BSD name cannot release an image which the same
		// framework inventory still lists under a different device.
		for _, raw := range images {
			image, ok := raw.(map[string]any)
			if !ok {
				return OwnershipUnknown, errors.New("framework image identity is incomplete while proving release")
			}
			path, _ := image["image-path"].(string)
			match, err := d.imagePathsMatch(path, a.Image)
			if err != nil {
				return OwnershipUnknown, err
			}
			if match {
				return OwnershipUnknown, errors.New("expected image remains in the framework inventory under another or unknown device")
			}
		}
		return OwnershipAbsent, nil
	}
	// Incomplete metadata for unrelated images cannot invalidate a positively
	// identified device. Resolve only this owner's path and the expected image.
	path, _ := owners[0]["image-path"].(string)
	return d.imageOwnership(path, a.Image)
}
