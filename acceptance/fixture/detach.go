package fixture

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
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
		owned, err := d.attachedTo(ctx, a)
		if err != nil {
			return false, "", errors.Join(fmt.Errorf("confirm attachment ownership before detaching %s: %w", a.Dev, err), ctx.Err())
		}
		if err := ctx.Err(); err != nil {
			return false, "", err
		}
		if !owned {
			return true, "", nil
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

// attachedTo reports whether hdiutil still lists the attachment's device under
// the same full image path. Distinct continuation directories all use the name
// writable.raw, so a basename cannot establish ownership.
func (d *HostDisk) attachedTo(ctx context.Context, a *Attachment) (bool, error) {
	cmd := Command{Label: "hdiutil-info", Argv: []string{"hdiutil", "info", "-plist"}, Expected: "0"}
	result := d.C.Run(ctx, cmd)
	if err := d.T.Record(cmd, result); err != nil {
		return false, err
	}
	info, err := d.plist(ctx, result.Stdout)
	if err != nil {
		return false, err
	}
	images, ok := info["images"].([]any)
	if !ok {
		return false, errors.New("hdiutil inventory has no valid image list")
	}
	var owners []map[string]any
	incomplete := false
	for _, img := range images {
		image, ok := img.(map[string]any)
		if !ok {
			incomplete = true
			continue
		}
		entities, ok := image["system-entities"].([]any)
		if !ok {
			incomplete = true
			continue
		}
		for _, e := range entities {
			entity, ok := e.(map[string]any)
			dev, identified := entity["dev-entry"].(string)
			if !ok || !identified || dev == "" {
				incomplete = true
				continue
			}
			if dev == a.Dev {
				owners = append(owners, image)
			}
		}
	}
	if len(owners) > 1 {
		return false, fmt.Errorf("hdiutil inventory has ambiguous owners for %s", a.Dev)
	}
	if len(owners) == 0 {
		if incomplete {
			return false, fmt.Errorf("hdiutil inventory cannot establish whether %s is still attached", a.Dev)
		}
		return false, nil
	}
	// Incomplete metadata for unrelated images cannot invalidate a positively
	// identified device. Resolve only this owner's path and the expected image.
	path, _ := owners[0]["image-path"].(string)
	actual, err := canonicalImagePath(path)
	if err != nil {
		return false, fmt.Errorf("resolve image owning %s: %w", a.Dev, err)
	}
	expected, err := canonicalImagePath(a.Image)
	if err != nil {
		return false, fmt.Errorf("resolve expected image %q: %w", a.Image, err)
	}
	return actual == expected, nil
}

func canonicalImagePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("missing image path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// This preserves legitimate /var versus /private/var aliases on macOS
	// without guessing that different complete paths identify the same image.
	return filepath.EvalSymlinks(abs)
}
