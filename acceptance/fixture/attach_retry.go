package fixture

import (
	"context"
	"errors"
	"fmt"
)

// confirmAttachRetry excludes an existing attachment of this exact backing
// image before repeating a busy attach with no returned device information.
// It never adopts or detaches a device: an observed image or uncertain proof
// leaves the original failed operation fatal.
func (d *HostDisk) confirmAttachRetry(ctx context.Context, path string) error {
	refuse := func(err error) error {
		return fmt.Errorf("confirm image is unattached before retrying attach %q: %w", path, errors.Join(err, ctx.Err()))
	}
	if err := ctx.Err(); err != nil {
		return refuse(err)
	}
	if path == "" {
		return refuse(errors.New("missing expected image path"))
	}
	resolve := d.imagePathResolver
	if resolve == nil {
		resolve = canonicalHostImagePath
	}
	identity, err := resolve(path)
	if err != nil || identity == "" {
		return refuse(errors.Join(errors.New("expected image has no complete canonical identity"), err))
	}
	if err := ctx.Err(); err != nil {
		return refuse(err)
	}
	cmd := Command{Label: "attach-retry-image-inventory", Argv: []string{"hdiutil", "info", "-plist"}, Expected: "0"}
	result := d.C.Run(ctx, cmd)
	if err := errors.Join(d.T.Record(cmd, result), ctx.Err()); err != nil {
		return refuse(err)
	}
	info, err := d.plist(ctx, result.Stdout)
	if err != nil || ctx.Err() != nil {
		return refuse(err)
	}
	images, ok := info["images"].([]any)
	if !ok {
		return refuse(errors.New("framework inventory has no valid image list"))
	}
	for _, raw := range images {
		image, ok := raw.(map[string]any)
		if !ok {
			return refuse(errors.New("framework image identity is incomplete"))
		}
		native, _ := image["image-path"].(string)
		match, err := d.imagePathsMatch(native, path)
		if err != nil || ctx.Err() != nil {
			return refuse(err)
		}
		if match {
			return refuse(errors.New("expected image remains in the framework inventory; refusing duplicate attachment"))
		}
	}
	// A framework omission or successful scoped-class miss alone is not a
	// retry permission. Independently inspect both qualified kernel backends.
	for _, scope := range []struct {
		label  string
		argv   []string
		legacy bool
	}{
		{"ioreg-attach-retry-image-ownership", imageRegistryArgs, false},
		{"ioreg-attach-retry-legacy-image-ownership", legacyRegistryArgs, true},
	} {
		roots, err := d.registryInventory(ctx, scope.label, scope.argv)
		if err != nil {
			return refuse(err)
		}
		for _, root := range roots {
			class, _ := root["IOObjectClass"].(string)
			if scope.legacy && !legacyImageClass(class) || !scope.legacy && class != "AppleDiskImageDevice" {
				return refuse(errors.New("kernel image scope has an unqualified root"))
			}
			present, err := d.registryImagePresent(root, path, scope.legacy, 0)
			if err != nil || ctx.Err() != nil {
				return refuse(err)
			}
			if present {
				return refuse(errors.New("expected image remains in kernel ancestry; refusing duplicate attachment"))
			}
		}
	}
	return ctx.Err()
}
