package fixture

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
)

const retainedRegistryTextLimit = 8 << 20

var imageRegistryArgs = []string{"/usr/sbin/ioreg", "-a", "-l", "-r", "-c", "AppleDiskImageDevice"}
var mediaRegistryArgs = []string{"/usr/sbin/ioreg", "-a", "-l", "-r", "-c", "IOMedia", "-d", "1"}

func isRegistryInventory(argv []string) bool {
	return slices.Equal(argv, imageRegistryArgs) || slices.Equal(argv, mediaRegistryArgs)
}

// kernelImageOwnership uses the live IOService ancestry independently of the
// DiskImages framework's image list. Chromium's public-IOKit implementation uses
// IOMedia -> AppleDiskImageDevice -> DiskImageURL for this same association:
// https://github.com/chromium/chromium/blob/main/chrome/browser/mac/install_from_dmg.mm
// A scoped-class miss cannot establish that a BSD device has disappeared.
func (d *HostDisk) kernelImageOwnership(ctx context.Context, a *Attachment) (bool, error) {
	if !strings.HasPrefix(a.Dev, "/dev/disk") || !inventoryReference(a.Dev) {
		return false, fmt.Errorf("invalid whole BSD device %q", a.Dev)
	}
	roots, err := d.registryInventory(ctx, "ioreg-image-ownership", imageRegistryArgs)
	if err != nil {
		return false, err
	}
	var owners []map[string]any
	for _, root := range roots {
		if err := walkRegistry(root, nil, strings.TrimPrefix(a.Dev, "/dev/"), 0, &owners); err != nil {
			return false, err
		}
	}
	if len(owners) > 1 {
		return false, fmt.Errorf("kernel registry has ambiguous image owners for %s", a.Dev)
	}
	if len(owners) == 1 {
		if owners[0] == nil {
			return false, fmt.Errorf("kernel media %s has no qualified AppleDiskImageDevice ancestor", a.Dev)
		}
		raw, ok := owners[0]["DiskImageURL"].(string)
		if !ok {
			return false, fmt.Errorf("kernel owner of %s has no string DiskImageURL", a.Dev)
		}
		actual, err := localImageURL(raw)
		if err != nil {
			return false, fmt.Errorf("kernel owner of %s: %w", a.Dev, err)
		}
		expected, err := canonicalImagePath(a.Image)
		if err != nil {
			return false, fmt.Errorf("resolve expected image %q: %w", a.Image, err)
		}
		return actual == expected, nil
	}

	// Read the entire IOMedia class independently. An empty scoped image
	// archive, an unknown backend or a still-existing unbound BSD name is
	// unknown ownership, never permission to detach or report success.
	media, err := d.registryInventory(ctx, "ioreg-media-absence", mediaRegistryArgs)
	if err != nil {
		return false, err
	}
	identified := 0
	seen := map[string]bool{}
	for _, node := range media {
		class, ok := node["IOObjectClass"].(string)
		if !ok || class != "IOMedia" {
			return false, errors.New("kernel IOMedia archive has an unidentified class")
		}
		if children, present := node["IORegistryEntryChildren"]; present {
			items, ok := children.([]any)
			if !ok || len(items) != 0 {
				return false, errors.New("kernel IOMedia root-only archive has unexpected children")
			}
		}
		raw, present := node["BSD Name"]
		if !present {
			continue // An unpublished medium has no BSD name to match.
		}
		name, ok := raw.(string)
		if !ok || !registryBSDName(name) || seen[name] {
			return false, errors.New("kernel IOMedia archive has invalid or duplicate BSD identities")
		}
		seen[name] = true
		identified++
		if name == strings.TrimPrefix(a.Dev, "/dev/") {
			return false, fmt.Errorf("kernel media %s still exists without a proven image owner", a.Dev)
		}
	}
	if identified == 0 {
		return false, errors.New("kernel IOMedia archive cannot corroborate device absence")
	}
	return false, nil
}

func (d *HostDisk) registryInventory(ctx context.Context, label string, argv []string) ([]map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	cmd := Command{Label: label, Argv: append([]string(nil), argv...), Expected: "0"}
	result := d.C.Run(ctx, cmd)
	if err := errors.Join(d.T.Record(cmd, result), ctx.Err()); err != nil {
		return nil, err
	}
	if len(result.Stdout) == 0 || len(result.Stdout) > retainedRegistryTextLimit {
		return nil, errors.New("kernel registry archive size outside bounds")
	}
	// plutil handles native opaque property types; only the ownership fields
	// and tree shape are interpreted here. The original archive remains in
	// the transcript independently of this conversion.
	var roots []map[string]any
	err := d.plistInto(ctx, result.Stdout, &roots)
	if err == nil && roots == nil {
		err = errors.New("kernel registry archive is not an array")
	}
	for _, root := range roots {
		if root == nil {
			err = errors.Join(err, errors.New("kernel registry root is not a dictionary"))
		}
	}
	return roots, errors.Join(err, ctx.Err())
}

func walkRegistry(node, owner map[string]any, target string, depth int, matches *[]map[string]any) error {
	if depth > 64 {
		return errors.New("kernel image ancestry exceeds the qualified depth")
	}
	if class, _ := node["IOObjectClass"].(string); class == "AppleDiskImageDevice" {
		owner = node
	}
	if raw, present := node["BSD Name"]; present {
		name, ok := raw.(string)
		if !ok || !registryBSDName(name) {
			return errors.New("kernel image archive has an invalid BSD name")
		}
		if name == target {
			if class, _ := node["IOObjectClass"].(string); class != "IOMedia" {
				return errors.New("kernel BSD target is not a qualified IOMedia node")
			}
			*matches = append(*matches, owner)
		}
	}
	if raw, present := node["IORegistryEntryChildren"]; present {
		children, ok := raw.([]any)
		if !ok {
			return errors.New("kernel image archive has malformed children")
		}
		for _, raw := range children {
			child, ok := raw.(map[string]any)
			if !ok {
				return errors.New("kernel image archive has a non-dictionary child")
			}
			if err := walkRegistry(child, owner, target, depth+1, matches); err != nil {
				return err
			}
		}
	}
	return nil
}

func registryBSDName(name string) bool {
	if !strings.HasPrefix(name, "disk") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(name, "disk"), "s")
	if len(parts) > 3 { // Whole media, partition, or synthesized snapshot slice.
		return false
	}
	for _, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" {
			return false
		}
	}
	return true
}

func localImageURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "file" || u.Opaque != "" || u.User != nil || u.Host != "" && !strings.EqualFold(u.Host, "localhost") || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || !filepath.IsAbs(u.Path) || strings.ContainsRune(u.Path, 0) || strings.ContainsAny(raw, " \t\r\n") {
		return "", fmt.Errorf("invalid local-file DiskImageURL %q", raw)
	}
	return canonicalImagePath(u.Path)
}
