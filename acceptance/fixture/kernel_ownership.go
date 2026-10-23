package fixture

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
)

const retainedRegistryTextLimit = 8 << 20

var imageRegistryArgs = []string{"/usr/sbin/ioreg", "-a", "-l", "-r", "-c", "AppleDiskImageDevice"}
var legacyRegistryArgs = []string{"/usr/sbin/ioreg", "-a", "-l", "-r", "-c", "IOHDIXHDDrive"}
var mediaRegistryArgs = []string{"/usr/sbin/ioreg", "-a", "-l", "-r", "-c", "IOMedia", "-d", "1"}

func isRegistryInventory(argv []string) bool {
	return slices.Equal(argv, imageRegistryArgs) || slices.Equal(argv, legacyRegistryArgs) || slices.Equal(argv, mediaRegistryArgs)
}

// kernelAttachmentOwnership uses the live IOService ancestry independently of the
// DiskImages framework's image list. Chromium's public-IOKit implementation uses
// IOMedia -> AppleDiskImageDevice -> DiskImageURL for this same association:
// https://github.com/chromium/chromium/blob/main/chrome/browser/mac/install_from_dmg.mm
// A scoped-class miss cannot establish that a BSD device has disappeared.
func (d *HostDisk) kernelAttachmentOwnership(ctx context.Context, a *Attachment) (AttachmentOwnership, error) {
	if !strings.HasPrefix(a.Dev, "/dev/disk") || !inventoryReference(a.Dev) {
		return OwnershipUnknown, fmt.Errorf("invalid whole BSD device %q", a.Dev)
	}
	roots, err := d.registryInventory(ctx, "ioreg-image-ownership", imageRegistryArgs)
	if err != nil {
		return OwnershipUnknown, err
	}
	modernRoots := roots
	var legacyRoots []map[string]any
	var owners []map[string]any
	for _, root := range roots {
		if err := walkRegistry(root, nil, strings.TrimPrefix(a.Dev, "/dev/"), false, 0, &owners); err != nil {
			return OwnershipUnknown, err
		}
	}
	legacy := len(owners) == 0
	if legacy {
		// Older IOHDIX backends expose an exact CFData filesystem path instead
		// of a URL. This is a separate ancestry proof, not an attach retry:
		// https://github.com/chromium/chromium/blob/4a8573cb240df29b0e4d9820303538fb28e31d84/chrome/browser/mac/install_from_dmg.mm
		roots, err = d.registryInventory(ctx, "ioreg-legacy-image-ownership", legacyRegistryArgs)
		if err != nil {
			return OwnershipUnknown, err
		}
		legacyRoots = roots
		for _, root := range roots {
			if err := walkRegistry(root, nil, strings.TrimPrefix(a.Dev, "/dev/"), true, 0, &owners); err != nil {
				return OwnershipUnknown, err
			}
		}
	}
	if len(owners) > 1 {
		return OwnershipUnknown, fmt.Errorf("kernel registry has ambiguous image owners for %s", a.Dev)
	}
	if len(owners) == 1 {
		if owners[0] == nil {
			return OwnershipUnknown, fmt.Errorf("kernel media %s has no qualified image ancestor", a.Dev)
		}
		actual, err := registryOwnerPath(owners[0], legacy)
		if err != nil {
			return OwnershipUnknown, fmt.Errorf("kernel owner of %s: %w", a.Dev, err)
		}
		return d.imageOwnership(actual, a.Image)
	}
	// A stale device handle can disappear while this same backing image
	// remains attached elsewhere. Never retarget it or claim it was released.
	for _, scope := range []struct {
		roots  []map[string]any
		legacy bool
	}{{modernRoots, false}, {legacyRoots, true}} {
		for _, root := range scope.roots {
			class, _ := root["IOObjectClass"].(string)
			if (scope.legacy && !legacyImageClass(class)) || (!scope.legacy && class != "AppleDiskImageDevice") {
				return OwnershipUnknown, errors.New("kernel image scope has an unqualified root while proving release")
			}
			present, err := d.registryImagePresent(root, a.Image, scope.legacy, 0)
			if err != nil {
				return OwnershipUnknown, err
			}
			if present {
				return OwnershipUnknown, fmt.Errorf("expected image remains in kernel ancestry without the requested device %s", a.Dev)
			}
		}
	}

	// Read the entire IOMedia class independently. An empty scoped image
	// archive, an unknown backend or a still-existing unbound BSD name is
	// unknown ownership, never permission to detach or report success.
	media, err := d.registryInventory(ctx, "ioreg-media-absence", mediaRegistryArgs)
	if err != nil {
		return OwnershipUnknown, err
	}
	identified := 0
	seen := map[string]bool{}
	for _, node := range media {
		class, ok := node["IOObjectClass"].(string)
		if !ok || !qualifiedMediaRegistryClass(class) {
			return OwnershipUnknown, errors.New("kernel IOMedia archive has an unidentified class")
		}
		if children, present := node["IORegistryEntryChildren"]; present {
			items, ok := children.([]any)
			if !ok || len(items) != 0 {
				return OwnershipUnknown, errors.New("kernel IOMedia root-only archive has unexpected children")
			}
		}
		raw, present := node["BSD Name"]
		if !present {
			continue // An unpublished medium has no BSD name to match.
		}
		name, ok := raw.(string)
		if !ok || !registryBSDName(name) || seen[name] {
			return OwnershipUnknown, errors.New("kernel IOMedia archive has invalid or duplicate BSD identities")
		}
		seen[name] = true
		identified++
		if name == strings.TrimPrefix(a.Dev, "/dev/") {
			return OwnershipUnknown, fmt.Errorf("kernel media %s still exists without a proven image owner", a.Dev)
		}
	}
	if identified == 0 {
		return OwnershipUnknown, errors.New("kernel IOMedia archive cannot corroborate device absence")
	}
	return OwnershipAbsent, nil
}

func (d *HostDisk) registryImagePresent(node map[string]any, expected string, legacy bool, depth int) (bool, error) {
	if depth > 64 {
		return false, errors.New("kernel image ancestry exceeds the qualified depth")
	}
	class, _ := node["IOObjectClass"].(string)
	if class == "AppleDiskImageDevice" || legacyImageClass(class) {
		actual, err := registryOwnerPath(node, legacy)
		if err != nil {
			return false, err
		}
		match, err := d.imagePathsMatch(actual, expected)
		if err != nil || match {
			return match, err
		}
	}
	if raw, exists := node["IORegistryEntryChildren"]; exists {
		children, ok := raw.([]any)
		if !ok {
			return false, errors.New("kernel image archive has malformed children")
		}
		for _, raw := range children {
			child, ok := raw.(map[string]any)
			if !ok {
				return false, errors.New("kernel image archive has a non-dictionary child")
			}
			present, err := d.registryImagePresent(child, expected, legacy, depth+1)
			if err != nil || present {
				return present, err
			}
		}
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
	if len(result.Stdout) == 0 {
		// A successful scoped class search emits no plist when it has no
		// matches. All three native captures in run 39941597269 record this
		// exact result. It permits another independent proof, never absence.
		if slices.Equal(argv, imageRegistryArgs) || slices.Equal(argv, legacyRegistryArgs) {
			return nil, nil
		}
		return nil, errors.New("kernel media inventory is empty; absence is not established")
	}
	if len(result.Stdout) > retainedRegistryTextLimit {
		return nil, errors.New("kernel registry archive size outside bounds")
	}
	roots, err := decodeRegistryOwnership(result.Stdout)
	return roots, errors.Join(err, ctx.Err())
}

func walkRegistry(node, owner map[string]any, target string, legacy bool, depth int, matches *[]map[string]any) error {
	if depth > 64 {
		return errors.New("kernel image ancestry exceeds the qualified depth")
	}
	class, _ := node["IOObjectClass"].(string)
	if class == "AppleDiskImageDevice" || legacyImageClass(class) {
		if legacyImageClass(class) != legacy {
			return errors.New("kernel registry has mixed image backend ancestry")
		}
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
			if err := walkRegistry(child, owner, target, legacy, depth+1, matches); err != nil {
				return err
			}
		}
	}
	return nil
}

func legacyImageClass(class string) bool {
	return class == "IOHDIXHDDrive" || class == "IOHDIXHDDriveInKernel" || class == "IOHDIXHDDriveOutKernel"
}

func registryOwnerPath(owner map[string]any, legacy bool) (string, error) {
	if legacy {
		if _, mixed := owner["DiskImageURL"]; mixed {
			return "", errors.New("kernel image owner has mixed URL and filesystem-path bindings")
		}
		path, ok := owner["image-path"].(registryPathData)
		if !ok {
			return "", errors.New("kernel image owner has no CFData image-path")
		}
		// The reference copies the complete CFData bytes, adding its own C++
		// string terminator. Never trim a NUL or guess a URL/text encoding here.
		return parseNativeImagePath(string(path))
	}
	if _, mixed := owner["image-path"]; mixed {
		return "", errors.New("kernel image owner has mixed URL and filesystem-path bindings")
	}
	url, ok := owner["DiskImageURL"].(string)
	if !ok {
		return "", errors.New("kernel image owner has no string DiskImageURL")
	}
	return parseNativeImageURL(url)
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

// These actual roots were retained from the complete IOMedia class query on
// macOS 15, 26 and 27 in run 39941597269. ioreg class matching includes native
// subclasses; a new unqualified class still cannot establish device absence.
func qualifiedMediaRegistryClass(class string) bool {
	switch class {
	case "IOMedia", "AppleAPFSMedia", "AppleAPFSVolume", "AppleAPFSSnapshot":
		return true
	default:
		return false
	}
}
