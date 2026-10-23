package fixture

import (
	"context"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// Synthetic archives qualify the source-backed legacy class/CFData contract.
// No historical native failure recorded IORegistry or establishes its backend.
func legacyRegistryImage(class string, path []byte, media string) string {
	return `<dict><key>IOObjectClass</key>` + registryString(class) + `<key>image-path</key><data>` + base64.StdEncoding.EncodeToString(path) + `</data><key>IORegistryEntryChildren</key><array>` + media + `</array></dict>`
}

func TestKernelOwnershipBindsLegacyFilesystemPathBytesForKnownImageClasses(t *testing.T) {
	for _, class := range []string{"IOHDIXHDDrive", "IOHDIXHDDriveInKernel", "IOHDIXHDDriveOutKernel"} {
		t.Run(class, func(t *testing.T) {
			image := detachImage(t, filepath.Join(t.TempDir(), "image space"))
			c := &kernelOwnershipCommander{
				global: []byte(`<plist><dict><key>images</key><array/></dict></plist>`),
				images: registryArchive(),
				legacy: registryArchive(legacyRegistryImage(class, []byte(projectedImagePath(image)), registryMedia("disk17"))),
				media:  registryArchive(registryMedia("disk0"), registryMedia("disk17")),
			}
			disk := imageTestDisk(c)
			if err := disk.Detach(context.Background(), &Attachment{Image: image, Dev: "/dev/disk17"}); err != nil {
				t.Fatal(err)
			}
			if c.count("detach") != 1 || c.count("ioreg-image-ownership") != 1 || c.count("ioreg-legacy-image-ownership") != 1 || c.count("ioreg-media-absence") != 0 {
				t.Fatal("legacy exact ownership did not precede the sole detach")
			}
			if len(disk.T.Commands) != 4 || disk.T.Commands[2].StdoutText != string(c.legacy) || !isRegistryInventory(disk.T.Commands[2].Argv) {
				t.Fatal("legacy ownership did not retain the original registry archive")
			}
		})
	}
}

func TestKernelLegacyOwnershipCanonicalizesDeclaredFilesystemAliases(t *testing.T) {
	root := t.TempDir()
	image := detachImage(t, filepath.Join(root, "original"))
	alias := filepath.Join(root, "alias")
	c := &kernelOwnershipCommander{
		global: []byte(`<plist><dict><key>images</key><array/></dict></plist>`),
		images: registryArchive(),
		legacy: registryArchive(legacyRegistryImage("IOHDIXHDDriveOutKernel", []byte(projectedImagePath(filepath.Join(alias, filepath.Base(image)))), registryMedia("disk17"))),
	}
	disk := imageTestDisk(c)
	disk.imagePathResolver = projectedImageResolver(map[string]string{filepath.Join(alias, filepath.Base(image)): image})
	if err := disk.Detach(context.Background(), &Attachment{Image: image, Dev: "/dev/disk17"}); err != nil || c.count("detach") != 1 {
		t.Fatalf("exact canonical alias was not recognized: %v", err)
	}
}

func TestKernelLegacyOwnershipLeavesForeignAndMalformedBindingsUntouched(t *testing.T) {
	for _, name := range []string{"foreign image", "unknown class", "unknown media class", "string path", "missing path", "empty path", "relative path", "URL path", "NUL path", "terminal NUL path", "non-UTF8 path", "oversized path", "invalid base64", "ambiguous owners", "mixed properties", "mixed ancestry"} {
		t.Run(name, func(t *testing.T) {
			image := detachImage(t, filepath.Join(t.TempDir(), "original"))
			path := []byte(projectedImagePath(image))
			class := "IOHDIXHDDriveOutKernel"
			media := registryMedia("disk17")
			switch name {
			case "foreign image":
				path = []byte(projectedImagePath(detachImage(t, filepath.Join(t.TempDir(), "foreign"))))
			case "unknown class":
				class = "IOHDIXUnknownDrive"
			case "unknown media class":
				media = strings.ReplaceAll(media, "IOMedia", "UnknownMedia")
			case "empty path":
				path = nil
			case "relative path":
				path = []byte("relative/writable.raw")
			case "URL path":
				path = []byte(imageFileURL(image))
			case "NUL path":
				path = append([]byte("/tmp/\x00"), path...)
			case "terminal NUL path":
				path = append(path, 0)
			case "non-UTF8 path":
				path = append(path, 0xff)
			case "oversized path":
				path = []byte("/" + strings.Repeat("a", retainedRegistryPathLimit))
			}
			owner := legacyRegistryImage(class, path, media)
			switch name {
			case "string path":
				owner = strings.ReplaceAll(owner, "<data>"+base64.StdEncoding.EncodeToString(path)+"</data>", registryString(string(path)))
			case "missing path":
				owner = strings.ReplaceAll(owner, "image-path", "unused-path")
			case "invalid base64":
				owner = strings.ReplaceAll(owner, base64.StdEncoding.EncodeToString(path), "invalid-base64!")
			case "ambiguous owners":
				owner += owner
			case "mixed properties":
				owner = strings.TrimSuffix(owner, "</dict>") + "<key>DiskImageURL</key>" + registryString(imageFileURL(image)) + "</dict>"
			case "mixed ancestry":
				owner = legacyRegistryImage(class, path, registryImage(imageFileURL(image), media))
			}
			c := &kernelOwnershipCommander{
				global: []byte(`<plist><dict><key>images</key><array/></dict></plist>`),
				images: registryArchive(),
				legacy: registryArchive(owner),
			}
			disk := imageTestDisk(c)
			err := disk.Detach(context.Background(), &Attachment{Image: image, Dev: "/dev/disk17"})
			if name == "foreign image" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unknown legacy ownership was accepted")
			}
			if c.count("detach") != 0 || c.count("ioreg-media-absence") != 0 {
				t.Fatal("a selected foreign/malformed legacy owner caused action or fell through to absence")
			}
		})
	}
}

func TestKernelOwnershipDoesNotReplaceAnInvalidModernProofWithLegacyEvidence(t *testing.T) {
	image := detachImage(t, t.TempDir())
	for _, owner := range []string{
		strings.ReplaceAll(registryImage(imageFileURL(image), registryMedia("disk17")), "DiskImageURL", "unused-url"),
		strings.TrimSuffix(registryImage(imageFileURL(image), registryMedia("disk17")), "</dict>") + "<key>image-path</key><data>" + base64.StdEncoding.EncodeToString([]byte(projectedImagePath(image))) + "</data></dict>",
	} {
		c := &kernelOwnershipCommander{
			global: []byte(`<plist><dict><key>images</key><array/></dict></plist>`),
			images: registryArchive(owner),
			legacy: registryArchive(legacyRegistryImage("IOHDIXHDDriveOutKernel", []byte(projectedImagePath(image)), registryMedia("disk17"))),
		}
		disk := imageTestDisk(c)
		if err := disk.Detach(context.Background(), &Attachment{Image: image, Dev: "/dev/disk17"}); err == nil || c.count("detach") != 0 || c.count("ioreg-legacy-image-ownership") != 0 {
			t.Fatalf("an invalid selected modern proof fell through to another backend: %v", err)
		}
	}
}

func TestKernelLegacyOwnershipKeepsFailedProbeAndCancellationCauses(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	image := detachImage(t, t.TempDir())
	cause := errors.New("legacy registry unavailable")
	c := &kernelOwnershipCommander{
		global:       []byte(`<plist><dict><key>images</key><array/></dict></plist>`),
		images:       registryArchive(),
		legacyErr:    cause,
		cancelLegacy: cancel,
	}
	disk := imageTestDisk(c)
	err := disk.Detach(ctx, &Attachment{Image: image, Dev: "/dev/disk17"})
	if !errors.Is(err, cause) || !errors.Is(err, context.Canceled) || c.count("detach") != 0 || c.count("ioreg-media-absence") != 0 {
		t.Fatalf("legacy proof lost cancellation/original cause or allowed action: %v", err)
	}
}

func TestKernelLegacyOwnershipPreservesTheFatalSixAttemptDetachBudget(t *testing.T) {
	instantWaits(t)
	image := detachImage(t, t.TempDir())
	c := &kernelOwnershipCommander{
		global: []byte(`<plist><dict><key>images</key><array/></dict></plist>`),
		images: registryArchive(),
		legacy: registryArchive(legacyRegistryImage("IOHDIXHDDriveOutKernel", []byte(projectedImagePath(image)), registryMedia("disk17"))),
		busy:   true,
	}
	disk := imageTestDisk(c)
	err := disk.Detach(context.Background(), &Attachment{Image: image, Dev: "/dev/disk17"})
	var spent *NotSettledError
	if !errors.As(err, &spent) || spent.Checks != 6 || c.count("detach") != 6 {
		t.Fatalf("legacy proof changed the fatal six-attempt budget: %v", err)
	}
}
