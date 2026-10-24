package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
)

type attachRetryCommander struct {
	calls                     []Command
	framework, modern, legacy Result
	conversionErr             error
	cancel                    context.CancelFunc
	cancelAt                  string
}

func (c *attachRetryCommander) Run(_ context.Context, cmd Command) Result {
	c.calls = append(c.calls, cmd)
	if c.cancel != nil && cmd.Label == c.cancelAt {
		c.cancel()
	}
	switch {
	case slices.Equal(cmd.Argv, []string{"hdiutil", "info", "-plist"}):
		return c.framework
	case cmd.Label == "plutil":
		return Result{Stdout: cmd.Stdin, Err: c.conversionErr}
	case slices.Equal(cmd.Argv, imageRegistryArgs):
		return c.modern
	case slices.Equal(cmd.Argv, legacyRegistryArgs):
		return c.legacy
	default:
		return Result{Status: -1, Err: errors.New("retry proof attempted an unexpected native command")}
	}
}

func attachRetryFramework(images ...any) []byte {
	if images == nil {
		images = []any{}
	}
	data, _ := json.Marshal(map[string]any{"images": images})
	return data
}

func newAttachRetryCommander() *attachRetryCommander {
	return &attachRetryCommander{framework: Result{Stdout: attachRetryFramework()}, modern: Result{Stdout: registryArchive()}, legacy: Result{Stdout: registryArchive()}}
}

func requireNoAttachmentActions(t *testing.T, c *attachRetryCommander) {
	t.Helper()
	for _, cmd := range c.calls {
		if len(cmd.Argv) > 1 && cmd.Argv[0] == "hdiutil" && (cmd.Argv[1] == "attach" || cmd.Argv[1] == "detach") {
			t.Fatal("absence proof performed an attachment action", cmd.Argv)
		}
	}
}

func TestAttachRetryRequiresFrameworkAndBothKernelBackendsToExcludeTheImage(t *testing.T) {
	for _, state := range []string{"empty archives", "successful class misses", "unrelated same-basename images"} {
		t.Run(state, func(t *testing.T) {
			image := detachImage(t, filepath.Join(t.TempDir(), "expected"))
			c := newAttachRetryCommander()
			if state == "successful class misses" {
				c.modern.Stdout, c.legacy.Stdout = nil, nil
			}
			if state == "unrelated same-basename images" {
				other := detachImage(t, filepath.Join(t.TempDir(), "other"))
				c.framework.Stdout = attachRetryFramework(map[string]any{"image-path": projectedImagePath(other)})
				c.modern.Stdout = registryArchive(registryImage(imageFileURL(other), ""))
				c.legacy.Stdout = registryArchive(legacyRegistryImage("IOHDIXHDDriveOutKernel", []byte(projectedImagePath(other)), ""))
			}
			disk := imageTestDisk(c)
			if err := disk.confirmAttachRetry(context.Background(), image); err != nil {
				t.Fatal("complete negative image proof was refused", err)
			}
			var labels []string
			for _, cmd := range c.calls {
				labels = append(labels, cmd.Label)
			}
			if !reflect.DeepEqual(labels, []string{"attach-retry-image-inventory", "plutil", "ioreg-attach-retry-image-ownership", "ioreg-attach-retry-legacy-image-ownership"}) {
				t.Fatal("retry proof omitted or added a native scope", labels)
			}
			if len(disk.T.Commands) != 3 {
				t.Fatal("original scope receipts were not retained", disk.T.Commands)
			}
			for index, command := range disk.T.Commands {
				emptyClassMiss := state == "successful class misses" && index > 0
				if command.Status != "0" || !emptyClassMiss && command.StdoutSHA256 == "" || emptyClassMiss && command.StdoutSHA256 != "" {
					t.Fatal("scope status or original digest missing", command)
				}
			}
			requireNoAttachmentActions(t, c)
		})
	}
}

func TestAttachRetryRefusesExistingImagesAndUncertainInventories(t *testing.T) {
	for _, state := range []string{"framework presence", "framework alias", "modern presence", "legacy presence", "legacy presence after unrelated modern owner", "missing framework list", "malformed framework row", "missing framework path", "foreign Windows path", "framework launch failure", "plist conversion failure", "modern probe failure", "unknown modern root", "unknown legacy root", "malformed kernel XML", "malformed kernel ancestry", "invalid legacy path bytes", "ambiguous path resolution", "missing expected path"} {
		t.Run(state, func(t *testing.T) {
			image := detachImage(t, filepath.Join(t.TempDir(), "expected"))
			other := detachImage(t, filepath.Join(t.TempDir(), "other"))
			cause := errors.New("specific inventory or path proof failed")
			c := newAttachRetryCommander()
			disk := imageTestDisk(c)
			switch state {
			case "framework presence", "framework alias":
				c.framework.Stdout = attachRetryFramework(map[string]any{"image-path": projectedImagePath(image)})
				if state == "framework alias" {
					alias := filepath.Join(t.TempDir(), "alias.raw")
					disk.imagePathResolver = projectedImageResolver(map[string]string{alias: image})
					image = alias
				}
			case "modern presence":
				c.modern.Stdout = registryArchive(registryImage(imageFileURL(image), ""))
			case "legacy presence", "legacy presence after unrelated modern owner":
				c.legacy.Stdout = registryArchive(legacyRegistryImage("IOHDIXHDDriveOutKernel", []byte(projectedImagePath(image)), ""))
				if state == "legacy presence after unrelated modern owner" {
					c.modern.Stdout = registryArchive(registryImage(imageFileURL(other), ""))
				}
			case "missing framework list":
				c.framework.Stdout = []byte(`{}`)
			case "malformed framework row":
				c.framework.Stdout = attachRetryFramework("unknown")
			case "missing framework path":
				c.framework.Stdout = attachRetryFramework(map[string]any{})
			case "foreign Windows path":
				c.framework.Stdout = attachRetryFramework(map[string]any{"image-path": `C:\opaque\image.raw`})
			case "framework launch failure":
				c.framework.Err = cause
			case "plist conversion failure":
				c.conversionErr = cause
			case "modern probe failure":
				c.modern.Err = cause
			case "unknown modern root":
				c.modern.Stdout = registryArchive(registryMedia("disk17"))
			case "unknown legacy root":
				c.legacy.Stdout = registryArchive(registryImage(imageFileURL(other), ""))
			case "malformed kernel XML":
				c.modern.Stdout = []byte("incomplete archive")
			case "malformed kernel ancestry":
				c.modern.Stdout = registryArchive(`<dict><key>IOObjectClass</key><string>AppleDiskImageDevice</string><key>IORegistryEntryChildren</key><string>unknown</string></dict>`)
			case "invalid legacy path bytes":
				c.legacy.Stdout = registryArchive(legacyRegistryImage("IOHDIXHDDriveOutKernel", []byte("/Volumes/image\x00.raw"), ""))
			case "ambiguous path resolution":
				c.framework.Stdout = attachRetryFramework(map[string]any{"image-path": projectedImagePath(other)})
				resolve := disk.imagePathResolver
				disk.imagePathResolver = func(path string) (string, error) {
					if path == projectedImagePath(other) {
						return "", cause
					}
					return resolve(path)
				}
			case "missing expected path":
				image = ""
			}
			if err := disk.confirmAttachRetry(context.Background(), image); err == nil {
				t.Fatal("existing or unproven image could be attached again")
			} else if (c.framework.Err != nil || c.modern.Err != nil || c.conversionErr != nil || state == "ambiguous path resolution") && !errors.Is(err, cause) {
				t.Fatal("original proof cause was lost", err)
			}
			requireNoAttachmentActions(t, c)
		})
	}
}

func TestAttachRetryProofPreservesCancellationAndFailedProbeCauses(t *testing.T) {
	for _, label := range []string{"before probes", "attach-retry-image-inventory", "plutil", "ioreg-attach-retry-image-ownership", "ioreg-attach-retry-legacy-image-ownership"} {
		t.Run(label, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			c := newAttachRetryCommander()
			cause := errors.New("cancelled inventory also failed")
			c.cancel, c.cancelAt = cancel, label
			switch label {
			case "before probes":
				cancel()
			case "attach-retry-image-inventory":
				c.framework.Err = cause
			case "plutil":
				c.conversionErr = cause
			case "ioreg-attach-retry-image-ownership":
				c.modern.Err = cause
			case "ioreg-attach-retry-legacy-image-ownership":
				c.legacy.Err = cause
			}
			image := detachImage(t, t.TempDir())
			err := imageTestDisk(c).confirmAttachRetry(ctx, image)
			if !errors.Is(err, context.Canceled) || label != "before probes" && !errors.Is(err, cause) {
				t.Fatal("cancellation or simultaneous proof failure was lost", err)
			}
			if label == "before probes" && len(c.calls) != 0 {
				t.Fatal("cancelled proof still queried native state")
			}
			requireNoAttachmentActions(t, c)
		})
	}
}
