package fixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func registryString(text string) string {
	var escaped bytes.Buffer
	_ = xml.EscapeText(&escaped, []byte(text))
	return "<string>" + escaped.String() + "</string>"
}

func registryArchive(nodes ...string) []byte {
	return []byte(xml.Header + `<plist version="1.0"><array>` + strings.Join(nodes, "") + `</array></plist>`)
}

func registryMedia(name string) string {
	return `<dict><key>IOObjectClass</key><string>IOMedia</string><key>BSD Name</key>` + registryString(name) + `</dict>`
}

// These IORegistry archives are synthetic public-API controls. Original native
// inventories remain separate, digest-bound evidence in the platform replays.
func registryImage(imageURL, media string) string {
	return `<dict><key>IOObjectClass</key><string>AppleDiskImageDevice</string><key>DiskImageURL</key>` + registryString(imageURL) + `<key>IORegistryEntryChildren</key><array>` + media + `</array><key>opaque-driver-data</key><data>AAEC</data><key>IORegistryEntryID</key><integer>18446744073709551615</integer></dict>`
}

func imageFileURL(path string) string {
	return (&url.URL{Scheme: "file", Path: projectedImagePath(path)}).String()
}

type kernelOwnershipCommander struct {
	calls                     []Command
	global                    []byte
	images                    []byte
	media                     []byte
	legacy                    []byte
	legacyErr                 error
	registryErr               error
	registryStatus            int
	registryConversionFailure *Result
	busy                      bool
	cancel                    context.CancelFunc
	cancelLegacy              context.CancelFunc
}

func (c *kernelOwnershipCommander) Run(_ context.Context, cmd Command) Result {
	c.calls = append(c.calls, cmd)
	switch cmd.Label {
	case "hdiutil-info":
		return Result{Stdout: c.global}
	case "plutil":
		if bytes.Equal(cmd.Stdin, c.images) && c.registryConversionFailure != nil {
			return *c.registryConversionFailure
		}
		value, err := readInventoryPlist(string(cmd.Stdin))
		if err != nil {
			return Result{Status: 1, Err: err}
		}
		if images, ok := value["images"].([]any); ok && images == nil {
			value["images"] = []any{}
		}
		data, err := json.Marshal(value)
		return Result{Stdout: data, Err: err}
	case "ioreg-image-ownership":
		if c.cancel != nil {
			c.cancel()
		}
		return Result{Stdout: c.images, Status: c.registryStatus, Err: c.registryErr}
	case "ioreg-media-absence":
		return Result{Stdout: c.media}
	case "ioreg-legacy-image-ownership":
		if c.cancelLegacy != nil {
			c.cancelLegacy()
		}
		if c.legacyErr != nil {
			return Result{Status: -1, Err: c.legacyErr}
		}
		if c.legacy == nil {
			return Result{Stdout: registryArchive()}
		}
		return Result{Stdout: c.legacy}
	case "detach":
		if c.busy {
			return Result{Status: 16, Stderr: []byte("Resource busy")}
		}
		return Result{}
	case "busy-detach-device", "busy-detach-open-files":
		return Result{}
	default:
		return Result{Status: -1, Err: fmt.Errorf("unexpected command %q", cmd.Label)}
	}
}

func (c *kernelOwnershipCommander) count(label string) int {
	n := 0
	for _, cmd := range c.calls {
		if cmd.Label == label {
			n++
		}
	}
	return n
}

func TestDetachUsesKernelOwnershipWhenTheNativeFrameworkInventoryOmitsItsImage(t *testing.T) {
	// Synthetic public-API scenario: the framework lists a different complete
	// image while the kernel binds our target. Historical macOS15 transcripts
	// remain archived but do not select an active replay platform.
	framework := []byte(`<plist><dict><key>images</key><array><dict><key>image-path</key><string>/System/Library/synthetic-unrelated.dmg</string><key>system-entities</key><array><dict><key>dev-entry</key><string>/dev/disk3</string></dict></array></dict></array></dict></plist>`)
	image := detachImage(t, t.TempDir())
	att := &Attachment{Image: image, Dev: "/dev/disk17"}
	c := &kernelOwnershipCommander{
		global: framework,
		images: registryArchive(registryImage(imageFileURL(image), registryMedia("disk17"))),
	}
	d := imageTestDisk(c)
	if err := d.Detach(context.Background(), att); err != nil {
		t.Fatal(err)
	}
	if c.count("detach") != 1 || c.count("ioreg-image-ownership") != 1 || c.count("ioreg-media-absence") != 0 {
		t.Fatalf("framework absence falsely completed cleanup: detach=%d kernel=%d full-media=%d", c.count("detach"), c.count("ioreg-image-ownership"), c.count("ioreg-media-absence"))
	}
	if d.T.Commands[0].StdoutText != string(framework) || d.T.Commands[0].StdoutSHA256 != fmt.Sprintf("%x", sha256.Sum256(framework)) {
		t.Fatal("synthetic framework evidence was not retained unchanged")
	}
	if len(d.T.Commands) != 3 || d.T.Commands[1].StdoutText != string(c.images) || d.T.Commands[1].StdoutSHA256 != fmt.Sprintf("%x", sha256.Sum256(c.images)) {
		t.Fatal("raw kernel proof was not retained before the detach")
	}
}

func TestKernelOwnershipLeavesForeignImagesAndUnknownDevicesUntouched(t *testing.T) {
	for _, name := range []string{"foreign image", "ambiguous owner", "unknown class", "unknown media class", "unknown absence class", "missing URL", "typed URL", "remote URL", "remote file host", "relative URL", "URL user", "URL query", "URL fragment", "URL empty fragment", "URL NUL", "missing scoped class", "only partition match", "empty full inventory", "duplicate full media", "malformed full media", "malformed children", "truncated archive", "kernel command failure"} {
		t.Run(name, func(t *testing.T) {
			image := detachImage(t, filepath.Join(t.TempDir(), "original"))
			foreign := detachImage(t, filepath.Join(t.TempDir(), "foreign"))
			owner := registryImage(imageFileURL(image), registryMedia("disk17"))
			c := &kernelOwnershipCommander{global: []byte(`<plist><dict><key>images</key><array/></dict></plist>`), media: registryArchive(registryMedia("disk0"), registryMedia("disk17"))}
			switch name {
			case "foreign image":
				owner = registryImage(imageFileURL(foreign), registryMedia("disk17"))
			case "ambiguous owner":
				owner += registryImage(imageFileURL(foreign), registryMedia("disk17"))
			case "unknown class":
				owner = strings.ReplaceAll(owner, "AppleDiskImageDevice", "UnknownImageBackend")
			case "unknown media class":
				owner = strings.ReplaceAll(owner, "<string>IOMedia</string>", "<string>UnknownMedia</string>")
			case "unknown absence class":
				owner = ""
				c.media = registryArchive(strings.ReplaceAll(registryMedia("disk0"), "IOMedia", "UnknownMedia"))
			case "missing URL":
				owner = strings.ReplaceAll(owner, "DiskImageURL", "unrelated-url")
			case "typed URL":
				owner = strings.ReplaceAll(owner, registryString(imageFileURL(image)), "<data>AAEC</data>")
			case "remote URL":
				owner = registryImage("https://example.invalid/image.raw", registryMedia("disk17"))
			case "remote file host":
				owner = registryImage("file://example.invalid"+image, registryMedia("disk17"))
			case "relative URL":
				owner = registryImage("file:relative.raw", registryMedia("disk17"))
			case "URL user":
				owner = registryImage("file://user@localhost"+image, registryMedia("disk17"))
			case "URL query":
				owner = registryImage(imageFileURL(image)+"?x", registryMedia("disk17"))
			case "URL fragment":
				owner = registryImage(imageFileURL(image)+"#x", registryMedia("disk17"))
			case "URL empty fragment":
				owner = registryImage(imageFileURL(image)+"#", registryMedia("disk17"))
			case "URL NUL":
				owner = registryImage(imageFileURL(image)+"%00", registryMedia("disk17"))
			case "missing scoped class", "empty full inventory":
				owner = ""
				if name == "empty full inventory" {
					c.media = registryArchive()
				}
			case "only partition match":
				owner = registryImage(imageFileURL(image), registryMedia("disk17s1"))
			case "duplicate full media":
				owner = ""
				c.media = registryArchive(registryMedia("disk0"), registryMedia("disk0"))
			case "malformed full media":
				owner = ""
				c.media = registryArchive(`<dict><key>IOObjectClass</key><string>IOMedia</string><key>BSD Name</key><integer>17</integer></dict>`)
			case "kernel command failure":
				c.registryStatus = 1
			case "malformed children":
				owner = strings.ReplaceAll(owner, "<array>"+registryMedia("disk17")+"</array>", "<string>unknown</string>")
			}
			c.images = registryArchive(owner)
			if name == "truncated archive" {
				c.images = c.images[:len(c.images)-10]
			}
			d := imageTestDisk(c)
			err := d.Detach(context.Background(), &Attachment{Image: image, Dev: "/dev/disk17"})
			if name == "foreign image" {
				var refusal *AttachmentOwnershipError
				if !errors.As(err, &refusal) || refusal.State != OwnershipForeign {
					t.Fatal("foreign image was reported as released instead of refused:", err)
				}
			} else if err == nil {
				t.Fatal("unproven ownership was reported as completed cleanup")
			}
			if c.count("detach") != 0 {
				t.Fatal("unproven or foreign ownership permitted a detach")
			}
		})
	}
}

func TestKernelMediaAbsenceRequiresACompleteIndependentInventory(t *testing.T) {
	image := detachImage(t, t.TempDir())
	c := &kernelOwnershipCommander{global: []byte(`<plist><dict><key>images</key><array/></dict></plist>`), images: registryArchive(), media: registryArchive(registryMedia("disk0"), registryMedia("disk0s1"))}
	d := imageTestDisk(c)
	if err := d.Detach(context.Background(), &Attachment{Image: image, Dev: "/dev/disk17"}); err != nil {
		t.Fatal(err)
	}
	if c.count("ioreg-image-ownership") != 1 || c.count("ioreg-media-absence") != 1 || c.count("detach") != 0 {
		t.Fatal("device absence did not require both independent scopes", c.calls)
	}
}

func TestKernelOwnershipCanBindTheTargetMissingFromIncompleteFrameworkRows(t *testing.T) {
	image := detachImage(t, t.TempDir())
	c := &kernelOwnershipCommander{
		global: []byte(`<plist><dict><key>images</key><array><dict><key>image-path</key><string>/unrelated/incomplete.raw</string></dict><dict><key>system-entities</key><array><dict/></array></dict></array></dict></plist>`),
		images: registryArchive(registryImage(imageFileURL(image), registryMedia("disk17"))),
	}
	disk := imageTestDisk(c)
	if err := disk.Detach(context.Background(), &Attachment{Image: image, Dev: "/dev/disk17"}); err != nil || c.count("detach") != 1 || c.count("ioreg-image-ownership") != 1 {
		t.Fatalf("unbound framework rows prevented an independent exact kernel proof: %v", err)
	}
}

func TestKernelOwnershipResolvesEscapedLocalURLsAndDeclaredAliases(t *testing.T) {
	root := t.TempDir()
	image := detachImage(t, filepath.Join(root, "actual space"))
	alias := filepath.Join(root, "alias")
	for _, expected := range []string{image, filepath.Join(alias, filepath.Base(image))} {
		c := &kernelOwnershipCommander{global: []byte(`<plist><dict><key>images</key><array/></dict></plist>`), images: registryArchive(registryImage(imageFileURL(image), registryMedia("disk17")))}
		d := imageTestDisk(c)
		d.imagePathResolver = projectedImageResolver(map[string]string{filepath.Join(alias, filepath.Base(image)): image})
		if err := d.Detach(context.Background(), &Attachment{Image: expected, Dev: "/dev/disk17"}); err != nil || c.count("detach") != 1 {
			t.Fatalf("qualified alias did not establish ownership: %v", err)
		}
	}
}

func TestKernelOwnershipKeepsProbeErrorsAndCancellationBeforeAnyAction(t *testing.T) {
	for _, cancelProbe := range []bool{false, true} {
		t.Run(fmt.Sprint(cancelProbe), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cause := errors.New("kernel registry unavailable")
			image := detachImage(t, t.TempDir())
			c := &kernelOwnershipCommander{global: []byte(`<plist><dict><key>images</key><array/></dict></plist>`), registryErr: cause}
			if cancelProbe {
				c.cancel = cancel
			}
			d := imageTestDisk(c)
			err := d.Detach(ctx, &Attachment{Image: image, Dev: "/dev/disk17"})
			if !errors.Is(err, cause) || cancelProbe && !errors.Is(err, context.Canceled) || c.count("detach") != 0 {
				t.Fatalf("failed/cancelled kernel proof lost its cause or allowed action: %v", err)
			}
		})
	}
}

func TestKernelOwnershipCannotIncreaseTheDetachBudget(t *testing.T) {
	instantWaits(t)
	image := detachImage(t, t.TempDir())
	c := &kernelOwnershipCommander{global: []byte(`<plist><dict><key>images</key><array/></dict></plist>`), images: registryArchive(registryImage(imageFileURL(image), registryMedia("disk17"))), busy: true}
	d := imageTestDisk(c)
	err := d.Detach(context.Background(), &Attachment{Image: image, Dev: "/dev/disk17"})
	var spent *NotSettledError
	if !errors.As(err, &spent) || spent.Checks != 6 || c.count("detach") != 6 {
		t.Fatalf("kernel ownership altered the fatal six-attempt budget: %v calls=%v", err, c.calls)
	}
}

func TestKernelRegistryReceiptsKeepBoundedOriginalTextAndDigests(t *testing.T) {
	for _, argv := range [][]string{imageRegistryArgs, legacyRegistryArgs, mediaRegistryArgs} {
		for _, size := range []int{retainedTextLimit + 1, retainedRegistryTextLimit, retainedRegistryTextLimit + 1} {
			raw := bytes.Repeat([]byte("x"), size)
			transcript := &Transcript{}
			cmd := Command{Label: "registry-receipt", Argv: argv, Expected: "0"}
			if err := transcript.Record(cmd, Result{Stdout: raw}); err != nil {
				t.Fatal(err)
			}
			got := transcript.Commands[0]
			if got.StdoutSHA256 != fmt.Sprintf("%x", sha256.Sum256(raw)) || (got.StdoutText != "") != (size <= retainedRegistryTextLimit) {
				t.Fatal("registry evidence was truncated without its original digest")
			}
			if size > retainedRegistryTextLimit {
				c := &kernelOwnershipCommander{images: raw}
				disk := imageTestDisk(c)
				if _, err := disk.registryInventory(context.Background(), "ioreg-image-ownership", argv); err == nil || c.count("plutil") != 0 {
					t.Fatal("oversized registry proof reached conversion or was admitted")
				}
			}
		}
	}
}
