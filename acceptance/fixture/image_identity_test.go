package fixture

import (
	"context"
	"encoding/base64"
	"errors"
	"io/fs"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

const projectedImagePrefix = "/Volumes/ordinary image fixtures/"

// Synthetic native identities explicitly project ordinary host paths. The
// reversible token keeps complete host paths distinct without treating their
// separators/drive syntax as macOS path syntax. Captured evidence is untouched.
func projectedImagePath(host string) string {
	return projectedImagePrefix + base64.RawURLEncoding.EncodeToString([]byte(host)) + "/writable.raw"
}

func projectedImageResolver(aliases map[string]string) func(string) (string, error) {
	return func(input string) (string, error) {
		if strings.HasPrefix(input, projectedImagePrefix) {
			token := strings.TrimPrefix(input, projectedImagePrefix)
			if !strings.HasSuffix(token, "/writable.raw") {
				return "", fs.ErrNotExist
			}
			decoded, err := base64.RawURLEncoding.DecodeString(strings.TrimSuffix(token, "/writable.raw"))
			if err != nil {
				return "", err
			}
			input = string(decoded)
		}
		if canonical, ok := aliases[input]; ok {
			input = canonical
		}
		return canonicalHostImagePath(input)
	}
}

func imageTestDisk(c Commander) *HostDisk {
	return &HostDisk{C: c, T: &Transcript{}, imagePathResolver: projectedImageResolver(nil)}
}

// This ordinary synthetic path reproduces the original Windows job's URI
// construction. Its host syntax must not become a macOS native image identity.
func TestOwnershipFixtureProjectsWindowsPathsBeforeFormingNativeFileURLs(t *testing.T) {
	const host = `C:\Users\RUNNER~1\AppData\Local\Temp\TestDetachUsesKernelOwnershipWhenTheNativeFrameworkInventoryOmit632658357\001\writable.raw`
	const malformed = `file://C:%5CUsers%5CRUNNER~1%5CAppData%5CLocal%5CTemp%5CTestDetachUsesKernelOwnershipWhenTheNativeFrameworkInventoryOmit632658357%5C001%5Cwritable.raw`
	if got := (&url.URL{Scheme: "file", Path: host}).String(); got != malformed {
		t.Fatalf("the original Windows failure pattern changed: %q", got)
	}
	got := imageFileURL(host)
	u, err := url.Parse(got)
	if err != nil || got == malformed || u.Host != "" || !strings.HasPrefix(u.Path, "/Volumes/") || strings.ContainsRune(u.Path, '\\') {
		t.Fatalf("Windows host path leaked into a native image URL: %q (%v)", got, err)
	}
	if _, err := parseNativeImageURL(malformed); err == nil {
		t.Fatal("the malformed captured URL became a valid native identity")
	}
}

func TestMacOSImageParsingIsIndependentOfHostPathSyntax(t *testing.T) {
	for _, path := range []string{"/Volumes/source image/writable.raw", "/C:/Users/runner/writable.raw", `/Volumes/back\slash/writable.raw`} {
		parsed, err := parseNativeImageURL((&url.URL{Scheme: "file", Path: path}).String())
		if err != nil || parsed != path {
			t.Fatalf("host syntax changed the macOS path %q: %q %v", path, parsed, err)
		}
	}
	for _, path := range []string{`C:\Users\runner\writable.raw`, `\\server\share\writable.raw`, "relative/writable.raw", "/Volumes/invalid\x00.raw"} {
		if _, err := parseNativeImagePath(path); err == nil {
			t.Fatalf("non-native path was admitted: %q", path)
		}
	}
}

func TestImageIdentityResolvesCompleteNativeAndHostPathsThroughOneExplicitBoundary(t *testing.T) {
	const host = `C:\Users\runner\source image\writable.raw`
	const native = "/Volumes/source image/writable.raw"
	const alias = "/Volumes/source alias/writable.raw"
	const foreign = "/Volumes/foreign image/writable.raw"
	bindings := map[string]string{host: "/canonical/source/writable.raw", native: "/canonical/source/writable.raw", alias: "/canonical/source/writable.raw", foreign: "/canonical/foreign/writable.raw"}
	var calls []string
	disk := &HostDisk{imagePathResolver: func(input string) (string, error) {
		calls = append(calls, input)
		if identity, ok := bindings[input]; ok {
			return identity, nil
		}
		return "", fs.ErrNotExist
	}}
	for _, input := range []string{native, alias} {
		if same, err := disk.imagePathsMatch(input, host); err != nil || !same {
			t.Fatalf("declared complete identity/alias failed: %q %v", input, err)
		}
	}
	if same, err := disk.imagePathsMatch(foreign, host); err != nil || same {
		t.Fatalf("a same-basename foreign image matched: %v", err)
	}
	if _, err := disk.imagePathsMatch("/Volumes/unknown/writable.raw", host); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("unknown identity lost its resolver refusal", err)
	}
	before := len(calls)
	if _, err := disk.imagePathsMatch(host, host); err == nil || len(calls) != before {
		t.Fatal("host drive syntax reached resolution as a native target")
	}
	disk.imagePathResolver = func(string) (string, error) { return "", nil }
	if _, err := disk.imagePathsMatch(native, host); err == nil {
		t.Fatal("empty identities were accepted as equal")
	}
}

func TestImageIdentityOrdinaryFileResolutionPreservesCanonicalPathsAndErrors(t *testing.T) {
	image := detachImage(t, t.TempDir())
	canonical, err := canonicalHostImagePath(image)
	if err != nil {
		t.Fatal(err)
	}
	if canonical != filepath.Clean(image) {
		// TempDir itself may have an actual host alias (e.g. /var on macOS).
		if other, err := canonicalHostImagePath(canonical); err != nil || other != canonical {
			t.Fatalf("canonical host identity is not stable: %q %v", canonical, err)
		}
	}
	if _, err := canonicalHostImagePath(filepath.Join(t.TempDir(), "missing.raw")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("ordinary-file absence lost its typed cause", err)
	}
}

func TestImageIdentityResolutionFailureKeepsCancellationAndPreventsDetach(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	image := detachImage(t, t.TempDir())
	c := &kernelOwnershipCommander{
		global: []byte(`<plist><dict><key>images</key><array/></dict></plist>`),
		images: registryArchive(registryImage(imageFileURL(image), registryMedia("disk17"))),
	}
	disk := imageTestDisk(c)
	cause := errors.New("image identity resolver unavailable")
	disk.imagePathResolver = func(string) (string, error) {
		cancel()
		return "", cause
	}
	err := disk.Detach(ctx, &Attachment{Image: image, Dev: "/dev/disk17"})
	if !errors.Is(err, cause) || !errors.Is(err, context.Canceled) || c.count("detach") != 0 {
		t.Fatalf("unknown identity allowed action or lost an original error: %v", err)
	}
}
