package fixture

import (
	"errors"
	"fmt"
	"net/url"
	"path"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// parseNativeImagePath interprets a macOS POSIX path, independent of the host
// running a portable test. It neither resolves filesystem aliases nor converts
// a Windows drive or UNC path into a macOS identity.
func parseNativeImagePath(raw string) (string, error) {
	if !path.IsAbs(raw) || !utf8.ValidString(raw) || strings.ContainsRune(raw, 0) {
		return "", fmt.Errorf("invalid absolute macOS image path %q", raw)
	}
	return raw, nil
}

func parseNativeImageURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "file" || u.Opaque != "" || u.User != nil || u.Host != "" && !strings.EqualFold(u.Host, "localhost") || u.RawQuery != "" || u.ForceQuery || strings.Contains(raw, "#") || strings.ContainsAny(raw, " \t\r\n") {
		return "", fmt.Errorf("invalid local-file DiskImageURL %q", raw)
	}
	return parseNativeImagePath(u.Path)
}

// imagePathsMatch compares a validated native target path with the caller's
// host path. Resolution is the only filesystem boundary: native macOS runs use
// ordinary canonical paths, while portable tests may explicitly map native
// identities to ordinary files or virtual canonical identities. Parsing always
// happens first, so an injected resolver cannot admit invalid native syntax.
func (d *HostDisk) imagePathsMatch(native, host string) (bool, error) {
	native, err := parseNativeImagePath(native)
	if err != nil {
		return false, err
	}
	resolve := d.imagePathResolver
	if resolve == nil {
		resolve = canonicalHostImagePath
	}
	actual, err := resolve(native)
	if err != nil {
		return false, fmt.Errorf("resolve native image %q: %w", native, err)
	}
	expected, err := resolve(host)
	if err != nil {
		return false, fmt.Errorf("resolve expected image %q: %w", host, err)
	}
	if actual == "" || expected == "" {
		return false, errors.New("image resolver returned an empty identity")
	}
	return actual == expected, nil
}

func canonicalHostImagePath(path string) (string, error) {
	if path == "" {
		return "", errors.New("missing image path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	// Resolve actual filesystem aliases, including /var vs /private/var on
	// macOS. Complete canonical paths remain distinct across directories.
	return filepath.EvalSymlinks(abs)
}
