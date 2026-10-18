package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

const fixtureText = "Built filesystem fixture.\n"

// builtImage stages Fixture/example.txt and the symlink Fixture/link through
// the session commands and packs them with the product. Apple-made images and
// their verdicts belong to the acceptance tier; this exercises CLI plumbing.
func builtImage(t *testing.T, format string) string {
	t.Helper()
	root := t.TempDir()
	scratch := filepath.Join(root, "scratch")
	host := filepath.Join(root, "example.txt")
	if err := os.WriteFile(host, []byte(fixtureText), 0600); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(root, format+".dmg")
	for _, args := range [][]string{
		{"session", "create", "--scratch-dir", scratch, "--filesystem", format, "--time", "2026-10-10T00:00:00Z", "stage"},
		{"mkdir", "--scratch-dir", scratch, "--session", "stage", "/Fixture"},
		{"cp", "--scratch-dir", scratch, "--session", "stage", "--from-host", host, "/Fixture/example.txt"},
		{"ln", "--scratch-dir", scratch, "--session", "stage", "-s", "example.txt", "/Fixture/link"},
		{"pack", "--scratch-dir", scratch, "--session", "stage", "--time", "2026-10-10T00:00:00Z", image},
	} {
		var out, diagnostics bytes.Buffer
		if err := run(context.Background(), args, nil, &out, &diagnostics); err != nil {
			t.Fatalf("%v: %v (%s)", args, err, diagnostics.String())
		}
	}
	return image
}

func TestInspectJSONHasNoDiagnosticNoise(t *testing.T) {
	var out, diagnostics bytes.Buffer
	if err := run(context.Background(), []string{"inspect", "--json", builtImage(t, "apfs")}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var r inspect.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Schema != 1 || diagnostics.Len() != 0 || len(r.Partitions) == 0 || r.Partitions[0].APFS == nil {
		t.Fatal("unexpected report schema or diagnostics", out.String(), diagnostics.String())
	}
}

// Image passwords are exact bytes from a file or stdin. APFS volume encryption
// needs Apple-made volumes and is qualified by the acceptance tier; the
// unencrypted built volume here must refuse a volume credential explicitly.
func TestEncryptedImageCatUsesExactPasswordBytesWithoutDiagnosticLeaks(t *testing.T) {
	const password = "public-dmg-password"
	plain := builtImage(t, "apfs")
	image := filepath.Join(t.TempDir(), "encrypted.dmg")
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte(password), 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	if err := run(context.Background(), []string{"pack", "--encryption", "AES-128", "--output-password-file", path, plain, image}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err, diagnostics.String())
	}
	if strings.Contains(out.String()+diagnostics.String(), password) {
		t.Fatal("pack disclosed the password")
	}
	for _, source := range []string{path, "-"} {
		out.Reset()
		diagnostics.Reset()
		if err := run(context.Background(), []string{"cat", "--image-password-file", source, image, "Fixture/example.txt"}, strings.NewReader(password), &out, &diagnostics); err != nil {
			t.Fatal(err)
		}
		if out.String() != fixtureText || diagnostics.Len() != 0 {
			t.Fatal("encrypted cat changed data or emitted diagnostics")
		}
	}
	out.Reset()
	if err := run(context.Background(), []string{"inspect", "--json", "--image-password-file", "-", image}, strings.NewReader(password), &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var report inspect.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Encryption == nil || report.Encryption.KeyBits != 128 || diagnostics.Len() != 0 {
		t.Fatal("missing image encryption report")
	}
	for _, secret := range []string{password + "\n", "wrong-private-input", ""} {
		out.Reset()
		diagnostics.Reset()
		err := run(context.Background(), []string{"cat", "--image-password-file", "-", image, "Fixture/example.txt"}, strings.NewReader(secret), &out, &diagnostics)
		if !errors.Is(err, filesystem.ErrAuthentication) || out.Len() != 0 || diagnostics.Len() != 0 {
			t.Fatal("invalid credential handling", err)
		}
		if secret != "" && strings.Contains(err.Error(), secret) {
			t.Fatal("error disclosed credential")
		}
	}
	if _, err := readPassword("-", strings.NewReader(strings.Repeat("x", 4097))); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal("password input limit", err)
	}
	out.Reset()
	if err := run(context.Background(), []string{"cat", image, "Fixture/example.txt"}, nil, &out, &diagnostics); err == nil || out.Len() != 0 {
		t.Fatal("missing credential opened encrypted image", err)
	}
	if err := run(context.Background(), []string{"cat", "--image-password-file", "-", "--password-file", "-", image, "Fixture/example.txt"}, strings.NewReader(password), &out, &diagnostics); err == nil || !strings.Contains(err.Error(), "both consume stdin") {
		t.Fatal("ambiguous credential input", err)
	}
	if err := run(context.Background(), []string{"cat", "--image-password-file", "-", "--password-file", path, image, "Fixture/example.txt"}, strings.NewReader(password), &out, &diagnostics); err == nil || !strings.Contains(err.Error(), "encrypted APFS volume") || out.Len() != 0 {
		t.Fatal("volume credential accepted for a plaintext volume", err)
	}
}

func TestCatIsByteExactAndDoesNotFollowSymlinks(t *testing.T) {
	for _, name := range []string{"apfs", "hfsplus"} {
		t.Run(name, func(t *testing.T) {
			image := builtImage(t, name)
			var out, diagnostics bytes.Buffer
			if err := run(context.Background(), []string{"cat", image, "Fixture/example.txt"}, nil, &out, &diagnostics); err != nil {
				t.Fatal(err)
			}
			if out.String() != fixtureText || diagnostics.Len() != 0 {
				t.Fatal("file stream was altered", out.String(), diagnostics.String())
			}
			out.Reset()
			if err := run(context.Background(), []string{"cat", image, "Fixture/link"}, nil, &out, &diagnostics); !errors.Is(err, fs.ErrInvalid) {
				t.Fatal("followed symlink", err)
			}
			if out.Len() != 0 {
				t.Fatal("failed cat emitted bytes")
			}
		})
	}
}

func TestUnimplementedCommandDoesNotSucceed(t *testing.T) {
	var out, diagnostics bytes.Buffer
	if err := run(context.Background(), []string{"create", "output.dmg"}, nil, &out, &diagnostics); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatal("unsupported command produced success output")
	}
}

func TestCancelledInspectionReturnsNoReport(t *testing.T) {
	path := builtImage(t, "hfsplus")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, diagnostics bytes.Buffer
	if err := run(ctx, []string{"inspect", path}, nil, &out, &diagnostics); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatal("canceled command produced a report")
	}
}

// A built volume has an empty inventory. Populated snapshot history belongs to
// the acceptance tier; selection of absent history must never expose live files.
func TestSnapshotSelectionNeverFallsBackToLiveFiles(t *testing.T) {
	image := builtImage(t, "apfs")
	var out, diagnostics bytes.Buffer
	if err := run(context.Background(), []string{"snapshot", "list", "--json", image}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Schema    int
		Volume    string
		Snapshots []json.RawMessage
	}
	if err := json.Unmarshal(out.Bytes(), &inventory); err != nil {
		t.Fatal(err)
	}
	if inventory.Schema != 1 || inventory.Volume == "" || inventory.Snapshots == nil || len(inventory.Snapshots) != 0 || diagnostics.Len() != 0 {
		t.Fatal("invalid empty snapshot inventory", out.String(), diagnostics.String())
	}
	for _, selectors := range [][]string{
		{"--snapshot-name", "absent"}, {"--snapshot-xid", "1"}, {"--snapshot-xid", "0"},
		{"--snapshot-name", ""}, {"--snapshot-name", "absent", "--snapshot-xid", "1"},
	} {
		out.Reset()
		args := append([]string{"cat"}, selectors...)
		args = append(args, image, "Fixture/example.txt")
		if err := run(context.Background(), args, nil, &out, &diagnostics); err == nil || out.Len() != 0 {
			t.Fatal("invalid snapshot selector exposed live content", selectors, err)
		}
	}
	out.Reset()
	hfs := builtImage(t, "hfsplus")
	if err := run(context.Background(), []string{"snapshot", "list", hfs}, nil, &out, &diagnostics); !errors.Is(err, filesystem.ErrUnsupported) || out.Len() != 0 {
		t.Fatal("HFS snapshot inventory", err)
	}
	if err := run(context.Background(), []string{"cat", "--snapshot-name", "absent", hfs, "Fixture/example.txt"}, nil, &out, &diagnostics); !errors.Is(err, filesystem.ErrUnsupported) || out.Len() != 0 {
		t.Fatal("HFS snapshot selection", err)
	}
}

func TestExtractAndVerifyPreservationReport(t *testing.T) {
	image := builtImage(t, "apfs")
	destination := filepath.Join(t.TempDir(), "extracted")
	var out, diagnostics bytes.Buffer
	if err := run(context.Background(), []string{"extract", "--json", image, "Fixture/example.txt", destination}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), out.Bytes()...)
	var report struct {
		Schema, Objects, Entries int
		Metadata                 string
	}
	if err := json.Unmarshal(original, &report); err != nil {
		t.Fatal(err)
	}
	if report.Schema != 1 || report.Objects != 1 || report.Entries != 1 || !strings.Contains(report.Metadata, "not applied") || diagnostics.Len() != 0 {
		t.Fatal("missing preservation outcome", out.String())
	}
	out.Reset()
	if err := run(context.Background(), []string{"workspace", "verify", "--json", destination}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Bytes(), original) {
		t.Fatal("reopened report differs")
	}
	out.Reset()
	if err := run(context.Background(), []string{"extract", image, "Fixture/example.txt", destination}, nil, &out, &diagnostics); !errors.Is(err, fs.ErrExist) || out.Len() != 0 {
		t.Fatal("overwrote destination", err)
	}
}

func TestSessionFileCommandsPreserveAliasesAndExport(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	scratch := filepath.Join(parent, "scratch")
	payload := []byte("CLI supplied content\x00\xff")
	contents := filepath.Join(parent, "contents")
	if err := os.WriteFile(contents, payload, 0600); err != nil {
		t.Fatal(err)
	}
	invoke := func(args ...string) []byte {
		t.Helper()
		var out, diagnostics bytes.Buffer
		args = append(args, "--scratch-dir", scratch)
		if err := run(ctx, args, nil, &out, &diagnostics); err != nil {
			t.Fatalf("%v: %v (%s)", args, err, diagnostics.String())
		}
		return out.Bytes()
	}
	// Stage an image whose Fixture subtree carries three names for one file,
	// an attribute to remove and an entry to delete, then pack it.
	image := filepath.Join(parent, "staged.dmg")
	original := filepath.Join(parent, "original")
	if err := os.WriteFile(original, []byte("original shared contents\n"), 0600); err != nil {
		t.Fatal(err)
	}
	invoke("session", "create", "--filesystem", "apfs", "--time", "2026-10-09T00:00:00Z", "stage")
	invoke("mkdir", "--session", "stage", "-p", "/Fixture/links")
	invoke("cp", "--session", "stage", "--from-host", original, "/Fixture/ordinary")
	invoke("ln", "--session", "stage", "/Fixture/ordinary", "/Fixture/alias")
	invoke("ln", "--session", "stage", "/Fixture/ordinary", "/Fixture/links/second")
	invoke("xattr", "--session", "stage", "-w", "--value-file", original, "org.go-apfs.keep", "/Fixture/alias")
	invoke("touch", "--session", "stage", "/Fixture/empty")
	invoke("pack", "--session", "stage", "--time", "2026-10-09T00:00:00Z", image)
	invoke("session", "open", "--image", image, "--path", "Fixture", "--time", "2026-10-10T00:00:00Z", "build")
	invoke("mkdir", "--session", "build", "-p", "/_CodeSignature")
	invoke("cp", "--session", "build", "--from-host", contents, "/_CodeSignature/CodeResources")
	invoke("ln", "--session", "build", "/_CodeSignature/CodeResources", "/seal-alias")
	invoke("cp", "--session", "build", "--from-host", "-X", contents, "/alias")
	invoke("rm", "--session", "build", "/empty")
	invoke("chmod", "--session", "build", "0700", "/seal-alias")
	invoke("xattr", "--session", "build", "-w", "--value-file", contents, "org.test", "/seal-alias")
	invoke("cp", "--session", "build", "--from-host", "--resource-fork", contents, "/seal-alias")
	invoke("xattr", "--session", "build", "-d", "org.go-apfs.keep", "/alias")
	for _, name := range []string{"alias", "ordinary", "links/second"} {
		if got := invoke("cat", "--session", "build", "/"+name); !bytes.Equal(got, payload) {
			t.Fatal(name, string(got))
		}
	}
	destination := filepath.Join(parent, "export")
	invoke("session", "export", "build", destination)
	w, err := workspace.Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	created, err := filesystem.Lookup(ctx, w, "seal-alias")
	if err != nil {
		t.Fatal(err)
	}
	other, err := filesystem.Lookup(ctx, w, "_CodeSignature/CodeResources")
	if err != nil || created != other {
		t.Fatal("lost alias", err)
	}
	node, err := w.Stat(ctx, created)
	if err != nil || node.Metadata.Mode.Value != 0100700 {
		t.Fatal(node, err)
	}
	if _, err := filesystem.Lookup(ctx, w, "empty"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("removed entry exported", err)
	}
	if got := invoke("xattr", "--session", "build", "-p", "org.test", "/seal-alias"); !bytes.Equal(got, payload) {
		t.Fatal("attribute bytes", got)
	}
	var out, diagnostics bytes.Buffer
	if err := run(ctx, []string{"workspace", "edit", "changes.json"}, nil, &out, &diagnostics); err == nil || out.Len() != 0 {
		t.Fatal("legacy JSON plan accepted", err)
	}
}

func TestSessionCommandFlagsAndDefaults(t *testing.T) {
	ctx := context.Background()
	scratch := t.TempDir()
	var out, diagnostics bytes.Buffer
	commands := [][]string{
		{"session", "create", "--filesystem", "apfs", "--time", "2026-01-01T00:00:00Z", "build"},
		{"mkdir", "--session", "build", "-pm755", "/a/b"},
		{"touch", "--session", "build", "/a/b/file"},
		{"chmod", "--session", "build", "--", "-w", "/a/b/file"},
	}
	for _, args := range commands {
		// Put common options before --, where all remaining words are operands.
		args = append(args[:1], append([]string{"--scratch-dir", scratch}, args[1:]...)...)
		if args[0] == "session" {
			args = []string{"session", "create", "--scratch-dir", scratch, "--filesystem", "apfs", "--time", "2026-01-01T00:00:00Z", "build"}
		}
		out.Reset()
		if err := run(ctx, args, nil, &out, &diagnostics); err != nil {
			t.Fatal(args, err)
		}
	}
	out.Reset()
	if err := run(ctx, []string{"stat", "--session", "build", "--scratch-dir", scratch, "--json", "/a/b/file"}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var node filesystem.Node
	if err := json.Unmarshal(out.Bytes(), &node); err != nil {
		t.Fatal(err)
	}
	if node.Metadata.Mode.Value != 0100444 || node.Metadata.UID.Value != 0 {
		t.Fatal(node)
	}
}

func TestPortableSessionNames(t *testing.T) {
	for _, name := range []string{"../build", "build.", "CON", "aux.data", "LPT1", "COM9.txt"} {
		if _, err := sessionDirectory(t.TempDir(), name); err == nil {
			t.Fatal("accepted nonportable session name", name)
		}
	}
	root := t.TempDir()
	a, err := sessionDirectory(root, "Build")
	if err != nil {
		t.Fatal(err)
	}
	b, err := sessionDirectory(root, "build")
	if err != nil || a != b {
		t.Fatal("host case policy changes session selection", a, b, err)
	}
}
