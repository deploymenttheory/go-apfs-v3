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

func TestInspectJSONHasNoDiagnosticNoise(t *testing.T) {
	var out, diagnostics bytes.Buffer
	path := filepath.Join("..", "..", "acceptance", "testdata", "native", "macos-27", "apfs.dmg")
	if err := run(context.Background(), []string{"inspect", "--json", path}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var r inspect.Report
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		t.Fatal(err)
	}
	if r.Schema != 1 || diagnostics.Len() != 0 {
		t.Fatal("unexpected report schema or diagnostics", out.String(), diagnostics.String())
	}
}

func TestEncryptedCatUsesExactPasswordBytesWithoutDiagnosticLeaks(t *testing.T) {
	image := filepath.Join("..", "..", "acceptance", "testdata", "encryption", "macos-27", "apfs.dmg")
	const password = "apfs-v3-public-fixture"
	path := filepath.Join(t.TempDir(), "password")
	if err := os.WriteFile(path, []byte(password), 0600); err != nil {
		t.Fatal(err)
	}
	for _, source := range []string{path, "-"} {
		var out, diagnostics bytes.Buffer
		if err := run(context.Background(), []string{"cat", "--password-file", source, image, "Fixture/example.txt"}, strings.NewReader(password), &out, &diagnostics); err != nil {
			t.Fatal(err)
		}
		if out.String() != "Native Apple filesystem fixture.\n" || diagnostics.Len() != 0 {
			t.Fatal("encrypted cat changed data or emitted diagnostics")
		}
	}
	for _, secret := range []string{password + "\n", "wrong-private-input", ""} {
		var out, diagnostics bytes.Buffer
		err := run(context.Background(), []string{"cat", "--password-file", "-", image, "Fixture/example.txt"}, strings.NewReader(secret), &out, &diagnostics)
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
	var out, diagnostics bytes.Buffer
	if err := run(context.Background(), []string{"cat", image, "Fixture/example.txt"}, nil, &out, &diagnostics); !errors.Is(err, filesystem.ErrAuthentication) || out.Len() != 0 {
		t.Fatal("missing credential unlocked volume", err)
	}
}

func TestEncryptedImageAndVolumeCredentialsAreIndependent(t *testing.T) {
	root := filepath.Join("..", "..", "acceptance", "testdata", "encrypted-dmg", "macos-27")
	const imagePassword = "public-dmg-password"
	var out, diagnostics bytes.Buffer
	image := filepath.Join(root, "hfsplus-aes128.dmg")
	if err := run(context.Background(), []string{"cat", "--image-password-file", "-", image, "Fixture/example.txt"}, strings.NewReader(imagePassword), &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if out.String() != "Native Apple filesystem fixture.\n" || diagnostics.Len() != 0 {
		t.Fatal("encrypted image cat output")
	}
	out.Reset()
	if err := run(context.Background(), []string{"inspect", "--json", "--image-password-file", "-", image}, strings.NewReader(imagePassword), &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var report inspect.Report
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Encryption == nil || report.Encryption.KeyBits != 128 {
		t.Fatal("missing image encryption report")
	}
	image = filepath.Join(root, "apfs-nested-aes256.dmg")
	out.Reset()
	if err := run(context.Background(), []string{"cat", "--image-password-file", "-", image, "Fixture/example.txt"}, strings.NewReader(imagePassword), &out, &diagnostics); !errors.Is(err, filesystem.ErrAuthentication) || out.Len() != 0 {
		t.Fatal("image password unlocked APFS", err)
	}
	volumeFile := filepath.Join(t.TempDir(), "volume-password")
	if err := os.WriteFile(volumeFile, []byte("apfs-v3-public-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(context.Background(), []string{"cat", "--image-password-file", "-", "--password-file", volumeFile, image, "Fixture/example.txt"}, strings.NewReader(imagePassword), &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	if out.String() != "Native Apple filesystem fixture.\n" || diagnostics.Len() != 0 {
		t.Fatal("nested encrypted cat output")
	}
	out.Reset()
	secret := "incorrect-private-image-password"
	err := run(context.Background(), []string{"cat", "--image-password-file", "-", image, "Fixture/example.txt"}, strings.NewReader(secret), &out, &diagnostics)
	if !errors.Is(err, filesystem.ErrAuthentication) || out.Len() != 0 || diagnostics.Len() != 0 || strings.Contains(err.Error(), secret) {
		t.Fatal("bad image credential handling", err)
	}
	if err := run(context.Background(), []string{"cat", "--image-password-file", "-", "--password-file", "-", image, "Fixture/example.txt"}, strings.NewReader(""), &out, &diagnostics); err == nil || !strings.Contains(err.Error(), "both consume stdin") {
		t.Fatal("ambiguous credential input", err)
	}
}

func TestCatIsByteExactAndDoesNotFollowSymlinks(t *testing.T) {
	for _, name := range []string{"apfs", "hfsplus"} {
		t.Run(name, func(t *testing.T) {
			image := filepath.Join("..", "..", "acceptance", "testdata", "files", "macos-27", name+".dmg")
			var out, diagnostics bytes.Buffer
			if err := run(context.Background(), []string{"cat", image, "Fixture/example.txt"}, nil, &out, &diagnostics); err != nil {
				t.Fatal(err)
			}
			if out.String() != "Native Apple filesystem fixture.\n" || diagnostics.Len() != 0 {
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
	if err := run(context.Background(), []string{"pack", "source", "output.dmg"}, nil, &out, &diagnostics); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatal("unsupported command produced success output")
	}
}

func TestCancelledInspectionReturnsNoReport(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, diagnostics bytes.Buffer
	path := filepath.Join("..", "..", "acceptance", "testdata", "native", "macos-27", "hfsplus.dmg")
	if err := run(ctx, []string{"inspect", path}, nil, &out, &diagnostics); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatal("canceled command produced a report")
	}
}

func TestSnapshotSelectionNeverFallsBackToLiveFiles(t *testing.T) {
	image := filepath.Join("..", "..", "acceptance", "testdata", "files", "macos-27", "apfs.dmg")
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
	hfs := filepath.Join("..", "..", "acceptance", "testdata", "files", "macos-27", "hfsplus.dmg")
	if err := run(context.Background(), []string{"snapshot", "list", hfs}, nil, &out, &diagnostics); !errors.Is(err, filesystem.ErrUnsupported) || out.Len() != 0 {
		t.Fatal("HFS snapshot inventory", err)
	}
}

func TestExtractAndVerifyPreservationReport(t *testing.T) {
	image := filepath.Join("..", "..", "acceptance", "testdata", "preservation", "macos-27", "apfs.dmg")
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

func TestWorkspaceReplaceProducesSeparateVerifiedOutput(t *testing.T) {
	ctx := context.Background()
	image := filepath.Join("..", "..", "acceptance", "testdata", "replacement", "macos-27", "apfs.dmg")
	parent := t.TempDir()
	baseline := filepath.Join(parent, "before")
	destination := filepath.Join(parent, "after")
	contents := filepath.Join(parent, "contents")
	payload := []byte("CLI supplied content\x00\xff")
	if err := os.WriteFile(contents, payload, 0600); err != nil {
		t.Fatal(err)
	}
	var out, diagnostics bytes.Buffer
	if err := run(ctx, []string{"extract", image, "Fixture", baseline}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run(ctx, []string{"workspace", "replace", "--json", baseline, "alias", contents, destination}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var report struct{ Schema, ModifiedFiles int }
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Schema != 1 || report.ModifiedFiles != 1 || diagnostics.Len() != 0 {
		t.Fatal("replacement report", out.String())
	}
	for _, name := range []string{"alias", "ordinary", filepath.Join("links", "second")} {
		data, err := os.ReadFile(filepath.Join(destination, "files", name))
		if err != nil || !bytes.Equal(data, payload) {
			t.Fatal("CLI alias replacement", name, err)
		}
	}
	out.Reset()
	if err := run(ctx, []string{"workspace", "verify", baseline}, nil, &out, &diagnostics); err != nil {
		t.Fatal("source workspace changed", err)
	}
	out.Reset()
	if err := run(ctx, []string{"workspace", "replace", baseline, "link", contents, filepath.Join(parent, "bad")}, nil, &out, &diagnostics); !errors.Is(err, fs.ErrInvalid) || out.Len() != 0 {
		t.Fatal("replacement followed symlink", err)
	}
}

func TestWorkspaceEditPlanCreatesAndReplacesInOneOutput(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	baseline := filepath.Join(parent, "before")
	destination := filepath.Join(parent, "after")
	image := filepath.Join("..", "..", "acceptance", "testdata", "replacement", "macos-27", "apfs.dmg")
	var out, diagnostics bytes.Buffer
	if err := run(ctx, []string{"extract", image, "Fixture", baseline}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	w, err := workspace.Open(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	id, err := filesystem.Lookup(ctx, w, "alias")
	if err != nil {
		t.Fatal(err)
	}
	n, err := w.Stat(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	directory := n.Metadata
	directory.Mode = filesystem.Observed(uint32(0040755))
	directory.BSDFlags = filesystem.Observed(uint32(0))
	payload := []byte("explicit edit input")
	if err := os.WriteFile(filepath.Join(parent, "payload"), payload, 0600); err != nil {
		t.Fatal(err)
	}
	plan := map[string]any{"schema": 1, "changes": []map[string]any{
		{"op": "mkdir", "path": "_CodeSignature", "metadata": directory},
		{"op": "create", "path": "_CodeSignature/CodeResources", "contents": "payload", "metadata": n.Metadata, "attributes": []map[string]string{{"name": "org.test", "contents": "payload"}}},
		{"op": "link", "path": "_CodeSignature/CodeResources", "to": "seal-alias"},
		{"op": "replace", "path": "alias", "contents": "payload"},
		{"op": "remove", "path": "empty"},
		{"op": "metadata", "path": "seal-alias", "metadata": filesystem.Metadata{Mode: filesystem.Observed(uint32(0100700))}},
		{"op": "setxattr", "path": "seal-alias", "attribute": "org.test", "attributeMode": "replace", "contents": "payload"},
		{"op": "resource-fork", "path": "seal-alias", "contents": "payload"},
		{"op": "removexattr", "path": "alias", "attribute": "org.go-apfs.keep"},
	}}
	encoded, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	planFile := filepath.Join(parent, "changes.json")
	if err := os.WriteFile(planFile, encoded, 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run(ctx, []string{"workspace", "edit", "--json", baseline, planFile, destination}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var report struct{ Schema, CreatedObjects, ModifiedFiles, MetadataObjects, AttributeObjects int }
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Schema != 1 || report.CreatedObjects != 2 || report.ModifiedFiles != 2 || report.MetadataObjects != 1 || report.AttributeObjects != 2 {
		t.Fatal("edit report", out.String())
	}
	result, err := workspace.Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	created, err := filesystem.Lookup(ctx, result, "_CodeSignature/CodeResources")
	if err != nil {
		t.Fatal(err)
	}
	alias, err := filesystem.Lookup(ctx, result, "seal-alias")
	if err != nil || created != alias {
		t.Fatal("plan link", err)
	}
	if _, err := result.OpenAttribute(ctx, id, "org.go-apfs.keep"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("plan attribute removal", err)
	}
	node, err := result.Stat(ctx, created)
	if err != nil || node.Metadata.Mode.Value != 0100700 {
		t.Fatal("plan metadata", err)
	}
	value, err := result.OpenAttribute(ctx, created, "org.test")
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, len(payload))
	_, err = value.ReadAt(b, 0)
	value.Close()
	if err != nil || !bytes.Equal(b, payload) {
		t.Fatal("plan attribute input", err)
	}
	if err := os.WriteFile(planFile, []byte(`{"schema":1,"changes":[],"unexpected":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run(ctx, []string{"workspace", "edit", baseline, planFile, filepath.Join(parent, "invalid")}, nil, &out, &diagnostics); err == nil || out.Len() != 0 {
		t.Fatal("unknown plan field accepted", err)
	}
}
