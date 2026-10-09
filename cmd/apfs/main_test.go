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
