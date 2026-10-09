package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

func TestInspectJSONHasNoDiagnosticNoise(t *testing.T) {
	var out, diagnostics bytes.Buffer
	path := filepath.Join("..", "..", "acceptance", "testdata", "native", "macos-27", "apfs.dmg")
	if err := run(context.Background(), []string{"inspect", "--json", path}, &out, &diagnostics); err != nil {
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

func TestCatIsByteExactAndDoesNotFollowSymlinks(t *testing.T) {
	for _, name := range []string{"apfs", "hfsplus"} {
		t.Run(name, func(t *testing.T) {
			image := filepath.Join("..", "..", "acceptance", "testdata", "files", "macos-27", name+".dmg")
			var out, diagnostics bytes.Buffer
			if err := run(context.Background(), []string{"cat", image, "Fixture/example.txt"}, &out, &diagnostics); err != nil {
				t.Fatal(err)
			}
			if out.String() != "Native Apple filesystem fixture.\n" || diagnostics.Len() != 0 {
				t.Fatal("file stream was altered", out.String(), diagnostics.String())
			}
			out.Reset()
			if err := run(context.Background(), []string{"cat", image, "Fixture/link"}, &out, &diagnostics); !errors.Is(err, fs.ErrInvalid) {
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
	if err := run(context.Background(), []string{"pack", "source", "output.dmg"}, &out, &diagnostics); !errors.Is(err, filesystem.ErrUnsupported) {
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
	if err := run(ctx, []string{"inspect", path}, &out, &diagnostics); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if out.Len() != 0 {
		t.Fatal("canceled command produced a report")
	}
}
