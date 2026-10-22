package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func TestCloneCopyCLIReportsImageAndOrderedEditStorageChoice(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"apfs", "hfsplus"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			payload := filepath.Join(root, "payload")
			if err := os.Mkdir(payload, 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(payload, "file"), []byte("clone copy source"), 0640); err != nil {
				t.Fatal(err)
			}
			invoke := func(args ...string) (string, string) {
				t.Helper()
				var out, diag bytes.Buffer
				if err := run(ctx, args, nil, &out, &diag); err != nil {
					t.Fatal(args, err, diag.String())
				}
				return out.String(), diag.String()
			}
			source := filepath.Join(root, "source.dmg")
			invoke("pack", "--filesystem", kind, "--time", "2025-06-07T08:09:10Z", payload, source)
			for _, ordered := range []bool{false, true} {
				output := filepath.Join(t.TempDir(), "cloned.dmg")
				args := []string{"cp", "-c", "--image", source, "--output", output, "--time", "2025-06-07T08:09:10Z", "--json", "/file", "/clone"}
				if ordered {
					args = []string{"edit", "--image", source, "--output", output, "--time", "2025-06-07T08:09:10Z", "--json", "--", "cp", "-c", "/file", "/clone"}
				}
				out, diagnostics := invoke(args...)
				var report imageedit.CopyReport
				if err := json.Unmarshal([]byte(out), &report); err != nil {
					t.Fatal(out, err)
				}
				if len(report.Clones) != 1 || report.Clones[0].Cloned != (kind == "apfs") || strings.Contains(diagnostics, "Cloned ") {
					t.Fatal("missing/incorrect machine-readable clone choice", out, diagnostics)
				}
			}
		})
	}
}
