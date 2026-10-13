package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestOrderedImageCommandsPublishOnce(t *testing.T) {
	for _, kind := range []string{"apfs", "hfsplus", "hfsx"} {
		t.Run(kind, func(t *testing.T) {
			ctx, root := context.Background(), t.TempDir()
			payload := filepath.Join(root, "payload")
			if err := os.Mkdir(payload, 0755); err != nil {
				t.Fatal(err)
			}
			host := filepath.Join(root, "host")
			if err := os.WriteFile(host, []byte("batch payload"), 0600); err != nil {
				t.Fatal(err)
			}
			invoke := func(args ...string) (string, error) {
				var output, diagnostics bytes.Buffer
				err := run(ctx, args, nil, &output, &diagnostics)
				return output.String(), err
			}
			source, destination := filepath.Join(root, "source.dmg"), filepath.Join(root, "edited.dmg")
			if _, err := invoke("pack", "--filesystem", kind, "--time", "2025-06-07T08:09:10Z", payload, source); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"edit", "--image", source, "--output", destination, "--time", "2025-06-07T08:09:10Z", "--",
				"mkdir", "/Bundle", "--next", "cp", "--from-host", host, "/Bundle/file", "--next", "chmod", "0755", "/Bundle/file",
				"--next", "ln", "/Bundle/file", "/Bundle/alias", "--next", "mv", "/Bundle/file", "/Bundle/renamed",
				"--next", "xattr", "-w", "org.go-apfs.batch", "retained", "/Bundle/alias"}
			output, err := invoke(args...)
			if err != nil || !strings.Contains(output, "Applied 6 command(s)") || strings.Count(output, "published") != 1 {
				t.Fatal("ordered command result", output, err)
			}
			if output, err := invoke("cat", destination, "/Bundle/renamed"); err != nil || output != "batch payload" {
				t.Fatal("later commands did not address copied contents", output, err)
			}
			r, close, err := (&readerOptions{}).open(ctx, destination, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer close()
			alias, err := filesystem.Lookup(ctx, r, "/Bundle/alias")
			if err != nil {
				t.Fatal(err)
			}
			renamed, err := filesystem.Lookup(ctx, r, "/Bundle/renamed")
			if err != nil || alias != renamed {
				t.Fatal("batch separated aliases", err)
			}
			node, err := r.Stat(ctx, alias)
			if err != nil || node.Metadata.Mode.Value&07777 != 0755 {
				t.Fatal("ordered permissions", node, err)
			}
			after, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("batch changed original image", err)
			}
			failed := filepath.Join(root, "failed.dmg")
			_, err = invoke("edit", "--image", source, "--output", failed, "--", "mkdir", "/first", "--next", "chmod", "0700", "/absent")
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("later command failure lost", err)
			}
			if _, err := os.Stat(failed); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("failed batch published intermediate state", err)
			}
		})
	}
}
