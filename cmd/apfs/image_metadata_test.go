package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestExistingImageMetadataCommands(t *testing.T) {
	for _, kind := range []string{"apfs", "hfsplus"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			payload := filepath.Join(dir, "payload")
			if err := os.Mkdir(payload, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(payload, "file"), []byte("retained bytes"), 0644); err != nil {
				t.Fatal(err)
			}
			invoke := func(args ...string) string {
				t.Helper()
				var out, diag bytes.Buffer
				if err := run(ctx, args, nil, &out, &diag); err != nil {
					t.Fatal(args, err, diag.String())
				}
				return out.String()
			}
			source := filepath.Join(dir, "source.dmg")
			invoke("pack", "--filesystem", kind, "--time", "2025-06-07T08:09:10Z", payload, source)
			read := func(path string) filesystem.Node {
				t.Helper()
				r, close, err := (&readerOptions{partition: 0}).open(ctx, path, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer close()
				id, err := filesystem.Lookup(ctx, r, "/file")
				if err != nil {
					t.Fatal(err)
				}
				node, err := r.Stat(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				return node
			}
			original := read(source)
			steps := [][]string{{"chown", "0:20", "/file"}, {"xattr", "-w", "-x", "org.go-apfs.binary", "00ff01", "/file"}, {"chflags", "hidden,nodump", "/file"}, {"chflags", "nohidden", "/file"}, {"touch", "-a", "-d", "2023-11-14T22:13:21.234567891Z", "/file"}, {"touch", "-m", "-r", "/file", "/file"}, {"xattr", "-d", "org.go-apfs.binary", "/file"}}
			steps = append(steps, []string{"chflags", "uchg", "/file"}, []string{"chflags", "nouchg", "/file"}, []string{"xattr", "-w", filesystem.ResourceFork, "fork", "/file"}, []string{"xattr", "-w", filesystem.ResourceFork, "", "/file"})
			current := source
			for i, args := range steps {
				output := filepath.Join(t.TempDir(), "edited.dmg")
				args = append(args, "--image", current, "--output", output, "--time", "2025-06-07T08:09:10Z")
				invoke(args...)
				node := read(output)
				if (node.Identity.Volume != original.Identity.Volume || node.Identity.Object != original.Identity.Object) || node.Metadata.UID.Value != 0 || node.Metadata.GID.Value != 20 {
					t.Fatal("identity/ownership", node)
				}
				if invoke("cat", output, "/file") != "retained bytes" {
					t.Fatal("metadata edit changed contents")
				}
				if i == 1 {
					if invoke("xattr", "--image", output, "-p", "-x", "org.go-apfs.binary", "/file") != "00ff01" {
						t.Fatal("binary image attribute")
					}
				}
				if i == 4 {
					want := time.Unix(1700000001, 234567891)
					if kind == "hfsplus" {
						want = want.Truncate(time.Second)
					}
					if !node.Metadata.AccessTime.Value.Equal(want) || node.Metadata.ModifyTime != original.Metadata.ModifyTime || node.Metadata.BirthTime != original.Metadata.BirthTime {
						t.Fatal("atime-only changed other clocks", node.Metadata)
					}
				}
				if i == 7 && node.Metadata.BSDFlags.Value&2 == 0 || i == 8 && node.Metadata.BSDFlags.Value&2 != 0 {
					t.Fatal("user immutable flag did not survive reopening or clearing", node.Metadata)
				}
				if i == 10 {
					var value, diagnostics bytes.Buffer
					err := run(ctx, []string{"xattr", "--image", output, "-p", filesystem.ResourceFork, "/file"}, nil, &value, &diagnostics)
					if kind == "apfs" {
						if err != nil || value.Len() != 0 {
							t.Fatal("native APFS empty resource attribute must remain present", err)
						}
					} else if !errors.Is(err, fs.ErrNotExist) {
						t.Fatal("native HFS zero-length fork has no synthesized attribute", err)
					}
				}
				current = output
			}
			var out, diag bytes.Buffer
			if err := run(ctx, []string{"xattr", "--image", current, "-p", "org.go-apfs.binary", "/file"}, nil, &out, &diag); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("removed attribute remained", err)
			}
			for _, args := range [][]string{{"chown", "alice:staff", "/file"}, {"chflags", "compressed", "/file"}, {"xattr", "-w", "com.apple.decmpfs", "value", "/file"}, {"touch", "-d", "invalid", "/file"}, {"touch", "-d", "2025-01-01T00:00:00Z", "-r", "/file", "/file"}} {
				output := filepath.Join(t.TempDir(), "rejected.dmg")
				args = append(args, "--image", current, "--output", output)
				if err := run(ctx, args, nil, &out, &diag); err == nil {
					t.Fatal("unsafe metadata CLI admitted", args)
				}
				if _, err := os.Stat(output); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("rejected operation published output", err)
				}
			}
		})
	}
}
