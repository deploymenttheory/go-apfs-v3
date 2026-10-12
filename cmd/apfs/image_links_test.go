package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestExistingImageLinkCommands(t *testing.T) {
	for _, kind := range []string{"apfs", "hfsplus", "hfsx"} {
		t.Run(kind, func(t *testing.T) {
			ctx := context.Background()
			dir := t.TempDir()
			payload := filepath.Join(dir, "payload")
			if err := os.Mkdir(payload, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(payload, "file"), []byte("shared contents"), 0644); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(payload, "file"), filepath.Join(payload, "alias")); err != nil {
				t.Fatal(err)
			}
			invoke := func(args ...string) {
				t.Helper()
				var out, diag bytes.Buffer
				if err := run(ctx, args, nil, &out, &diag); err != nil {
					t.Fatal(args, err, diag.String())
				}
			}
			source := filepath.Join(dir, "source.dmg")
			invoke("pack", "--filesystem", kind, "--time", "2025-06-07T08:09:10Z", payload, source)
			input, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(input)
			read := func(image, path string) filesystem.Node {
				t.Helper()
				r, close, err := (&readerOptions{}).open(ctx, image, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer close()
				id, err := filesystem.Lookup(ctx, r, path)
				if err != nil {
					t.Fatal(err)
				}
				node, err := r.Stat(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				return node
			}
			original := read(source, "/file")
			current := source
			edit := func(args ...string) {
				t.Helper()
				out := filepath.Join(t.TempDir(), "edited.dmg")
				args = append(args, "--image", current, "--output", out, "--time", "2025-06-07T08:09:10Z")
				invoke(args...)
				current = out
			}
			edit("mkdir", "/nested")
			edit("mv", "/file", "/nested/file")
			edit("ln", "/nested/file", "/")
			edit("rm", "/nested/file")
			edit("ln", "/file", "/third")
			edit("ln", "-f", "/file", "/third") // Different aliases of one inode may be replaced.
			for _, path := range []string{"/file", "/alias", "/third"} {
				n := read(current, path)
				if n.Identity.Volume != original.Identity.Volume || n.Identity.Object != original.Identity.Object || n.Links.Value != 3 {
					t.Fatal("hard-link identity/count", path, n)
				}
			}
			edit("ln", "-s", "absent/path", "/symbol")
			if n := read(current, "/symbol"); n.Metadata.Mode.Value != 0120755 {
				t.Fatal("literal dangling link", n)
			}
			r, close, err := (&readerOptions{}).open(ctx, current, nil)
			if err != nil {
				t.Fatal(err)
			}
			id, err := filesystem.Lookup(ctx, r, "/symbol")
			if err != nil {
				t.Fatal(err)
			}
			target, err := r.Readlink(ctx, id)
			close()
			if err != nil || target != "absent/path" {
				t.Fatal("literal symlink target", target, err)
			}
			out := filepath.Join(t.TempDir(), "rejected.dmg")
			var stdout, diagnostics bytes.Buffer
			if err := run(ctx, []string{"ln", "-f", "--image", current, "--output", out, "/file", "/symbol"}, nil, &stdout, &diagnostics); !errors.Is(err, filesystem.ErrUnsupported) {
				t.Fatal("destination symlink needs explicit -h", err)
			}
			if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("refusal published output", err)
			}
			edit("ln", "-h", "-f", "/file", "/symbol")
			if n := read(current, "/symbol"); n.Identity.Volume != original.Identity.Volume || n.Identity.Object != original.Identity.Object || n.Links.Value != 4 {
				t.Fatal("explicit replacement of a symlink", n)
			}
			edit("rm", "/file")
			if n := read(current, "/alias"); n.Identity.Volume != original.Identity.Volume || n.Identity.Object != original.Identity.Object || n.Links.Value != 3 {
				t.Fatal("removal lost shared inode", n)
			}
			var contents bytes.Buffer
			if err := run(ctx, []string{"cat", current, "/alias"}, nil, &contents, &diagnostics); err != nil || contents.String() != "shared contents" {
				t.Fatal("shared data lost", err)
			}
			edit("rm", "/alias", "/third", "/symbol")
			for _, path := range []string{"/file", "/alias", "/third", "/symbol"} {
				r, close, err := (&readerOptions{}).open(ctx, current, nil)
				if err != nil {
					t.Fatal(err)
				}
				_, err = filesystem.Lookup(ctx, r, path)
				close()
				if !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("final link remains", path, err)
				}
			}
			input, err = os.ReadFile(source)
			if err != nil || sha256.Sum256(input) != digest {
				t.Fatal("CLI changed source image", err)
			}
		})
	}
}
