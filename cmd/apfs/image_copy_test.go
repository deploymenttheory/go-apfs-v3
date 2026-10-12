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

func TestExistingImageCopyCommands(t *testing.T) {
	for _, kind := range []string{"apfs", "hfsplus", "hfsx"} {
		t.Run(kind, func(t *testing.T) {
			ctx, root := context.Background(), t.TempDir()
			payload := filepath.Join(root, "payload")
			if err := os.MkdirAll(filepath.Join(payload, "Sub", "Empty"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(payload, "Sub", "file"), []byte("copy contents"), 0640); err != nil {
				t.Fatal(err)
			}
			if err := os.Link(filepath.Join(payload, "Sub", "file"), filepath.Join(payload, "Sub", "alias")); err != nil {
				t.Fatal(err)
			}
			for _, name := range []string{"target", "plain"} {
				if err := os.WriteFile(filepath.Join(payload, name), []byte("old contents"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Link(filepath.Join(payload, "target"), filepath.Join(payload, "target-alias")); err != nil {
				t.Fatal(err)
			}
			invoke := func(args ...string) string {
				t.Helper()
				var out, diagnostics bytes.Buffer
				if err := run(ctx, args, nil, &out, &diagnostics); err != nil {
					t.Fatal(args, err, diagnostics.String())
				}
				return out.String()
			}
			current := filepath.Join(root, "source.dmg")
			invoke("pack", "--filesystem", kind, "--time", "2025-06-07T08:09:10Z", payload, current)
			edits := func(args ...string) {
				t.Helper()
				destination := filepath.Join(t.TempDir(), "output.dmg")
				args = append(args, "--image", current, "--output", destination, "--time", "2025-06-07T08:09:10Z")
				invoke(args...)
				current = destination
			}
			read := func(path string) filesystem.Node {
				t.Helper()
				r, close, err := (&readerOptions{}).open(ctx, current, nil)
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
			edits("ln", "-s", "absent", "/Sub/dangling")
			edits("xattr", "-w", "org.go-apfs.copy", "source attribute", "/Sub/file")
			edits("xattr", "-w", filesystem.ResourceFork, "source fork", "/Sub/file")
			edits("xattr", "-w", "org.go-apfs.old", "stale", "/target")
			edits("xattr", "-w", "org.go-apfs.old", "keep", "/plain")
			edits("touch", "-d", "2001-02-03T04:05:06Z", "/Sub/file")
			sourceID, targetID := read("/Sub/file").Identity, read("/target").Identity
			original := current
			input, err := os.ReadFile(original)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(input)
			edits("cp", "-a", "/Sub", "/Copied")
			file, alias := read("/Copied/file"), read("/Copied/alias")
			if file.Identity.Object == sourceID.Object || file.Identity.Object == alias.Identity.Object || file.Links.Value != 1 || alias.Links.Value != 1 {
				t.Fatal("ordinary archive copy must create independent files")
			}
			if file.Metadata.Mode.Value != 0100640 || file.Metadata.ModifyTime.Value.Year() != 2001 {
				t.Fatal("preserved metadata", file.Metadata)
			}
			if read("/Copied/dangling").Metadata.Mode.Value&0170000 != 0120000 || read("/Copied/Empty").Metadata.Mode.Value&0170000 != 0040000 {
				t.Fatal("recursive literal symlink/empty directory")
			}
			if invoke("xattr", "--image", current, "-p", filesystem.ResourceFork, "/Copied/file") != "source fork" {
				t.Fatal("independent resource fork lost")
			}
			edits("cp", "-a", "--preserve-links", "/Sub", "/Linked")
			if read("/Linked/file").Identity.Object != read("/Linked/alias").Identity.Object || read("/Linked/file").Identity.Object == sourceID.Object {
				t.Fatal("explicit copy link group must be independent of source")
			}
			edits("cp", "-p", "/Sub/file", "/target")
			if read("/target").Identity.Object != targetID.Object || read("/target-alias").Identity.Object != targetID.Object || read("/target").Identity.Volume != targetID.Volume || invoke("cat", current, "/target-alias") != "copy contents" {
				t.Fatal("overwrite must retain destination inode and aliases")
			}
			if bytes.Contains([]byte(invoke("xattr", "--image", current, "/target")), []byte("org.go-apfs.old")) {
				t.Fatal("stale destination attribute retained")
			}
			edits("cp", "-X", "/Sub/file", "/plain")
			if invoke("xattr", "--image", current, "-p", "org.go-apfs.old", "/plain") != "keep" {
				t.Fatal("-X must retain destination attributes")
			}
			edits("mkdir", "/Merged")
			edits("cp", "-R", "/Sub/", "/Merged")
			if invoke("cat", current, "/Merged/file") != "copy contents" {
				t.Fatal("source trailing slash must copy directory contents")
			}
			host := filepath.Join(root, "host-tree")
			if err = os.Mkdir(host, 0755); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(host, "café"), []byte("host import"), 0644); err != nil {
				t.Fatal(err)
			}
			edits("cp", "--from-host", "-RX", host, "/Imported")
			if invoke("cat", current, "/Imported/café") != "host import" {
				t.Fatal("recursive host directory import")
			}
			for _, args := range [][]string{{"cp", "-n", "/Sub/file", "/target"}, {"cp", "-R", "/Sub", "/Sub/child"}, {"cp", "/Sub/file", "/Sub/alias"}, {"cp", "/Sub", "/not-recursive"}, {"cp", "-a", "/Sub/", "/"}, {"cp", "-a", "--resource-fork", "--from-host", host, "/target"}} {
				destination := filepath.Join(t.TempDir(), "refused.dmg")
				args = append(args, "--image", current, "--output", destination)
				var out, diagnostics bytes.Buffer
				if err = run(ctx, args, nil, &out, &diagnostics); err == nil {
					t.Fatal("unsafe copy admitted", args)
				}
				if _, err = os.Stat(destination); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("refusal published output", err)
				}
			}
			after, err := os.ReadFile(original)
			if err != nil || sha256.Sum256(after) != digest {
				t.Fatal("copy changed source", err)
			}
		})
	}
}
