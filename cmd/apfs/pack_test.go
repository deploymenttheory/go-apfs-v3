package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestPackDirectoryAndSession(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "file"), []byte("contents"), 0644); err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(root, "scratch")
	commands := [][]string{
		{"pack", "--filesystem", "hfsplus", "--time", "2025-06-07T08:09:10Z", source, filepath.Join(root, "directory.dmg")},
		{"session", "create", "--scratch-dir", scratch, "--filesystem", "hfsx", "--time", "2025-06-07T08:09:10Z", "build"},
		{"cp", "--scratch-dir", scratch, "--session", "build", "--from-host", filepath.Join(source, "file"), "/file"},
		{"pack", "--scratch-dir", scratch, "--session", "build", "--format", "UDRO", "--time", "2025-06-07T08:09:10Z", filepath.Join(root, "session.dmg")},
	}
	for _, args := range commands {
		var out, diag bytes.Buffer
		if err := run(ctx, args, nil, &out, &diag); err != nil {
			t.Fatalf("%v: %v %s", args, err, diag.String())
		}
	}
	for _, image := range []string{"directory.dmg", "session.dmg"} {
		var out, diag bytes.Buffer
		if err := run(ctx, []string{"cat", filepath.Join(root, image), "/file"}, nil, &out, &diag); err != nil || out.String() != "contents" {
			t.Fatal(err, out.String())
		}
	}
}
