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
			t.Fatalf("%s: %v %s", image, err, out.String())
		}
	}
}

func TestPackImageAndRejectConstructionFlags(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "input.raw")
	raw := make([]byte, 8192)
	copy(raw[32:], "NXSB")
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	var out, diag bytes.Buffer
	args := []string{"pack", source, filepath.Join(root, "output.dmg"), "--format", "UDRO", "--json"}
	if err := run(context.Background(), args, nil, &out, &diag); err != nil {
		t.Fatal(err, diag.String())
	}
	if !bytes.Contains(out.Bytes(), []byte(`"diskSHA256"`)) {
		t.Fatal(out.String())
	}
	for _, option := range []string{"--filesystem=hfsplus", "--volume-name=Changed", "--capacity=16MiB", "--time=2025-06-07T08:09:10Z", "--volume-id=0000000000000000", "--uid=0", "--gid=0", "--scratch-dir=" + root} {
		destination := filepath.Join(root, "refused.dmg")
		if err := run(context.Background(), []string{"pack", option, source, destination}, nil, &out, &diag); err == nil {
			t.Fatal("accepted", option)
		}
		if _, err := os.Stat(destination); !os.IsNotExist(err) {
			t.Fatal("published refused output", err)
		}
	}
}
