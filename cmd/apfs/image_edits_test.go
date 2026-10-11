package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Exercise the ordinary input/output flags through the public CLI dispatcher,
// including native case lookup, symbolic modes, independent forks and errors.
func TestExistingImageFileCommands(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	payload := filepath.Join(root, "payload")
	if e := os.Mkdir(payload, 0700); e != nil {
		t.Fatal(e)
	}
	host := filepath.Join(payload, "file")
	if e := os.WriteFile(host, []byte("before"), 0644); e != nil {
		t.Fatal(e)
	}
	invoke := func(args ...string) string {
		t.Helper()
		var out, diag bytes.Buffer
		if e := run(ctx, args, nil, &out, &diag); e != nil {
			t.Fatal(args, e, diag.String())
		}
		return out.String()
	}
	source := filepath.Join(root, "source.dmg")
	invoke("pack", "--filesystem", "hfsplus", "--time", "2025-06-07T08:09:10Z", payload, source)
	if e := os.WriteFile(host, []byte("replacement"), 0600); e != nil {
		t.Fatal(e)
	}
	data := filepath.Join(root, "data.dmg")
	invoke("cp", "--image", source, "--output", data, "--time", "2025-06-07T08:09:10Z", "--from-host", host, "/FILE")
	if got := invoke("cat", data, "/file"); got != "replacement" {
		t.Fatal(got)
	}
	mode := filepath.Join(root, "mode.dmg")
	invoke("chmod", "--image", data, "--output", mode, "--time", "2025-06-07T08:09:10Z", "u=rwx,go=rx", "/file")
	fork := filepath.Join(root, "fork.dmg")
	invoke("cp", "--image", mode, "--output", fork, "--from-host", "--resource-fork", host, "/file")
	if got := invoke("cat", fork, "/file"); got != "replacement" {
		t.Fatal("fork replacement changed data")
	}
	for _, args := range [][]string{{"cp", "--from-host", "-a", host, "/file"}, {"cp", host, "/file"}, {"chmod", "-R", "0755", "/file"}, {"chmod", "--session", "conflict", "0755", "/file"}, {"chmod", "0755", "/absent"}, {"chmod", "--time", "invalid", "0755", "/file"}} {
		var out, diag bytes.Buffer
		destination := filepath.Join(t.TempDir(), "failed.dmg")
		args = append(args, "--image", source, "--output", destination)
		if e := run(ctx, args, nil, &out, &diag); e == nil {
			t.Fatal("unsupported image command admitted", args)
		}
		if _, e := os.Stat(destination); !os.IsNotExist(e) {
			t.Fatal("failed image command published", e)
		}
	}
	var out, diag bytes.Buffer
	if e := run(ctx, []string{"chmod", "--image", source, "--output", source, "0600", "/file"}, nil, &out, &diag); !os.IsExist(e) {
		t.Fatal("source overwrite admitted", e)
	}
}
