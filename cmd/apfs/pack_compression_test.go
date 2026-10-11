package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestPackFileCompressionCLI(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	source := filepath.Join(root, "payload")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	data := bytes.Repeat([]byte("portable compressed application data\n"), 4000)
	if err := os.WriteFile(filepath.Join(source, "file"), data, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "empty"), nil, 0644); err != nil {
		t.Fatal(err)
	}
	scratch := filepath.Join(root, "scratch")
	invoke := func(args ...string) string {
		t.Helper()
		var out, diag bytes.Buffer
		if err := run(ctx, args, nil, &out, &diag); err != nil {
			t.Fatal(args, err, diag.String())
		}
		return out.String()
	}
	compressed := filepath.Join(root, "compressed.dmg")
	text := invoke("pack", "--filesystem", "apfs", "--file-compression", "zlib", "--scratch-dir", scratch, "--time", "2025-06-07T08:09:10Z", source, compressed)
	if !strings.Contains(text, "1 compressed") || !strings.Contains(text, "empty-file") {
		t.Fatal(text)
	}
	check := func(path string, active bool) {
		t.Helper()
		image, err := diskimage.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer image.Close()
		section, err := image.Partition(0)
		if err != nil {
			t.Fatal(err)
		}
		container, err := apfs.Open(section)
		if err != nil {
			t.Fatal(err)
		}
		id, err := filesystem.Lookup(ctx, &container.Volumes[0], "/file")
		if err != nil {
			t.Fatal(err)
		}
		n, err := container.Volumes[0].Stat(ctx, id)
		if err != nil || (n.Compression.State == filesystem.Present) != active {
			t.Fatal(n, err)
		}
		if got := invoke("cat", path, "/file"); got != string(data) {
			t.Fatal("CLI logical data mismatch")
		}
	}
	check(compressed, true)
	invoke("session", "open", "--scratch-dir", scratch, "--image", compressed, "build")
	decompressed := filepath.Join(root, "decompressed.dmg")
	text = invoke("pack", "--session", "build", "--scratch-dir", scratch, "--file-compression", "none", "--time", "2025-06-07T08:09:10Z", "--json", decompressed)
	var report struct {
		FileCompression string
		Compression     []struct{ Action string }
	}
	if err := json.Unmarshal([]byte(text), &report); err != nil || report.FileCompression != "none" || len(report.Compression) != 1 || report.Compression[0].Action != "decompressed" {
		t.Fatal(text, err)
	}
	check(decompressed, false)
	for _, args := range [][]string{
		{"pack", "--filesystem", "apfs", "--file-compression", "bogus", source},
		{"pack", "--file-compression", "zlib", compressed},
		{"pack", "--file-compression", "none", compressed},
		{"pack", "--file-compression", "preserve", compressed},
	} {
		var out, diag bytes.Buffer
		destination := filepath.Join(root, "refused.dmg")
		if err := run(ctx, append(args, destination), nil, &out, &diag); err == nil {
			t.Fatal("invalid policy accepted", args)
		}
		if _, err := os.Stat(destination); !os.IsNotExist(err) {
			t.Fatal("refused output published", err)
		}
	}
	text = invoke("pack", "--file-compression", "zlib", "--scratch-dir", scratch, "--volume", "Apps", "--directory", source, "--volume", "Empty", "--time", "2025-06-07T08:09:10Z", "--json", filepath.Join(root, "container.dmg"))
	if !strings.Contains(text, `"volume":"Apps"`) || !strings.Contains(text, `"fileCompression":"zlib"`) {
		t.Fatal(text)
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "apfs-file-compression-") || strings.HasPrefix(entry.Name(), "apfs-pack-session-") {
			t.Fatal("managed scratch leaked", entry.Name())
		}
	}
}
