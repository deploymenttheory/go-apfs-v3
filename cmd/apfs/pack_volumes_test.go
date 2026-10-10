package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestPackVolumesFromSessionDirectoryAndEmpty(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	scratch := filepath.Join(root, "scratch")
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "Name"), []byte("directory"), 0600); err != nil {
		t.Fatal(err)
	}
	runOK := func(args ...string) []byte {
		t.Helper()
		var out, diag bytes.Buffer
		if err := run(ctx, args, nil, &out, &diag); err != nil {
			t.Fatalf("%v: %v %s", args, err, diag.String())
		}
		return out.Bytes()
	}
	runOK("session", "create", "--scratch-dir", scratch, "--filesystem", "apfs", "--time", "2025-06-07T08:09:10Z", "input")
	runOK("cp", "--scratch-dir", scratch, "--session", "input", "--from-host", filepath.Join(source, "Name"), "/Name")
	destination := filepath.Join(root, "multiple.dmg")
	args := []string{"pack", "--scratch-dir", scratch, "--time", "2025-06-07T08:09:10Z", "--json",
		"--volume", "System", "--session", "input", "--role", "system", "--group-with", "Data",
		"--volume", "Data", "--session", "input", "--role", "data", "--reserve", "16MiB", "--quota", "32MiB",
		"--volume", "Imported", "--directory", source, "--case-sensitive", "--uid", "42",
		"--volume", "Empty", destination}
	var report struct {
		Schema, VolumeCount int
		Volumes             []struct{ Name string }
	}
	if err := json.Unmarshal(runOK(args...), &report); err != nil {
		t.Fatal(err)
	}
	if report.Schema != 1 || report.VolumeCount != 4 || len(report.Volumes) != 4 {
		t.Fatal("construction report", report)
	}
	image, err := diskimage.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	part, err := image.Partition(0)
	if err != nil {
		t.Fatal(err)
	}
	c, err := apfs.Open(part)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Volumes) != 4 || c.Volumes[0].VolumeGroup != c.Volumes[1].VolumeGroup || c.Volumes[0].VolumeGroup == "00000000-0000-0000-0000-000000000000" {
		t.Fatal("derived group identity")
	}
	ids := map[string]bool{c.UUID: true}
	for i, v := range c.Volumes {
		if ids[v.UUID] || v.Name != report.Volumes[i].Name {
			t.Fatal("independent volume identity")
		}
		ids[v.UUID] = true
	}
	if c.Volumes[1].ReserveBlocks*4096 != 16<<20 || c.Volumes[1].QuotaBlocks*4096 != 32<<20 {
		t.Fatal("space limits")
	}
	if _, err = filesystem.Lookup(ctx, &c.Volumes[0], "name"); err != nil {
		t.Fatal("insensitive session", err)
	}
	if _, err = filesystem.Lookup(ctx, &c.Volumes[2], "name"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("sensitive import", err)
	}
	if err = c.Volumes[3].ReadDir(ctx, c.Volumes[3].Root(), func(filesystem.DirEntry) error { t.Fatal("nonempty volume"); return nil }); err != nil {
		t.Fatal(err)
	}
	// Both volume clauses borrowed the same session without reopening its lock.
	if string(runOK("cat", "--scratch-dir", scratch, "--session", "input", "/Name")) != "directory" {
		t.Fatal("source session changed")
	}
	entries, err := os.ReadDir(scratch)
	if err != nil || len(entries) != 1 {
		t.Fatal("temporary imports leaked", entries, err)
	}
}

func TestPackVolumesRefusesAmbiguousOrInvalidOptions(t *testing.T) {
	root := t.TempDir()
	for _, args := range [][]string{
		{"--session", "input", "--volume", "Late"},
		{"--volume", "Duplicate", "--volume", "Duplicate"},
		{"--volume", "A", "--session", "one", "--directory", "two"},
		{"--volume", "A", "--group-with", "Absent"},
		{"--volume", "A", "--group-uuid", "11111111-2222-5333-8444-555555555555"},
		{"--volume", "A", "--role", "recovery"},
		{"--volume", "A", "--session", "input", "--case-sensitive"},
		{"--volume", "A", "--session", "input", "--uid", "0"},
		{"--volume", "A", "--reserve", "32MiB", "--quota", "16MiB"},
		{"--volume", "A", "--volume", "B", "--capacity", "512MiB"},
		{"--volume", "A", "--filesystem", "hfsplus"},
	} {
		destination := filepath.Join(root, "refused.dmg")
		var out, diag bytes.Buffer
		command := append([]string{"pack", "--scratch-dir", root}, args...)
		command = append(command, destination)
		if err := run(context.Background(), command, nil, &out, &diag); err == nil {
			t.Fatal("accepted", args)
		}
		if _, err := os.Lstat(destination); !os.IsNotExist(err) {
			t.Fatal("published invalid build", err)
		}
	}
	if entries, _ := os.ReadDir(root); len(entries) != 0 {
		t.Fatal("failed imports leaked", entries)
	}
}

func TestPackVolumeFlagIsNotAnOptionValue(t *testing.T) {
	for _, args := range [][]string{{"--volume-name", "--volume", "source", "out"}, {"--", "--volume", "out"}, {"--directory=--volume", "out"}} {
		if packHasVolumes(args) {
			t.Fatal("mistook an operand or option value for a volume clause", args)
		}
	}
}
