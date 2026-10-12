package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

// Exercise real retained Apple evidence through the public CLI dispatcher.
// Native tooling is never invoked here, including on the developer's Mac.
func TestJournalCommandsPreserveEvidenceAndRequireExplicitNewOutput(t *testing.T) {
	ctx := context.Background()
	archive, err := os.Open("../../acceptance/testdata/hfs-recovery/macos-27/hfsplus-linear-interrupted.raw.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	reader, err := gzip.NewReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	source := filepath.Join(t.TempDir(), "Interrupted.raw")
	file, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = io.Copy(file, io.LimitReader(reader, (64<<20)+1)); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	digest := func() [32]byte {
		t.Helper()
		data, err := os.ReadFile(source)
		if err != nil {
			t.Fatal(err)
		}
		return sha256.Sum256(data)
	}
	before := digest()
	var out, diagnostics bytes.Buffer
	if err = run(ctx, []string{"journal", "inspect", "--json", "--image", source}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var inspected struct {
		Schema  int
		Journal hfsplus.JournalInfo
	}
	if err = json.Unmarshal(out.Bytes(), &inspected); err != nil || inspected.Schema != 1 || !inspected.Journal.Pending {
		t.Fatal(inspected, err)
	}
	output := filepath.Join(t.TempDir(), "Recovered.dmg")
	out.Reset()
	if err = run(ctx, []string{"journal", "replay", "--json", "--format", "UDRO", "--image", source, "--output", output}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var report struct {
		Schema int
		imageedit.Report
	}
	if err = json.Unmarshal(out.Bytes(), &report); err != nil || report.Schema != 1 || report.Journal == nil || report.Journal.Sectors == 0 {
		t.Fatal(report, err)
	}
	for _, args := range [][]string{
		{"journal"}, {"journal", "reset"}, {"journal", "replay", "--image", source},
		{"journal", "inspect", "--image", source, "--output", output},
		{"journal", "replay", "--session", "build", "--image", source, "--output", output},
		{"journal", "replay", "--image", source, "--output", output},
		{"journal", "replay", "--image", source, "--output", source},
	} {
		out.Reset()
		if err = run(ctx, args, nil, &out, &diagnostics); err == nil {
			t.Fatal("invalid journal command accepted", args)
		}
	}
	if err = run(ctx, []string{"cat", source, "/Fixture/retained"}, nil, &out, &diagnostics); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal("reader implicitly recovered source", err)
	}
	if digest() != before {
		t.Fatal("journal CLI changed source evidence")
	}
}
