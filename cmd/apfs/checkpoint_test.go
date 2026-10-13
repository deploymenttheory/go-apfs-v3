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

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

// Retained Apple source with deliberate newest-object checksum damage exercises
// the complete public command path. No native tools are run on the local host.
func TestCheckpointCommandsPreserveEvidenceAndMakeRollbackExplicit(t *testing.T) {
	archive, err := os.Open("../../acceptance/testdata/apfs-recovery/macos-27/apfs-bad-object-interrupted.raw.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()
	z, err := gzip.NewReader(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	source := filepath.Join(t.TempDir(), "Interrupted.raw")
	file, err := os.Create(source)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := io.Copy(file, io.LimitReader(z, (128<<20)+1)); err != nil || n != 128<<20 {
		file.Close()
		t.Fatal("bounded native evidence", n, err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	digest := func() []byte {
		t.Helper()
		file, err := os.Open(source)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		hash := sha256.New()
		if _, err = io.Copy(hash, file); err != nil {
			t.Fatal(err)
		}
		return hash.Sum(nil)
	}
	before := digest()
	ctx := context.Background()
	var out, diagnostics bytes.Buffer
	if err = run(ctx, []string{"cat", source, "/Fixture/retained"}, nil, &out, &diagnostics); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("ordinary reader silently rolled back", err)
	}
	out.Reset()
	if err = run(ctx, []string{"checkpoint", "inspect", "--json", "--image", source}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var inspected struct {
		Schema     int
		Checkpoint apfs.CheckpointReport
	}
	if err = json.Unmarshal(out.Bytes(), &inspected); err != nil || inspected.Schema != 1 || inspected.Checkpoint.Candidates[0].State != "invalid" || inspected.Checkpoint.SelectedTransaction >= inspected.Checkpoint.Candidates[0].Transaction {
		t.Fatal(inspected, err)
	}
	output := filepath.Join(t.TempDir(), "Recovered.dmg")
	out.Reset()
	if err = run(ctx, []string{"checkpoint", "recover", "--json", "--image", source, "--output", output}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var recovered struct {
		Schema int
		imageedit.Report
	}
	if err = json.Unmarshal(out.Bytes(), &recovered); err != nil || recovered.Schema != 1 || recovered.Checkpoint == nil || !recovered.Checkpoint.FilesystemValidated || recovered.Transaction != uint64(inspected.Checkpoint.SelectedTransaction) {
		t.Fatal(recovered, err)
	}
	out.Reset()
	if err = run(ctx, []string{"cat", output, "/Fixture/retained"}, nil, &out, &diagnostics); err != nil || out.String() != "Checkpoint recovery preserves identity.\n" {
		t.Fatal("recovered file contents", out.String(), err)
	}
	for _, args := range [][]string{
		{"checkpoint"}, {"checkpoint", "repair"}, {"checkpoint", "recover", "--image", source},
		{"checkpoint", "inspect", "--image", source, "--output", output},
		{"checkpoint", "recover", "--image", source, "--output", output},
		{"checkpoint", "recover", "--image", source, "--output", source},
	} {
		out.Reset()
		if err = run(ctx, args, nil, &out, &diagnostics); err == nil {
			t.Fatal("invalid recovery command accepted", args)
		}
	}
	if !bytes.Equal(digest(), before) {
		t.Fatal("CLI modified original evidence")
	}
}
