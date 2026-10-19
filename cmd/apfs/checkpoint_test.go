package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func fileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return sha256.Sum256(data)
}

// A Go-built container has one complete checkpoint. Interrupted Apple
// checkpoint windows belong to the acceptance tier; this exercises the public
// command path, its refusals and source evidence preservation.
func TestCheckpointCommandsPreserveEvidenceAndRequireExplicitNewOutput(t *testing.T) {
	source := builtImage(t, "apfs")
	before := fileDigest(t, source)
	ctx := context.Background()
	var out, diagnostics bytes.Buffer
	if err := run(ctx, []string{"checkpoint", "inspect", "--json", "--image", source}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var inspected struct {
		Schema     int
		Checkpoint apfs.CheckpointReport
	}
	if err := json.Unmarshal(out.Bytes(), &inspected); err != nil || inspected.Schema != 1 || inspected.Checkpoint.SelectedAddress == 0 || len(inspected.Checkpoint.Candidates) == 0 || diagnostics.Len() != 0 {
		t.Fatal(inspected, err)
	}
	for _, candidate := range inspected.Checkpoint.Candidates {
		if candidate.State != "valid" || candidate.Transaction > inspected.Checkpoint.SelectedTransaction {
			t.Fatal("built checkpoint reported as damaged", candidate)
		}
	}
	output := filepath.Join(t.TempDir(), "Recovered.dmg")
	out.Reset()
	if err := run(ctx, []string{"checkpoint", "recover", "--json", "--format", "UDRO", "--image", source, "--output", output}, nil, &out, &diagnostics); err != nil {
		t.Fatal(err)
	}
	var recovered struct {
		Schema int
		imageedit.Report
	}
	if err := json.Unmarshal(out.Bytes(), &recovered); err != nil || recovered.Schema != 1 || recovered.Checkpoint == nil || !recovered.Checkpoint.FilesystemValidated || recovered.Transaction != uint64(inspected.Checkpoint.SelectedTransaction) || len(recovered.Checkpoint.DiscardedDescriptors) != 0 {
		t.Fatal(recovered, err)
	}
	out.Reset()
	if err := run(ctx, []string{"cat", output, "/Fixture/example.txt"}, nil, &out, &diagnostics); err != nil || out.String() != fixtureText {
		t.Fatal("recovered file contents", out.String(), err)
	}
	hfs := builtImage(t, "hfsplus")
	refused := filepath.Join(t.TempDir(), "refused.dmg")
	for _, tc := range []struct {
		args []string
		want error
	}{
		{[]string{"checkpoint"}, nil}, {[]string{"checkpoint", "repair"}, nil},
		{[]string{"checkpoint", "recover", "--image", source}, fs.ErrInvalid},
		{[]string{"checkpoint", "inspect", "--image", source, "--output", output}, nil},
		{[]string{"checkpoint", "recover", "--image", source, "--output", output}, fs.ErrExist},
		{[]string{"checkpoint", "recover", "--image", source, "--output", source}, fs.ErrExist},
		{[]string{"checkpoint", "recover", "--image", hfs, "--output", refused}, filesystem.ErrUnsupported},
		{[]string{"checkpoint", "inspect", "--image", hfs}, filesystem.ErrCorrupt},
	} {
		out.Reset()
		err := run(ctx, tc.args, nil, &out, &diagnostics)
		if err == nil || (tc.want != nil && !errors.Is(err, tc.want)) || out.Len() != 0 {
			t.Fatal("invalid recovery command accepted", tc.args, err)
		}
	}
	if _, err := os.Lstat(refused); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("refused recovery published output", err)
	}
	if fileDigest(t, source) != before {
		t.Fatal("CLI modified original evidence")
	}
}
