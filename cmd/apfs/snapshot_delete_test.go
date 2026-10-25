package main

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestSnapshotDeleteCLIRequiresOneExplicitIdentityAndPublishesNothingOnFailure(t *testing.T) {
	source := builtImage(t, "apfs")
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		flags []string
		want  error
	}{
		{"no identity", nil, fs.ErrInvalid},
		{"empty name", []string{"--snapshot-name", ""}, fs.ErrInvalid},
		{"zero xid", []string{"--snapshot-xid", "0"}, fs.ErrInvalid},
		{"two identities", []string{"--snapshot-name", "absent", "--snapshot-xid", "1"}, fs.ErrInvalid},
		{"empty name with xid", []string{"--snapshot-name", "", "--snapshot-xid", "1"}, fs.ErrInvalid},
		{"name with zero xid", []string{"--snapshot-name", "absent", "--snapshot-xid", "0"}, fs.ErrInvalid},
		{"missing name", []string{"--snapshot-name", "absent"}, fs.ErrNotExist},
		{"missing xid", []string{"--snapshot-xid", "1"}, fs.ErrNotExist},
		{"fractional operation time", []string{"--snapshot-name", "absent", "--time", "2026-10-10T00:00:00.5Z"}, fs.ErrInvalid},
		{"negative partition", []string{"--snapshot-name", "absent", "--partition", "-1"}, fs.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "deleted.dmg")
			args := append([]string{"snapshot", "delete", "--json", "--image", source, "--output", output, "--time", "2026-10-10T00:00:00Z"}, tc.flags...)
			var out, diagnostics bytes.Buffer
			if err := run(context.Background(), args, nil, &out, &diagnostics); !errors.Is(err, tc.want) || out.Len() != 0 {
				t.Fatalf("deletion error/report changed: %v; %s", err, out.String())
			}
			if _, err := os.Lstat(output); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("failed deletion published", err)
			}
		})
	}
	output := filepath.Join(t.TempDir(), "existing.dmg")
	if err := os.WriteFile(output, []byte("do not overwrite"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, dest := range []string{output, source} {
		before, err := os.ReadFile(dest)
		if err != nil {
			t.Fatal(err)
		}
		var out, diagnostics bytes.Buffer
		if err := run(context.Background(), []string{"snapshot", "delete", "--image", source, "--output", dest, "--snapshot-name", "absent"}, nil, &out, &diagnostics); !errors.Is(err, fs.ErrExist) || out.Len() != 0 {
			t.Fatal("existing output accepted", err, out.String())
		}
		after, err := os.ReadFile(dest)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("destination overwritten", err)
		}
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("snapshot CLI changed source", err)
	}
}

func TestSnapshotDeleteCLIRefusesHFSAndRetainsListBehavior(t *testing.T) {
	source := builtImage(t, "hfsplus")
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "unsupported.dmg")
	var out, diagnostics bytes.Buffer
	if err := run(context.Background(), []string{"snapshot", "delete", "--image", source, "--output", output, "--snapshot-name", "absent"}, nil, &out, &diagnostics); !errors.Is(err, filesystem.ErrUnsupported) || out.Len() != 0 {
		t.Fatal("HFS deletion accepted", err, out.String())
	}
	if _, err := os.Lstat(output); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("HFS deletion published", err)
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("HFS original changed", err)
	}
	out.Reset()
	apfsImage := builtImage(t, "apfs")
	if err := run(context.Background(), []string{"snapshot", "list", "--json", apfsImage}, nil, &out, &diagnostics); err != nil || !bytes.Contains(out.Bytes(), []byte(`"snapshots":[]`)) {
		t.Fatal("read-only snapshot inventory changed", err, out.String())
	}
}
