package pack

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestRepackPublicationAndSourcePreservation(t *testing.T) {
	dir := t.TempDir()
	source, destination := filepath.Join(dir, "source.raw"), filepath.Join(dir, "out.dmg")
	raw := make([]byte, 8192)
	copy(raw[32:], "NXSB")
	if err := os.WriteFile(source, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Repack(context.Background(), source, source, "UDZO"); !errors.Is(err, fs.ErrExist) {
		t.Fatal(err)
	}
	if _, err := Repack(context.Background(), source, destination, "UDZO"); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(source)
	if err != nil || string(original) != string(raw) {
		t.Fatal("source changed", err)
	}
	if _, err := Repack(context.Background(), source, destination, "UDZO"); !errors.Is(err, fs.ErrExist) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	failed := filepath.Join(dir, "failed.dmg")
	if _, err := Repack(ctx, source, failed, "UDZO"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := os.Lstat(failed); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	staging, _ := filepath.Glob(filepath.Join(dir, ".apfs-pack-*"))
	if len(staging) != 0 {
		t.Fatal("unremoved staging", staging)
	}
}
