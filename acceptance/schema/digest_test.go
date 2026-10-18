package schema

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTreeDigestIsOrderIndependentAndStructureSensitive(t *testing.T) {
	a := t.TempDir()
	b := t.TempDir()
	for _, root := range []string{a, b} {
		if err := os.MkdirAll(filepath.Join(root, "nested"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	write := func(root, name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(name)), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(a, "z.json", "{}")
	write(a, "nested/a.bin", "payload")
	write(b, "nested/a.bin", "payload")
	write(b, "z.json", "{}")
	da, err := TreeDigest(a)
	if err != nil {
		t.Fatal(err)
	}
	db, err := TreeDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatalf("identical trees hashed differently: %s vs %s", da, db)
	}
	if err := os.Rename(filepath.Join(b, "nested", "a.bin"), filepath.Join(b, "a.bin")); err != nil {
		t.Fatal(err)
	}
	moved, err := TreeDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if moved == da {
		t.Fatal("moving a file between directories did not change the digest")
	}
	write(b, "a.bin", "payloaD")
	changed, err := TreeDigest(b)
	if err != nil {
		t.Fatal(err)
	}
	if changed == moved {
		t.Fatal("changing one byte did not change the digest")
	}
}

func TestTreeDigestRejectsSymlinks(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "file"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file", filepath.Join(root, "link")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if _, err := TreeDigest(root); err == nil {
		t.Fatal("symlink inside the tree must be rejected")
	}
}
