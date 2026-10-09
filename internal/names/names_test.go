package names

import (
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type directory struct {
	filesystem.Reader
	entries []filesystem.DirEntry
}

func (d directory) ReadDir(ctx context.Context, _ uint64, yield func(filesystem.DirEntry) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, entry := range d.entries {
		if err := yield(entry); err != nil {
			return err
		}
	}
	return nil
}

func TestLookupRejectsAmbiguousOrInvalidInput(t *testing.T) {
	d := directory{entries: []filesystem.DirEntry{{Name: "ReadMe", Object: 3}, {Name: "README", Object: 4}}}
	key := func(s string) string { return APFS(s, false, true) }
	if _, err := Lookup(context.Background(), d, 2, "readme", key); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal(err)
	}
	for _, name := range []string{"", ".", "..", "a/b", "a\x00b", "\xff"} {
		if _, err := Lookup(context.Background(), d, 2, name, key); !errors.Is(err, fs.ErrInvalid) {
			t.Fatalf("%q: %v", name, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Lookup(ctx, d, 2, "ReadMe", key); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

// Lookup is distinct from exact forensic spelling and does not traverse links.
func TestNativeAndExactPathLookup(t *testing.T) {
	d := pathDirectory{directory{entries: []filesystem.DirEntry{{Name: "ReadMe", Object: 3}}}}
	if got, err := filesystem.Lookup(context.Background(), d, "/readme"); err != nil || got != 3 {
		t.Fatal(got, err)
	}
	if _, err := filesystem.LookupExact(context.Background(), d, "readme"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if _, err := filesystem.Lookup(context.Background(), d, "../ReadMe"); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
}

type pathDirectory struct{ directory }

func (d pathDirectory) Root() uint64 { return 2 }
func (d pathDirectory) Lookup(ctx context.Context, parent uint64, name string) (filesystem.DirEntry, error) {
	return Lookup(ctx, d, parent, name, func(s string) string { return APFS(s, false, true) })
}

func FuzzComparisonKeys(f *testing.F) {
	f.Add("caf\u00e9\u0345\u0301")
	f.Add("\uac01\U00010570\u1c89")
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 1024 {
			return
		}
		_ = APFS(s, false, true)
		_ = APFS(s, true, true)
		_ = HFS(s, false)
		_ = HFS(s, true)
	})
}
