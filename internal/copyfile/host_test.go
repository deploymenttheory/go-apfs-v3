package copyfile

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestHostChangeWhileCopyingIsRefused(t *testing.T) {
	name := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(name, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(name)
	if err != nil {
		t.Fatal(err)
	}
	c := copier{options: Options{FromHost: true}}
	value, err := c.sourceData(context.Background(), copyEntry{path: name, info: info})
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(name, []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(name, info.ModTime().Add(time.Second), info.ModTime().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if err = value.Close(); !errors.Is(err, filesystem.ErrConflict) {
		t.Fatal("host mutation accepted", err)
	}
	if _, err = c.sourceData(context.Background(), copyEntry{path: name, info: info}); !errors.Is(err, filesystem.ErrConflict) {
		t.Fatal("changed host identity accepted at open", err)
	}
}
