package imageedit_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

var clock = time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)

func fixture(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	s, e := session.Create(ctx, filepath.Join(root, "session"), session.Options{Names: filesystem.NameRules{Format: "HFS+", NormalizationInsensitive: true}, Time: &clock})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	host := filepath.Join(root, "host")
	if e = os.WriteFile(host, []byte("existing"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Copy(ctx, []string{host}, "/file", session.CopyOptions{FromHost: true}); e != nil {
		t.Fatal(e)
	}
	source := filepath.Join(root, "source.dmg")
	if _, e = pack.Create(ctx, source, s, pack.Options{Volume: pack.VolumeOptions{Name: "Keep", Time: clock, Capacity: 16 << 20}}); e != nil {
		t.Fatal(e)
	}
	return source
}
func TestExistingImageOutputPreservesSourceAndIsReproducible(t *testing.T) {
	ctx := context.Background()
	source := fixture(t)
	original, e := os.ReadFile(source)
	if e != nil {
		t.Fatal(e)
	}
	for _, format := range []string{"UDRO", "UDZO"} {
		var previous [32]byte
		for repeat := 0; repeat < 2; repeat++ {
			out := filepath.Join(t.TempDir(), "edited.dmg")
			report, e := imageedit.Apply(ctx, source, out, imageedit.Options{Format: format, Time: clock}, []hfsplus.Change{{Path: "/FILE", Data: bytes.NewReader(bytes.Repeat([]byte("growth"), 40000))}, {Path: "/file", Mode: "0755"}})
			if e != nil {
				t.Fatal(e)
			}
			img, e := diskimage.Open(out)
			if e != nil {
				t.Fatal(e)
			}
			p, e := img.Partition(0)
			if e != nil {
				t.Fatal(e)
			}
			v, e := hfsplus.Open(p)
			if e != nil {
				t.Fatal(e)
			}
			if report.VolumeID != v.VolumeID || v.Name != "Keep" {
				t.Fatal("filesystem identity changed")
			}
			if e = hfsplus.ValidateMutation(ctx, p); e != nil {
				t.Fatal(e)
			}
			img.Close()
			encoded, e := os.ReadFile(out)
			if e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256(encoded)
			if repeat > 0 && sum != previous {
				t.Fatal("nonreproducible mutation")
			}
			previous = sum
			if _, e = imageedit.Apply(ctx, source, out, imageedit.Options{Time: clock}, []hfsplus.Change{{Path: "/file", Mode: "0600"}}); !errors.Is(e, fs.ErrExist) {
				t.Fatal("overwrote destination", e)
			}
		}
	}
	after, e := os.ReadFile(source)
	if e != nil || !bytes.Equal(after, original) {
		t.Fatal("source changed", e)
	}
	for _, change := range []hfsplus.Change{{Path: "/absent", Mode: "0755"}, {Path: "/file", Data: brokenInput{}}, {Path: "/file", Data: hugeInput{}}} {
		out := filepath.Join(t.TempDir(), "failed.dmg")
		if _, e = imageedit.Apply(ctx, source, out, imageedit.Options{Time: clock}, []hfsplus.Change{change}); e == nil {
			t.Fatal("bad transaction succeeded")
		}
		if _, e = os.Lstat(out); !errors.Is(e, fs.ErrNotExist) {
			t.Fatal("failed output published", e)
		}
	}
}

type brokenInput struct{}

func (brokenInput) Size() int64                       { return 8192 }
func (brokenInput) ReadAt([]byte, int64) (int, error) { return 0, io.ErrUnexpectedEOF }

type hugeInput struct{ brokenInput }

func (hugeInput) Size() int64 { return 1 << 40 }

// Abrupt exit while replacing contents must not expose a partial destination.
// It intentionally leaves only private scratch, which the parent removes.
func TestInterruptedImageTransaction(t *testing.T) {
	if os.Getenv("APFS_EDIT_INTERRUPT_CHILD") == "1" {
		_, _ = imageedit.Apply(context.Background(), os.Getenv("APFS_EDIT_SOURCE"), os.Getenv("APFS_EDIT_DESTINATION"), imageedit.Options{Time: clock}, []hfsplus.Change{{Path: "/file", Data: interruptedInput{}}})
		os.Exit(99)
	}
	source := fixture(t)
	before, _ := os.ReadFile(source)
	root := t.TempDir()
	out := filepath.Join(root, "edited.dmg")
	command := exec.Command(os.Args[0], "-test.run=^TestInterruptedImageTransaction$")
	command.Env = append(os.Environ(), "APFS_EDIT_INTERRUPT_CHILD=1", "APFS_EDIT_SOURCE="+source, "APFS_EDIT_DESTINATION="+out, "TMPDIR="+root, "TMP="+root, "TEMP="+root)
	err := command.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 17 {
		t.Fatal("child did not stop in mutation", err)
	}
	if _, e := os.Lstat(out); !errors.Is(e, fs.ErrNotExist) {
		t.Fatal("interrupted transaction published", e)
	}
	after, _ := os.ReadFile(source)
	if !bytes.Equal(before, after) {
		t.Fatal("interruption changed source")
	}
}

type interruptedInput struct{}

func (interruptedInput) Size() int64 { return 1 << 20 }
func (interruptedInput) ReadAt(p []byte, off int64) (int, error) {
	if off > 0 {
		os.Exit(17)
	}
	clear(p)
	return len(p), nil
}
