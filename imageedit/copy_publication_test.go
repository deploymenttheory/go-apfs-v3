package imageedit_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

// Stop only after a copy payload reaches managed scratch. This exercises the
// public transaction without adding a fault hook to the production writer.
type stopDuringCopy struct {
	context.Context
	directory string
}

func (c stopDuringCopy) Err() error {
	names, _ := filepath.Glob(filepath.Join(c.directory, ".apfs-copy-data-*"))
	for _, name := range names {
		if info, err := os.Stat(name); err == nil && info.Size() > 0 {
			os.Exit(17)
		}
	}
	return c.Context.Err()
}

func TestInterruptedImageCopyPublishesNothing(t *testing.T) {
	if os.Getenv("APFS_COPY_INTERRUPT_CHILD") == "1" {
		ctx := stopDuringCopy{context.Background(), os.Getenv("APFS_COPY_SCRATCH")}
		_, _ = imageedit.Copy(ctx, os.Getenv("APFS_COPY_SOURCE"), os.Getenv("APFS_COPY_DESTINATION"), imageedit.Options{Time: clock}, []string{os.Getenv("APFS_COPY_HOST")}, "/created", imageedit.CopyOptions{FromHost: true, NoAttributes: true})
		os.Exit(99)
	}
	for _, kind := range []string{"APFS", "HFS+"} {
		t.Run(kind, func(t *testing.T) {
			source := fixture(t, kind)
			original, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			host, destination := filepath.Join(root, "host"), filepath.Join(root, "output.dmg")
			if err = os.WriteFile(host, bytes.Repeat([]byte("payload"), 200000), 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(os.Args[0], "-test.run=^TestInterruptedImageCopyPublishesNothing$")
			command.Env = append(os.Environ(), "APFS_COPY_INTERRUPT_CHILD=1", "APFS_COPY_SOURCE="+source, "APFS_COPY_DESTINATION="+destination, "APFS_COPY_HOST="+host, "APFS_COPY_SCRATCH="+root, "TMPDIR="+root, "TMP="+root, "TEMP="+root)
			var exit *exec.ExitError
			if err = command.Run(); !errors.As(err, &exit) || exit.ExitCode() != 17 {
				t.Fatal("child did not stop while copying", err)
			}
			if _, err = os.Stat(destination); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("interrupted copy published output", err)
			}
			after, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(original, after) {
				t.Fatal("interrupted copy changed source", err)
			}
		})
	}
}

func TestOversizedHostCopyPublishesNothing(t *testing.T) {
	source := fixture(t)
	root := t.TempDir()
	host, destination := filepath.Join(root, "oversized"), filepath.Join(root, "output.dmg")
	file, err := os.Create(host)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate((1 << 30) + 1); err != nil {
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = imageedit.Copy(context.Background(), source, destination, imageedit.Options{Time: clock}, []string{host}, "/created", imageedit.CopyOptions{FromHost: true}); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal("oversized input accepted", err)
	}
	if _, err = os.Stat(destination); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("failed copy published output", err)
	}
}
