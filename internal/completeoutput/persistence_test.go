package completeoutput

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func systemOperations() operations {
	return operations{syncFile: (*os.File).Sync, link: os.Link, remove: os.Remove, syncDirectory: syncDirectory}
}

func TestPublicationPersistenceFailures(t *testing.T) {
	for _, phase := range []string{"write-full", "flush-full", "link", "directory", "cleanup"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "completed")
			ops := systemOperations()
			cause := syscall.ENOSPC
			switch phase {
			case "flush-full":
				ops.syncFile = func(*os.File) error { return cause }
			case "link":
				ops.link = func(string, string) error { return cause }
			case "directory":
				ops.syncDirectory = func(string) error { return cause }
			case "cleanup":
				ops.remove = func(string) error { return cause }
			}
			err := publish(context.Background(), path, func(out io.Writer) error {
				_, e := io.WriteString(out, "complete image bytes")
				if phase == "write-full" {
					return errors.Join(e, cause)
				}
				return e
			}, ops)
			if !errors.Is(err, cause) {
				t.Fatal("OS failure lost", err)
			}
			var published *PublishedError
			visible := phase == "directory" || phase == "cleanup"
			if errors.As(err, &published) != visible {
				t.Fatal("publication outcome misreported", err)
			}
			data, readErr := os.ReadFile(path)
			if visible {
				if readErr != nil || string(data) != "complete image bytes" || published.Path != path || published.Persisted != (phase == "cleanup") {
					t.Fatal("published output/outcome", published, readErr)
				}
			} else if !errors.Is(readErr, fs.ErrNotExist) {
				t.Fatal("partial output visible", readErr)
			}
			matches, e := filepath.Glob(filepath.Join(filepath.Dir(path), ".apfs-pack-*"))
			if e != nil || len(matches) != map[bool]int{true: 1, false: 0}[phase == "cleanup"] {
				t.Fatal("temporary cleanup outcome", matches, e)
			}
		})
	}
}

func TestCancellationAfterPublicationFinishesFlush(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(t.TempDir(), "completed")
	ops := systemOperations()
	ops.link = func(old, new string) error {
		err := os.Link(old, new)
		cancel()
		return err
	}
	flushed := false
	ops.syncDirectory = func(dir string) error {
		flushed = true
		return syncDirectory(dir)
	}
	err := publish(ctx, path, func(out io.Writer) error {
		_, err := io.WriteString(out, "complete")
		return err
	}, ops)
	if err != nil || !flushed {
		t.Fatal("publication cancellation retracted completed output", err)
	}
}

func TestPublishedFileClosedBeforeNameAndCleanupBeforeDirectoryFlush(t *testing.T) {
	path := filepath.Join(t.TempDir(), "completed")
	ops := systemOperations()
	var file *os.File
	var temporary string
	ops.link = func(old, new string) error {
		temporary = old
		if _, err := file.Write([]byte("late write")); !errors.Is(err, fs.ErrClosed) {
			t.Fatal("file was not closed before publication", err)
		}
		return os.Link(old, new)
	}
	ops.syncDirectory = func(dir string) error {
		if _, err := os.Lstat(temporary); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("temporary link still present at directory flush", err)
		}
		return syncDirectory(dir)
	}
	err := publish(context.Background(), path, func(out io.Writer) error {
		file = out.(*os.File)
		_, err := io.WriteString(out, "complete")
		return err
	}, ops)
	if err != nil {
		t.Fatal(err)
	}
}
