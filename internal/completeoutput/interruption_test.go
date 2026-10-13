package completeoutput

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestProcessDeathAtPublication(t *testing.T) {
	if phase := os.Getenv("APFS_PUBLISH_INTERRUPT_PHASE"); phase != "" {
		ops := systemOperations()
		ops.link = func(old, new string) error {
			if phase == "before-name" {
				os.Exit(17)
			}
			if err := os.Link(old, new); err != nil {
				return err
			}
			os.Exit(17)
			return nil
		}
		_ = publish(context.Background(), os.Getenv("APFS_PUBLISH_INTERRUPT_PATH"), func(out io.Writer) error {
			_, err := out.Write(bytes.Repeat([]byte("completed image bytes\n"), 10000))
			return err
		}, ops)
		os.Exit(99)
	}
	for _, phase := range []string{"before-name", "after-name"} {
		t.Run(phase, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "output")
			child := exec.Command(os.Args[0], "-test.run=^TestProcessDeathAtPublication$")
			child.Env = append(os.Environ(), "APFS_PUBLISH_INTERRUPT_PHASE="+phase, "APFS_PUBLISH_INTERRUPT_PATH="+path)
			var exit *exec.ExitError
			if err := child.Run(); !errors.As(err, &exit) || exit.ExitCode() != 17 {
				t.Fatal("child did not stop at the publication boundary", err)
			}
			data, err := os.ReadFile(path)
			if phase == "before-name" {
				if !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("partial destination visible", err)
				}
			} else if err != nil || !bytes.Equal(data, bytes.Repeat([]byte("completed image bytes\n"), 10000)) {
				t.Fatal("published destination incomplete", err)
			}
		})
	}
}
