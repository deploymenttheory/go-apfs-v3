package imageedit_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

func TestEditorFailureCannotPublishEvenIfCallbackIgnoresIt(t *testing.T) {
	for _, kind := range []string{"APFS", "HFS+"} {
		t.Run(kind, func(t *testing.T) {
			source := fixture(t, kind)
			original, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(t.TempDir(), "output.dmg")
			var retained *imageedit.Editor
			_, err = imageedit.Edit(context.Background(), source, destination, imageedit.Options{Time: clock}, func(editor *imageedit.Editor) error {
				retained = editor
				if _, err := editor.Apply([]imageedit.Change{{Operation: "mkdir", Path: "/created"}}); err != nil {
					t.Fatal(err)
				}
				// The first change writes private bytes before the second fails.
				_, failure := editor.Apply([]imageedit.Change{{Operation: "chmod", Path: "/created", Mode: "0700"}, {Operation: "chmod", Path: "/absent", Mode: "0700"}})
				if !errors.Is(failure, fs.ErrNotExist) {
					t.Fatal("fault did not reach mutation", failure)
				}
				if _, err := editor.Apply([]imageedit.Change{{Operation: "mkdir", Path: "/later"}}); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("failed scratch continued", err)
				}
				return nil // ignoring the failure must not publish partial work
			})
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("callback swallowed failure", err)
			}
			if _, err := os.Stat(destination); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("failed batch published output", err)
			}
			if _, err := retained.Apply([]imageedit.Change{{Operation: "mkdir", Path: "/expired"}}); !errors.Is(err, fs.ErrClosed) {
				t.Fatal("editor escaped its lifetime", err)
			}
			actual, err := os.ReadFile(source)
			if err != nil || !bytes.Equal(actual, original) {
				t.Fatal("original source changed", err)
			}
		})
	}
}
