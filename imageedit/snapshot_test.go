package imageedit_test

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

// These public failure controls use an ordinary built volume with no history.
// Deletion ordering, retained-history equality and reclaimed allocation belong
// to the APFS engine and independently captured history acceptance controls.
func TestSnapshotDeletionFailuresPreserveSourceAndPublishNothing(t *testing.T) {
	ctx := context.Background()
	source := fixture(t, "APFS")
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		selector apfs.SnapshotSelector
		want     error
	}{
		{"missing exact name", apfs.SnapshotSelector{Name: "absent"}, fs.ErrNotExist},
		{"missing xid", apfs.SnapshotSelector{XID: 1}, fs.ErrNotExist},
		{"no identity", apfs.SnapshotSelector{}, fs.ErrInvalid},
		{"ambiguous identity", apfs.SnapshotSelector{Name: "absent", XID: 1}, fs.ErrInvalid},
		{"invalid name", apfs.SnapshotSelector{Name: "bad\x00name"}, fs.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "deleted.dmg")
			_, err := imageedit.DeleteSnapshot(ctx, source, output, imageedit.Options{Time: clock}, tc.selector)
			if !errors.Is(err, tc.want) {
				t.Fatalf("wrong deletion refusal: %v", err)
			}
			if _, err := os.Lstat(output); !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("failed deletion published: %v", err)
			}
		})
	}
	for _, output := range []string{source, filepath.Join(t.TempDir(), "occupied.dmg")} {
		if output != source {
			if err := os.WriteFile(output, []byte("existing destination"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		before, err := os.ReadFile(output)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := imageedit.DeleteSnapshot(ctx, source, output, imageedit.Options{Time: clock}, apfs.SnapshotSelector{Name: "absent"}); !errors.Is(err, fs.ErrExist) {
			t.Fatal("existing destination accepted", err)
		}
		after, err := os.ReadFile(output)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("existing output changed", err)
		}
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	output := filepath.Join(t.TempDir(), "cancelled.dmg")
	if _, err := imageedit.DeleteSnapshot(cancelled, source, output, imageedit.Options{Time: clock}, apfs.SnapshotSelector{Name: "absent"}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	if _, err := os.Lstat(output); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("cancelled deletion published", err)
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("deletion changed original source", err)
	}
}

func TestIgnoredSnapshotDeletionFailureDiscardsEarlierEditorWrites(t *testing.T) {
	ctx := context.Background()
	source := fixture(t, "APFS")
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "discarded.dmg")
	var retained *imageedit.Editor
	_, err = imageedit.Edit(ctx, source, output, imageedit.Options{Time: clock}, func(editor *imageedit.Editor) error {
		retained = editor
		if _, err := editor.Apply([]imageedit.Change{{Path: "/file", Data: bytes.NewReader([]byte("unpublished replacement"))}}); err != nil {
			return err
		}
		if _, err := editor.DeleteSnapshot(apfs.SnapshotSelector{Name: "absent"}); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("missing snapshot error changed: %v", err)
		}
		if _, err := editor.Apply([]imageedit.Change{{Path: "/file", Mode: "0700"}}); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("deletion did not make command failure sticky: %v", err)
		}
		return nil // Ignoring a failed command must never publish earlier writes.
	})
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("ignored deletion published", err)
	}
	if _, err := os.Lstat(output); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("intermediate write published", err)
	}
	if _, err := retained.DeleteSnapshot(apfs.SnapshotSelector{Name: "absent"}); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("expired editor remained usable", err)
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("failed transaction changed source", err)
	}
}

func TestSnapshotDeletionRefusesHFSWithoutPublishing(t *testing.T) {
	source := fixture(t)
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "unsupported.dmg")
	if _, err := imageedit.DeleteSnapshot(context.Background(), source, output, imageedit.Options{Time: clock}, apfs.SnapshotSelector{Name: "absent"}); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal("non-APFS deletion accepted", err)
	}
	if _, err := os.Lstat(output); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("unsupported deletion published", err)
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(original, after) {
		t.Fatal("unsupported deletion changed source", err)
	}
}
