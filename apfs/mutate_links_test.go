package apfs_test

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// A failed link insertion must never expose a partially updated sibling graph
// through the previous checkpoint, including failure at every actual write.
func TestAPFSLinkFailureRetainsPreviousCheckpoint(t *testing.T) {
	ctx := context.Background()
	when := time.Unix(1749283750, 0)
	original := mutationInput(t)
	changes := []apfs.Change{{Operation: "ln", Path: "/file", Destination: "/new-alias"}, {Operation: "ln", Path: "missing", Destination: "/new-symbol", Symbolic: true}}
	baseline := newMutationDisk(original)
	if _, err := apfs.Modify(ctx, baseline, changes, when); err != nil {
		t.Fatal(err)
	}
	for boundary := 1; boundary <= baseline.writes; boundary++ {
		disk := newMutationDisk(original)
		disk.failAt = boundary
		if _, err := apfs.Modify(ctx, disk, changes, when); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatal(boundary, err)
		}
		if boundary < baseline.writes {
			c, err := apfs.Open(disk)
			if err != nil {
				t.Fatal(boundary, err)
			}
			for _, name := range []string{"/new-alias", "/new-symbol"} {
				if _, err = filesystem.LookupExact(ctx, &c.Volumes[0], name); !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("partial link became visible", boundary, name, err)
				}
			}
		}
	}
}
