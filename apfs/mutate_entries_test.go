package apfs_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// These controls stress ordered changes, structural growth/collapse and space
// reuse. Independent Apple before/after captures qualify on-disk semantics.
func TestAPFSDirectoryTransactionsGrowCollapseAndReuse(t *testing.T) {
	ctx := context.Background()
	when := time.Unix(1749283750, 0)
	original := mutationInput(t)
	digest := sha256.Sum256(original)
	disk := newMutationDisk(original)
	var stable uint64
	var previousID uint64
	for cycle := range 14 {
		changes := []apfs.Change{{Operation: "mkdir", Path: "/A/B", Parents: true, Mode: "0750"}, {Operation: "mkdir", Path: "/A/B", Parents: true}}
		for i := range 180 {
			changes = append(changes, apfs.Change{Path: fmt.Sprintf("/A/B/%03d-%s", i, strings.Repeat("x", 110)), Data: bytes.NewReader(bytes.Repeat([]byte("new"), 1366))})
		}
		changes = append(changes, apfs.Change{Operation: "mv", Path: "/A/B", Destination: "/Moved"}, apfs.Change{Operation: "mv", Path: "/Moved/000-" + strings.Repeat("x", 110), Destination: "/Moved/CASE"}, apfs.Change{Operation: "mv", Path: "/Moved/CASE", Destination: "/Moved/case"}, apfs.Change{Operation: "chmod", Path: "/Moved", Mode: "u=rwx,g=rx,o="})
		if _, e := apfs.Modify(ctx, disk, changes, when); e != nil {
			t.Fatal(cycle, e)
		}
		if e := apfs.ValidateMutation(ctx, disk); e != nil {
			t.Fatal(cycle, e)
		}
		c, e := apfs.Open(disk)
		if e != nil {
			t.Fatal(e)
		}
		v := &c.Volumes[0]
		id, e := filesystem.LookupExact(ctx, v, "/Moved/case")
		if e != nil {
			t.Fatal(e)
		}
		if id <= previousID {
			t.Fatal("inode high-water mark reused IDs")
		}
		previousID = id
		dir, e := filesystem.LookupExact(ctx, v, "/Moved")
		if e != nil {
			t.Fatal(e)
		}
		n, e := v.Stat(ctx, dir)
		if e != nil || n.Metadata.Mode.Value != 0040750 {
			t.Fatal(n, e)
		}
		data, e := v.OpenData(ctx, id)
		if e != nil {
			t.Fatal(e)
		}
		var got bytes.Buffer
		_, e = io.Copy(&got, io.NewSectionReader(data, 0, data.Size()))
		data.Close()
		if e != nil || got.Len() != 4098 {
			t.Fatal("created/moved bytes", got.Len(), e)
		}
		report, e := apfs.Modify(ctx, disk, []apfs.Change{{Operation: "rm", Path: "/Moved", Recursive: true}, {Operation: "rm", Path: "/A", Recursive: true}, {Operation: "rm", Path: "/absent", Force: true}}, when)
		if e != nil {
			t.Fatal(cycle, e)
		}
		if e = apfs.ValidateMutation(ctx, disk); e != nil {
			t.Fatal(e)
		}
		if cycle == 5 {
			stable = report.FreeBlocks
		}
		if cycle > 5 && report.FreeBlocks != stable {
			t.Fatal("repeated directory transactions leaked blocks", cycle, stable, report.FreeBlocks)
		}
		c, e = apfs.Open(disk)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = filesystem.LookupExact(ctx, &c.Volumes[0], "/Moved"); !errors.Is(e, fs.ErrNotExist) {
			t.Fatal("removed directory remains", e)
		}
	}
	if sha256.Sum256(original) != digest {
		t.Fatal("source changed")
	}
}
func TestAPFSDirectoryRefusalsAndNoOpRetainCheckpoint(t *testing.T) {
	original := mutationInput(t)
	ctx := context.Background()
	when := time.Unix(1749283750, 0)
	for _, changes := range [][]apfs.Change{
		{{Operation: "mkdir", Path: "/file"}}, {{Operation: "mkdir", Path: "/missing/child"}}, {{Operation: "mkdir", Path: "/new", Mode: "4755"}},
		{{Operation: "rm", Path: "/", Recursive: true}}, {{Operation: "mv", Path: "/", Destination: "/other"}},
		{{Operation: "mkdir", Path: "/A/B", Parents: true}, {Operation: "mv", Path: "/A", Destination: "/A/B/cycle"}},
		{{Path: "/file", Data: bytes.NewReader(nil), NoClobber: true}}, {{Path: "/missing", Data: bytes.NewReader(nil), ResourceFork: true}},
		{{Operation: "mkdir", Path: "/A"}, {Operation: "rm", Path: "/A"}},
		{{Operation: "mkdir", Path: "/A/B", Parents: true}, {Path: "/A/B/child", Data: bytes.NewReader(nil)}, {Operation: "mkdir", Path: "/Other/B", Parents: true}, {Operation: "mv", Path: "/Other/B", Destination: "/A"}},
	} {
		if _, e := apfs.Modify(ctx, newMutationDisk(original), changes, when); e == nil {
			t.Fatal("unsafe directory operation admitted", changes)
		}
	}
	disk := newMutationDisk(original)
	c, e := apfs.Open(disk)
	if e != nil {
		t.Fatal(e)
	}
	report, e := apfs.Modify(ctx, disk, []apfs.Change{{Operation: "rm", Path: "/absent", Force: true}, {Operation: "mkdir", Path: "/", Parents: true}, {Operation: "mv", Path: "/file", Destination: "/file"}}, when)
	if e != nil || disk.writes != 0 || report.Transaction != uint64(c.XID) {
		t.Fatal("no-op published transaction", report, e, disk.writes)
	}
}
func TestAPFSDirectoryFailureRetainsPreviousCheckpoint(t *testing.T) {
	original := mutationInput(t)
	ctx := context.Background()
	when := time.Unix(1749283750, 0)
	changes := []apfs.Change{{Operation: "mkdir", Path: "/new/dir", Parents: true}, {Path: "/new/dir/file", Data: bytes.NewReader(bytes.Repeat([]byte("created"), 1200))}, {Operation: "mv", Path: "/new/dir/file", Destination: "/new/renamed"}, {Operation: "rm", Path: "/new/dir", Recursive: true}, {Operation: "rm", Path: "/file"}}
	baseline := newMutationDisk(original)
	if _, e := apfs.Modify(ctx, baseline, changes, when); e != nil {
		t.Fatal(e)
	}
	for boundary := 1; boundary <= baseline.writes; boundary++ {
		disk := newMutationDisk(original)
		disk.failAt = boundary
		if _, e := apfs.Modify(ctx, disk, changes, when); !errors.Is(e, io.ErrClosedPipe) {
			t.Fatal(boundary, e)
		}
		if boundary < baseline.writes {
			c, e := apfs.Open(disk)
			if e != nil {
				t.Fatal(boundary, e)
			}
			if _, e = filesystem.LookupExact(ctx, &c.Volumes[0], "/file"); e != nil {
				t.Fatal("original checkpoint entry lost", boundary, e)
			}
			if _, e = filesystem.LookupExact(ctx, &c.Volumes[0], "/new"); !errors.Is(e, fs.ErrNotExist) {
				t.Fatal("partial create became visible", boundary, e)
			}
		}
	}
}

func TestAPFSConstructedResourceForksRemainEditable(t *testing.T) {
	ctx := context.Background()
	source, options, _ := buildInput(t)
	options.Time = options.Time.Truncate(time.Second)
	options.Capacity = 8 << 20
	fork := bytes.Repeat([]byte("fork"), 2049)
	if _, e := source.ReplaceResourceFork(ctx, "/file", bytes.NewReader(fork)); e != nil {
		t.Fatal(e)
	}
	plan, e := apfs.Plan(ctx, source, options)
	if e != nil {
		t.Fatal(e)
	}
	var encoded bytes.Buffer
	if e = plan.Write(ctx, &encoded); e != nil {
		t.Fatal(e)
	}
	if e = apfs.ValidateMutation(ctx, bytes.NewReader(encoded.Bytes())); e != nil {
		t.Fatal("Go-constructed ordinary fork image is not editable", e)
	}
	disk := newMutationDisk(encoded.Bytes())
	before, e := apfs.Open(disk)
	if e != nil {
		t.Fatal(e)
	}
	identity, e := filesystem.LookupExact(ctx, &before.Volumes[0], "/file")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = apfs.Modify(ctx, disk, []apfs.Change{{Operation: "mkdir", Path: "/Moved"}, {Operation: "mv", Path: "/file", Destination: "/Moved"}}, options.Time); e != nil {
		t.Fatal(e)
	}
	after, e := apfs.Open(disk)
	if e != nil {
		t.Fatal(e)
	}
	gotID, e := filesystem.LookupExact(ctx, &after.Volumes[0], "/Moved/file")
	if e != nil || gotID != identity {
		t.Fatal("moving a constructed fork file changed identity", e)
	}
	value, e := after.Volumes[0].OpenAttribute(ctx, gotID, filesystem.ResourceFork)
	if e != nil {
		t.Fatal(e)
	}
	got, e := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
	value.Close()
	if e != nil || !bytes.Equal(got, fork) {
		t.Fatal("moving a constructed file changed its fork", e)
	}
	if _, e = apfs.Modify(ctx, disk, []apfs.Change{{Operation: "rm", Path: "/Moved", Recursive: true}}, options.Time); e != nil {
		t.Fatal(e)
	}
	if e = apfs.ValidateMutation(ctx, disk); e != nil {
		t.Fatal(e)
	}
}
