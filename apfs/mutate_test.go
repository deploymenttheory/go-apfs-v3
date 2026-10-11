package apfs_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type mutationDisk struct {
	*bytes.Reader
	data           []byte
	writes, failAt int
	short          bool
}

func newMutationDisk(data []byte) *mutationDisk {
	b := bytes.Clone(data)
	return &mutationDisk{Reader: bytes.NewReader(b), data: b}
}
func (d *mutationDisk) WriteAt(b []byte, off int64) (int, error) {
	d.writes++
	if d.failAt == d.writes {
		if d.short {
			return len(b) / 2, nil
		}
		return 0, io.ErrClosedPipe
	}
	if off < 0 || off > int64(len(d.data)) || len(b) > len(d.data)-int(off) {
		return 0, fs.ErrInvalid
	}
	copy(d.data[off:], b)
	return len(b), nil
}
func mutationInput(t *testing.T) []byte {
	t.Helper()
	s, o, _ := buildInput(t)
	o.Time = o.Time.Truncate(time.Second)
	o.Capacity = 8 << 20
	plan, e := apfs.Plan(context.Background(), s, o)
	if e != nil {
		t.Fatal(e)
	}
	var b bytes.Buffer
	if e = plan.Write(context.Background(), &b); e != nil {
		t.Fatal(e)
	}
	if e = apfs.ValidateMutation(context.Background(), bytes.NewReader(b.Bytes())); e != nil {
		t.Fatal(e)
	}
	return b.Bytes()
}
func TestAPFSMutationReusesRetiredSpaceAndRetainsIdentity(t *testing.T) {
	ctx := context.Background()
	original := mutationInput(t)
	before := sha256.Sum256(original)
	disk := newMutationDisk(original)
	c, e := apfs.Open(disk)
	if e != nil {
		t.Fatal(e)
	}
	id, e := c.Volumes[0].Lookup(ctx, 2, "file")
	if e != nil {
		t.Fatal(e)
	}
	var free uint64
	for n := 0; n < 40; n++ {
		payload := bytes.Repeat([]byte("growth"), 17000)
		if n%2 == 1 {
			payload = []byte("small")
		}
		report, e := apfs.Modify(ctx, disk, []apfs.Change{{Path: "/file", Data: bytes.NewReader(payload)}}, time.Unix(1749283750, 0))
		if e != nil {
			t.Fatal(n, e)
		}
		if e = apfs.ValidateMutation(ctx, disk); e != nil {
			t.Fatal(n, e)
		}
		next, e := apfs.Open(disk)
		if e != nil {
			t.Fatal(e)
		}
		got, e := next.Volumes[0].Lookup(ctx, 2, "file")
		if e != nil || got.Object != id.Object || next.UUID != c.UUID || next.Volumes[0].UUID != c.Volumes[0].UUID {
			t.Fatal("identity changed", e)
		}
		v, e := next.Volumes[0].OpenData(ctx, id.Object)
		if e != nil {
			t.Fatal(e)
		}
		b := make([]byte, v.Size())
		_, e = v.ReadAt(b, 0)
		v.Close()
		if e != nil && !errors.Is(e, io.EOF) || !bytes.Equal(b, payload) {
			t.Fatal("changed contents", e)
		}
		if n == 9 {
			free = report.FreeBlocks
		}
		if n > 9 && n%2 == 1 && report.FreeBlocks != free {
			t.Fatal("repeated writes leaked allocation", n, free, report.FreeBlocks)
		}
	}
	if sha256.Sum256(original) != before {
		t.Fatal("source changed")
	}
}
func TestAPFSMutationFailuresRequireDiscardAndRetainLastCheckpoint(t *testing.T) {
	original := mutationInput(t)
	before := sha256.Sum256(original)
	when := time.Unix(1749283750, 0)
	changes := []apfs.Change{{Path: "/file", Data: bytes.NewReader(bytes.Repeat([]byte("p"), 8193))}}
	baseline := newMutationDisk(original)
	if _, e := apfs.Modify(context.Background(), baseline, changes, when); e != nil {
		t.Fatal(e)
	}
	for fail := 1; fail <= baseline.writes; fail++ {
		disk := newMutationDisk(original)
		disk.failAt = fail
		if _, e := apfs.Modify(context.Background(), disk, changes, when); !errors.Is(e, io.ErrClosedPipe) {
			t.Fatal("write failure lost", fail, e)
		}
		// Until checkpoint publication, the original selected view must remain
		// readable. The scratch copy itself is never eligible for publication.
		if fail < baseline.writes {
			c, e := apfs.Open(disk)
			if e != nil {
				t.Fatal("last checkpoint lost", fail, e)
			}
			id, e := c.Volumes[0].Lookup(context.Background(), 2, "file")
			if e != nil {
				t.Fatal(e)
			}
			v, e := c.Volumes[0].OpenData(context.Background(), id.Object)
			if e != nil {
				t.Fatal(e)
			}
			b := make([]byte, v.Size())
			v.ReadAt(b, 0)
			v.Close()
			if !bytes.Equal(b, []byte("original payload")) {
				t.Fatal("partial transaction visible", fail)
			}
		}
	}
	short := newMutationDisk(original)
	short.failAt = 1
	short.short = true
	if _, e := apfs.Modify(context.Background(), short, changes, when); !errors.Is(e, io.ErrShortWrite) {
		t.Fatal("short write admitted", e)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, e := apfs.Modify(canceled, newMutationDisk(original), changes, when); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	if _, e := apfs.Modify(context.Background(), newMutationDisk(original), []apfs.Change{{Path: "/file", Data: bytes.NewReader(make([]byte, 8<<20))}}, when); !errors.Is(e, filesystem.ErrLimit) {
		t.Fatal("disk full admitted")
	}
	if sha256.Sum256(original) != before {
		t.Fatal("source changed")
	}
}
