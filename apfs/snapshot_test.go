package apfs

import (
	"context"
	"errors"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// These existing native images qualify empty inventories and missing selection,
// not populated snapshots or historical content. Those need the capture gate.
func TestNativeEmptySnapshotInventory(t *testing.T) {
	for _, name := range []string{"apfs", "apfs-case-sensitive"} {
		t.Run(name, func(t *testing.T) {
			img, err := diskimage.Open(filepath.Join("..", "acceptance", "testdata", "files", "macos-27", name+".dmg"))
			if err != nil {
				t.Fatal(err)
			}
			defer img.Close()
			var v *Volume
			for _, p := range img.Partitions {
				if p.Type != "7C3457EF-0000-11AA-AA11-00306543ECAC" {
					continue
				}
				source, err := img.Partition(p.Index)
				if err != nil {
					t.Fatal(err)
				}
				c, err := Open(source)
				if err != nil {
					t.Fatal(err)
				}
				if len(c.Volumes) != 1 {
					t.Fatal("expected one native volume")
				}
				v = &c.Volumes[0]
			}
			if v == nil {
				t.Fatal("missing native APFS")
			}
			if err := v.ListSnapshots(context.Background(), func(Snapshot) error {
				t.Fatal("unexpected snapshot in existing empty native image")
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			for _, xid := range []XID{0, 1, XID(^uint64(0))} {
				if r, err := v.OpenSnapshot(context.Background(), xid); r != nil || !errors.Is(err, fs.ErrNotExist) {
					t.Fatal("missing snapshot became live reader", err)
				}
			}
			if r, err := v.OpenSnapshotName(context.Background(), "missing"); r != nil || !errors.Is(err, fs.ErrNotExist) {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			if err := v.ListSnapshots(ctx, func(Snapshot) error { return nil }); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			v.Snapshots = maxSnapshots + 1
			if err := v.ListSnapshots(context.Background(), func(Snapshot) error { return nil }); !errors.Is(err, filesystem.ErrLimit) {
				t.Fatal(err)
			}
		})
	}
}

// Format-only record fixture: this does not establish native historical reads.
func snapshotRecordBytes() record {
	key := make([]byte, 8)
	le.PutUint64(key, 7|1<<60)
	value := make([]byte, 56)
	le.PutUint64(value[8:], 8)
	le.PutUint64(value[16:], 1234)
	le.PutUint64(value[24:], 5678)
	le.PutUint16(value[48:], 6)
	copy(value[50:], "first\x00")
	return record{key, value}
}

func TestSnapshotRecordBoundsAndNames(t *testing.T) {
	r := snapshotRecordBytes()
	s, err := readSnapshotRecord(r)
	if err != nil || s.Name != "first" || s.XID != 7 || s.CreateTime.UnixNano() != 1234 || s.ChangeTime.UnixNano() != 5678 {
		t.Fatal(s, err)
	}
	for size := 0; size < len(r.value); size++ {
		if _, err := readSnapshotRecord(record{r.key, r.value[:size]}); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatal("truncated metadata", size, err)
		}
	}
	for _, name := range []string{"", ".", "..", "a/b", "a\x00b", "\xff"} {
		b := append([]byte(name), 0)
		if _, err := snapshotName(b, len(b)); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatal("invalid name admitted", name, err)
		}
	}
	for _, length := range []int{0, 1, 5, 7, 65535} {
		if _, err := snapshotName([]byte("first\x00"), length); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatal("bad length admitted", length, err)
		}
	}
}

func FuzzSnapshotRecord(f *testing.F) {
	r := snapshotRecordBytes()
	f.Add(r.key, r.value)
	f.Fuzz(func(t *testing.T, key, value []byte) {
		if len(key)+len(value) <= 65536 {
			_, _ = readSnapshotRecord(record{key, value})
		}
	})
}

// Corrupt native metadata in a borrowed overlay. The retained evidence stays
// unchanged, and a failed historical open must not return a live reader.
func TestDamagedSnapshotDoesNotFallBackToLive(t *testing.T) {
	image, err := diskimage.Open("../acceptance/testdata/snapshots/macos-27/apfs.dmg")
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	var c *Container
	for _, p := range image.Partitions {
		if p.Type != diskimage.APFSType {
			continue
		}
		source, err := image.Partition(p.Index)
		if err != nil {
			t.Fatal(err)
		}
		c, err = Open(source)
		if err != nil {
			t.Fatal(err)
		}
	}
	if c == nil || len(c.Volumes) != 1 {
		t.Fatal("native APFS volume missing")
	}
	v, ctx := &c.Volumes[0], context.Background()
	records, err := v.snapshots(ctx)
	if err != nil || len(records) != 2 {
		t.Fatal("native snapshot inventory", err)
	}
	view, err := v.snapshotVolume(records[0])
	if err != nil {
		t.Fatal(err)
	}
	root, err := c.resolve(view.omap, view.root, view.xid)
	if err != nil {
		t.Fatal(err)
	}
	original := c.source
	for _, tc := range []struct {
		name    string
		address PhysicalAddress
	}{
		{"inventory", PhysicalAddress(v.snapMeta)},
		{"historical-superblock", records[0].superblock},
		{"historical-root", root.address},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c.source = damagedSource{original, int64(tc.address)*int64(c.BlockSize) + 100}
			defer func() { c.source = original }()
			if r, err := v.OpenSnapshot(ctx, records[0].XID); r != nil || !errors.Is(err, filesystem.ErrCorrupt) {
				t.Fatal("corrupt snapshot returned a reader", err)
			}
			if _, err := v.Stat(ctx, v.Root()); err != nil {
				t.Fatal("control live view must remain readable", err)
			}
		})
	}
}
