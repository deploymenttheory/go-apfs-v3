package apfs

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type damagedSource struct {
	block.Source
	offset int64
}

func (s damagedSource) ReadAt(p []byte, off int64) (int, error) {
	n, err := s.Source.ReadAt(p, off)
	if s.offset >= off && s.offset-off < int64(n) {
		p[s.offset-off] ^= 1
	}
	return n, err
}

// A fresh Go-built volume qualifies empty inventories and missing selection.
// Populated snapshots and historical content belong to the acceptance tier.
func TestBuiltEmptySnapshotInventory(t *testing.T) {
	data := builtContainer(t, stageFixture(t))
	c := openBuilt(t, data)
	v := &c.Volumes[0]
	if err := v.ListSnapshots(context.Background(), func(Snapshot) error {
		t.Fatal("unexpected snapshot in fresh built image")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, xid := range []XID{0, 1, c.XID, XID(^uint64(0))} {
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
}

// Damaged snapshot metadata on a built volume must refuse explicitly. The live
// view stays readable as a control; a historical open never returns it.
func TestDamagedSnapshotMetadataDoesNotFallBackToLive(t *testing.T) {
	data := builtContainer(t, stageFixture(t))
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		edit func(v *Volume)
		want error
	}{
		{"count without inventory tree", func(v *Volume) { v.Snapshots = 1 }, filesystem.ErrCorrupt},
		{"inventory tree pointing at the root tree", func(v *Volume) { v.Snapshots, v.snapMeta, v.snapMetaType = 1, v.root, 0x40000002 }, filesystem.ErrCorrupt},
		{"unsupported inventory tree type", func(v *Volume) { v.Snapshots, v.snapMeta, v.snapMetaType = 1, v.root, 0x40000003 }, filesystem.ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := openBuilt(t, data)
			v := &c.Volumes[0]
			tc.edit(v)
			if err := v.ListSnapshots(ctx, func(Snapshot) error { return nil }); !errors.Is(err, tc.want) {
				t.Fatal("damaged inventory listed", err)
			}
			for _, xid := range []XID{1, c.XID} {
				if r, err := v.OpenSnapshot(ctx, xid); r != nil || !errors.Is(err, tc.want) {
					t.Fatal("damaged inventory returned a reader", r, err)
				}
			}
			if r, err := v.OpenSnapshotName(ctx, "any"); r != nil || !errors.Is(err, tc.want) {
				t.Fatal("damaged inventory returned a reader by name", r, err)
			}
			if _, err := v.Stat(ctx, v.Root()); err != nil {
				t.Fatal("control live view must remain readable", err)
			}
		})
	}
	// Damaged live metadata is also never bridged by a snapshot path.
	c := openBuilt(t, data)
	v := &c.Volumes[0]
	mapping, err := c.resolve(v.omap, v.root, c.XID)
	if err != nil {
		t.Fatal(err)
	}
	c.source = damagedSource{bytes.NewReader(data), int64(mapping.address)*int64(c.BlockSize) + 100}
	if _, err := v.Stat(ctx, v.Root()); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("damaged root tree admitted", err)
	}
	if r, err := v.OpenSnapshot(ctx, c.XID); r != nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("damaged live root reached through snapshot selection", r, err)
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
