package hfsplus

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Synthetic controls exercise structural transitions and refusals. Independent
// Apple-created reference states, not these builders, qualify native behavior.
func TestCatalogMutationGrowthMoveRemovalAndLinkLifetime(t *testing.T) {
	for _, sensitive := range []bool{false, true} {
		t.Run(fmt.Sprint(sensitive), func(t *testing.T) {
			ctx := context.Background()
			original := mutationFixture(t, sensitive, "zlib")
			disk := &memoryMutation{bytes.Clone(original)}
			before, e := Open(disk)
			if e != nil {
				t.Fatal(e)
			}
			inode, e := filesystem.Lookup(ctx, before, "/large")
			if e != nil {
				t.Fatal(e)
			}
			changes := []Change{{Operation: "mkdir", Path: "/A/B", Parents: true, Mode: "0750"}}
			for i := range 180 {
				changes = append(changes, Change{Path: fmt.Sprintf("/A/B/%03d-%s", i, string(bytes.Repeat([]byte("x"), 110))), Data: bytes.NewReader([]byte("created"))})
			}
			changes = append(changes, Change{Operation: "mv", Path: "/A/B", Destination: "/Moved"}, Change{Operation: "mv", Path: "/small", Destination: "/Moved/Small"}, Change{Operation: "mv", Path: "/Moved/Small", Destination: "/Moved/SMALL"}, Change{Operation: "rm", Path: "/large"})
			if _, e = Modify(ctx, disk, changes, mutationTime); e != nil {
				t.Fatal(e)
			}
			v, e := Open(disk)
			if e != nil {
				t.Fatal(e)
			}
			if e = ValidateMutation(ctx, disk); e != nil {
				t.Fatal(e)
			}
			if len(v.catalog.fork.extents) <= 8 {
				t.Fatal("catalog overflow storage not exercised")
			}
			alias, e := filesystem.Lookup(ctx, v, "/alias")
			if e != nil || alias != inode {
				t.Fatal("shared inode lost", e)
			}
			n, e := v.Stat(ctx, alias)
			if e != nil || n.Links.Value != 1 {
				t.Fatal("remaining link count", n, e)
			}
			data, e := v.OpenData(ctx, alias)
			if e != nil {
				t.Fatal(e)
			}
			var got bytes.Buffer
			_, e = io.Copy(&got, io.NewSectionReader(data, 0, data.Size()))
			data.Close()
			if e != nil || got.Len() != 150000 {
				t.Fatal("shared compressed contents lost", e)
			}
			if _, e = filesystem.Lookup(ctx, v, "/Moved/SMALL"); e != nil {
				t.Fatal(e)
			}
			growth := be.Uint32(disk.data[1024+284:])
			if growth <= be.Uint32(original[1024+284:]) {
				t.Fatal("catalog growth not exercised")
			}
			freeBefore := v.FreeBlocks
			if _, e = Modify(ctx, disk, []Change{{Operation: "rm", Path: "/alias"}, {Operation: "rm", Path: "/Moved", Recursive: true}, {Operation: "rm", Path: "/A", Recursive: true}, {Operation: "rm", Path: "/absent", Force: true}}, mutationTime); e != nil {
				t.Fatal(e)
			}
			v, e = Open(disk)
			if e != nil {
				t.Fatal(e)
			}
			if e = ValidateMutation(ctx, disk); e != nil {
				t.Fatal(e)
			}
			if v.FreeBlocks <= freeBefore {
				t.Fatal("final link and recursive removal did not free storage")
			}
			for _, path := range []string{"/alias", "/large", "/Moved", "/A"} {
				if _, e = filesystem.Lookup(ctx, v, path); !errors.Is(e, fs.ErrNotExist) {
					t.Fatal("removed entry remains", path, e)
				}
			}
			if _, _, e = v.rawCatalogRecord(ctx, inode); !errors.Is(e, fs.ErrNotExist) {
				t.Fatal("final shared inode remains", e)
			}
		})
	}
}

func TestCatalogMutationRefusesUnsafeNamespaceOperations(t *testing.T) {
	original := mutationFixture(t, false, "preserve")
	for _, c := range []Change{
		{Operation: "mkdir", Path: "/small"}, {Operation: "mkdir", Path: "/missing/child"},
		{Operation: "mv", Path: "/", Destination: "/other"}, {Operation: "rm", Path: "/", Recursive: true},

		{Operation: "mv", Path: "/small", Destination: "/untouched", NoClobber: true},
		{Operation: "mkdir", Path: "/x", Mode: "4755"}, {Path: "/absent", ResourceFork: true, Data: bytes.NewReader([]byte("fork"))},
	} {
		disk := &memoryMutation{bytes.Clone(original)}
		if _, e := Modify(context.Background(), disk, []Change{c}, mutationTime); e == nil {
			t.Fatal("unsafe operation admitted", c)
		}
	}
	disk := &memoryMutation{bytes.Clone(original)}
	if _, e := Modify(context.Background(), disk, []Change{{Operation: "mkdir", Path: "/parent/child", Parents: true}, {Operation: "mv", Path: "/parent", Destination: "/parent/child/nested"}}, mutationTime); !errors.Is(e, fs.ErrInvalid) {
		t.Fatal("directory cycle admitted", e)
	}
}

func TestCatalogMutationRefusesExpandedTimestampRecords(t *testing.T) {
	ctx := context.Background()
	for _, path := range []string{"/", "/small"} {
		t.Run(path, func(t *testing.T) {
			disk := &memoryMutation{bytes.Clone(mutationFixture(t, false, "preserve"))}
			v, e := Open(disk)
			if e != nil {
				t.Fatal(e)
			}
			m := &mutation{ctx: ctx, disk: disk, v: v, header: bytes.Clone(disk.data[1024:1536]), trees: map[uint32]*mutableTree{}}
			if e = m.admit(); e != nil {
				t.Fatal(e)
			}
			id, e := filesystem.Lookup(ctx, v, path)
			if e != nil {
				t.Fatal(e)
			}
			record, e := v.catalogRecord(ctx, id)
			if e != nil {
				t.Fatal(e)
			}
			be.PutUint16(record[2:], be.Uint16(record[2:])|0x1000)
			if e = m.patchCatalog(uint32(id), record); e != nil {
				t.Fatal(e)
			}
			before := bytes.Clone(disk.data)
			if _, e = Modify(ctx, disk, []Change{{Operation: "mkdir", Path: "/new"}}, mutationTime); !errors.Is(e, filesystem.ErrUnsupported) {
				t.Fatal("expanded timestamps admitted", e)
			}
			if !bytes.Equal(before, disk.data) {
				t.Fatal("unsupported timestamp profile changed before refusal")
			}
		})
	}
}
