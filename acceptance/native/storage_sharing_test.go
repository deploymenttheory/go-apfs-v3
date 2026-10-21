package native

import (
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestPhysicalReadComparisonRequiresTheNativeAddresses(t *testing.T) {
	for _, tc := range []struct {
		name   string
		reads  [][2]int64
		want   [3]int64
		sector int64
		valid  bool
	}{
		{"plain contiguous", [][2]int64{{8192, 7}}, [3]int64{0, 8192, 7}, 1, true},
		{"encrypted sectors", [][2]int64{{8704, 512}, {8192, 512}}, [3]int64{0, 8192, 513}, 512, true},
		{"repeated boundary sector", [][2]int64{{8192, 512}, {8192, 512}}, [3]int64{0, 8192, 7}, 512, true},
		{"different physical location", [][2]int64{{16384, 7}}, [3]int64{0, 8192, 7}, 1, false},
		{"unread physical tail", [][2]int64{{8192, 6}}, [3]int64{0, 8192, 7}, 1, false},
		{"missing middle", [][2]int64{{8192, 2}, {8196, 3}}, [3]int64{0, 8192, 7}, 1, false},
		{"metadata contamination", [][2]int64{{4096, 4096}, {8192, 7}}, [3]int64{0, 8192, 7}, 1, false},
		{"no reads", nil, [3]int64{0, 8192, 7}, 1, false},
		{"invalid native run", [][2]int64{{8192, 7}}, [3]int64{0, 8192, -7}, 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ComparePhysicalRead(tc.reads, tc.want, tc.sector); (err == nil) != tc.valid {
				t.Fatalf("valid %v: %v", tc.valid, err)
			}
		})
	}
}

func TestCloneControlsDistinguishPhysicalSharingFromEqualContents(t *testing.T) {
	control := func() schema.View {
		return schema.View{Entries: []schema.Entry{
			{Path: "Fixture/data", ID: 19, Links: 2, Size: 4096, SHA256: "same bytes", Xattrs: []schema.Xattr{{Name: "com.apple.ResourceFork", Bytes: 32}}, Extents: &schema.Extents{Data: [][3]int64{{0, 8192, 4096}}, Resource: [][3]int64{{0, 16384, 32}}}},
			{Path: "Fixture/alias", ID: 19, Links: 2, Size: 4096},
			{Path: "Fixture/clone", ID: 26, Links: 1, Size: 4096, SHA256: "same bytes", Xattrs: []schema.Xattr{{Name: "com.apple.ResourceFork", Bytes: 32}}, Extents: &schema.Extents{Data: [][3]int64{{0, 8192, 4096}}, Resource: [][3]int64{{0, 16384, 32}}}},
			{Path: "Fixture/ordinary-copy", ID: 28, Links: 1, Size: 4096, SHA256: "same bytes", Xattrs: []schema.Xattr{{Name: "com.apple.ResourceFork", Bytes: 32}}, Extents: &schema.Extents{Data: [][3]int64{{0, 24576, 4096}}, Resource: [][3]int64{{0, 32768, 32}}}},
		}}
	}
	for _, fault := range []string{"valid", "equal unshared bytes", "hard link as clone", "ordinary copy shares data", "ordinary copy shares fork", "missing native extent", "invalid native range", "duplicate native path"} {
		t.Run(fault, func(t *testing.T) {
			view := control()
			switch fault {
			case "equal unshared bytes":
				view.Entries[2].Extents.Data[0][1] = 40960
			case "hard link as clone":
				view.Entries[2].ID = view.Entries[0].ID
			case "ordinary copy shares data":
				view.Entries[3].Extents.Data[0][1] = 8192
			case "ordinary copy shares fork":
				view.Entries[3].Extents.Resource[0][1] = 16384
			case "missing native extent":
				view.Entries[2].Extents = nil
			case "invalid native range":
				view.Entries[2].Extents.Data[0][2] = -1
			case "duplicate native path":
				view.Entries = append(view.Entries, view.Entries[0])
			}
			if err := CheckCloneSharing(view, "clone-shared"); (err == nil) != (fault == "valid") {
				t.Fatalf("%s: %v", fault, err)
			}
		})
	}
}
