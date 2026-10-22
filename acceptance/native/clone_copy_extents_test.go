package native

import (
	"slices"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func cloneCopyMeasuredEntry(name string, id uint64, data, resource int64) schema.Entry {
	return schema.Entry{Path: "Fixture/" + name, Kind: "file", ID: id, Size: 4096, SHA256: "equal-data", Xattrs: []schema.Xattr{{Name: "com.apple.ResourceFork", Bytes: 4096, SHA256: "equal-fork"}}, Extents: &schema.Extents{Data: [][3]int64{{0, data, 4096}}, Resource: [][3]int64{{0, resource, 4096}}}}
}

func TestCloneCopyPhysicalGraphRequiresSharingAndIndependentEqualBytes(t *testing.T) {
	want := schema.View{Entries: []schema.Entry{
		cloneCopyMeasuredEntry("source", 1, 4096, 8192),
		cloneCopyMeasuredEntry("clone", 2, 4096, 8192),
		cloneCopyMeasuredEntry("clone-alias", 2, 4096, 8192),
		cloneCopyMeasuredEntry("equal-independent", 3, 12288, 16384),
	}}
	for _, subtree := range []string{"", "Fixture"} {
		view := schema.View{Entries: slices.Clone(want.Entries)}
		for i := range view.Entries {
			entry := &view.Entries[i]
			entry.Extents = &schema.Extents{Data: slices.Clone(entry.Extents.Data), Resource: slices.Clone(entry.Extents.Resource)}
			entry.Extents.Data[0][1] += 1 << 20
			entry.Extents.Resource[0][1] += 1 << 20
			if subtree != "" {
				entry.Path = strings.TrimPrefix(entry.Path, subtree+"/")
			}
		}
		obs := &schema.Observation{Volumes: []schema.Volume{{Index: 0}}, Views: []schema.View{view}}
		if differences, err := cloneCopyOutputDifferences(obs, want, subtree); err != nil || len(differences) != 0 {
			t.Fatal("equivalent native relations rejected across allocation/root projection", subtree, err, differences)
		}
		// Full independent copies preserve every logical digest, but must fail
		// the physical graph whenever native cp -c actually shared storage.
		view.Entries[1].Extents.Data[0][1] += 1 << 22
		if differences, err := cloneCopyOutputDifferences(obs, want, subtree); err != nil || len(differences) == 0 {
			t.Fatal("content-only clone accepted", subtree, err, differences)
		}
		view.Entries[1].Extents.Data[0][1] -= 1 << 22
		view.Entries[3].Extents.Data = slices.Clone(view.Entries[0].Extents.Data)
		if differences, err := cloneCopyOutputDifferences(obs, want, subtree); err != nil || len(differences) == 0 {
			t.Fatal("equal independent file incorrectly shared", subtree, err, differences)
		}
	}
}

func TestCloneCopyPhysicalGraphRetainsForkOnlyDetachmentAndRejectsMissingEvidence(t *testing.T) {
	want := schema.View{Entries: []schema.Entry{cloneCopyMeasuredEntry("followed", 1, 4096, 8192), cloneCopyMeasuredEntry("clone", 2, 12288, 16384), cloneCopyMeasuredEntry("clone-alias", 2, 12288, 16384)}}
	obs := &schema.Observation{Volumes: []schema.Volume{{Index: 0}}, Views: []schema.View{want}}
	if differences, err := cloneCopyOutputDifferences(obs, want, ""); err != nil || len(differences) != 0 {
		t.Fatal("private data/fork relation rejected", err, differences)
	}
	obs.Views = []schema.View{{Entries: slices.Clone(want.Entries)}}
	obs.Views[0].Entries[1].Extents = nil
	if _, err := cloneCopyOutputDifferences(obs, want, ""); err == nil {
		t.Fatal("missing actual native evidence accepted")
	}
	obs.Views[0].Entries = slices.Clone(want.Entries[:2])
	if _, err := cloneCopyOutputDifferences(obs, want, ""); err == nil {
		t.Fatal("missing measured alias accepted")
	}
}
