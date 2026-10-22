package native

import (
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func measuredCloneCopyContinuation(subtree string, shift int64) *schema.Observation {
	const size int64 = 16384
	data, resource := int64(409600)+shift, int64(819200)+shift
	var entries []schema.Entry
	for i, name := range []string{"Fixture/followed", "Fixture/overwrite", retainedPartialClone} {
		if subtree != "" {
			name = strings.TrimPrefix(name, subtree+"/")
		}
		entry := schema.Entry{Path: name, Kind: "file", ID: uint64(i + 1), Links: 1, Size: size,
			Xattrs:  []schema.Xattr{{Name: "com.apple.ResourceFork", Bytes: size}},
			Extents: &schema.Extents{Data: [][3]int64{{0, data, size}}, Resource: [][3]int64{{0, resource, size}}}}
		if name == retainedPartialClone {
			entry.Extents.Data = [][3]int64{{0, 1228800 + shift, 8192}, {8192, data + 8192, 8192}}
			entry.Extents.Resource = [][3]int64{{0, 1638400 + shift, 8192}, {8192, resource + 8192, 8192}}
		}
		entries = append(entries, entry)
	}
	return &schema.Observation{Volumes: []schema.Volume{{Index: 0}}, Views: []schema.View{{Entries: entries}}}
}

func TestCloneCopyContinuationSelectsNativePeersInEditedAndSessionLayouts(t *testing.T) {
	for _, profile := range []string{"apfs", "apfsx", "hfsplus", "hfsx"} {
		for _, operation := range []string{"edit", "build"} {
			out := schema.Output{Operation: operation, Source: schema.CaseRef{Recipe: "clone-copy", Profile: profile}}
			if operation == "build" {
				out.Expect.Subtree = "Fixture"
			}
			if usesCloneCopyContinuation(out) != strings.HasPrefix(profile, "apfs") {
				t.Fatal("wrong native clone/fallback continuation", out)
			}
			source, sibling := cloneCopyContinuationPeers(out)
			prefix := "Fixture/"
			if operation == "build" {
				prefix = ""
			}
			if source != prefix+"followed" || sibling != prefix+"overwrite" {
				t.Fatal("wrong final untouched native clone pair", source, sibling)
			}
		}
	}
	if usesCloneCopyContinuation(schema.Output{Operation: "repack", Source: schema.CaseRef{Recipe: "clone-copy", Profile: "apfs"}}) || usesCloneCopyContinuation(schema.Output{Operation: "edit", Source: schema.CaseRef{Recipe: "apfs-clones", Profile: "apfs"}}) {
		t.Fatal("another capability was routed to clone-copy continuation")
	}
}

func TestCloneCopyContinuationPreservesPartialAndUntouchedPhysicalRelations(t *testing.T) {
	for _, subtree := range []string{"", "Fixture"} {
		out := schema.Output{Expect: schema.Expectation{Subtree: subtree}}
		before, after := measuredCloneCopyContinuation(subtree, 0), measuredCloneCopyContinuation(subtree, 1<<24)
		if err := compareCloneCopyContinuation(after, before, out); err != nil {
			t.Fatal("equivalent native sharing rejected after independent allocation", subtree, err)
		}
		for _, test := range []struct {
			name   string
			change func(*schema.View)
		}{
			{"lost partial data", func(v *schema.View) { v.Entries[2].Extents.Data[1][1] += 1 << 20 }},
			{"lost partial fork", func(v *schema.View) { v.Entries[2].Extents.Resource[1][1] += 1 << 20 }},
			{"lost untouched sibling", func(v *schema.View) { v.Entries[1].Extents.Data[0][1] += 1 << 20 }},
			{"missing native measurements", func(v *schema.View) { v.Entries[2].Extents = nil }},
			{"partial became hard link", func(v *schema.View) { v.Entries[2].ID = v.Entries[0].ID }},
			{"missing partial", func(v *schema.View) { v.Entries = v.Entries[:2] }},
		} {
			t.Run(subtree+"/"+test.name, func(t *testing.T) {
				after := measuredCloneCopyContinuation(subtree, 1<<24)
				test.change(&after.Views[0])
				if err := compareCloneCopyContinuation(after, before, out); err == nil {
					t.Fatal("lost native clone preservation passed")
				}
			})
		}
	}
}
