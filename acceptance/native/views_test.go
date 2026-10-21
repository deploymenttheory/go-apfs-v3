package native

import (
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestNativeReadbackRequiresEveryVolumeAndSnapshot(t *testing.T) {
	want := &schema.Observation{
		Volumes: []schema.Volume{{Index: 0, Diskutil: map[string]any{"VolumeName": "Data"}}, {Index: 1, Diskutil: map[string]any{"VolumeName": "Peer"}}},
		Views:   []schema.View{{Volume: 0, Entries: []schema.Entry{entry("live", 10)}}, {Volume: 0, Snapshot: "old", Entries: []schema.Entry{entry("historical", 10)}}, {Volume: 1, Entries: []schema.Entry{entry("peer", 20)}}},
	}
	for _, tc := range []struct {
		name   string
		change func(*schema.Observation)
	}{
		{"missing snapshot", func(o *schema.Observation) { o.Views = append(o.Views[:1], o.Views[2:]...) }},
		{"wrong snapshot", func(o *schema.Observation) { o.Views[1].Snapshot = "other" }},
		{"missing peer", func(o *schema.Observation) { o.Volumes = o.Volumes[:1] }},
		{"duplicate live view", func(o *schema.Observation) { o.Views[1] = o.Views[0] }},
		{"duplicate peer name", func(o *schema.Observation) { o.Volumes[1].Diskutil["VolumeName"] = "Data" }},
		{"extra view", func(o *schema.Observation) { o.Views = append(o.Views, schema.View{Volume: 1, Snapshot: "extra"}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cloneObservation(t, want)
			tc.change(got)
			if differences, err := compareObservationViews(got, want, CompareOptions{}); err == nil && len(differences) == 0 {
				t.Fatal("missing or ambiguous native view escaped verification")
			}
		})
	}
	got := cloneObservation(t, want)
	got.Volumes[0], got.Volumes[1] = got.Volumes[1], got.Volumes[0]
	if differences, err := compareObservationViews(got, want, CompareOptions{}); err != nil || len(differences) != 0 {
		t.Fatalf("attachment order changed semantic result: %v %v", differences, err)
	}
}

func TestFreshReadbackPreservesHardLinkRelationships(t *testing.T) {
	a, alias, independent := entry("a", 10), entry("alias", 10), entry("independent", 11)
	a.Links, alias.Links = 2, 2
	want := schema.View{Entries: []schema.Entry{a, alias, independent}}
	got := schema.View{Entries: append([]schema.Entry(nil), want.Entries...)}
	got.Entries[0].ID, got.Entries[1].ID, got.Entries[2].ID = 20, 20, 21
	if d := CompareViews(got, want, CompareOptions{IgnoreIdentity: true}); len(d) != 0 {
		t.Fatal(d)
	}
	for _, tc := range []struct {
		name   string
		change func(*schema.View)
	}{
		{"flattened alias", func(v *schema.View) { v.Entries[1].ID = 22 }},
		{"unrelated objects merged", func(v *schema.View) { v.Entries[2].ID = 20 }},
		{"lost link count", func(v *schema.View) { v.Entries[0].Links = 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := schema.View{Entries: append([]schema.Entry(nil), got.Entries...)}
			tc.change(&v)
			if d := CompareViews(v, want, CompareOptions{IgnoreIdentity: true}); len(d) == 0 {
				t.Fatal("altered hard-link relationship escaped fresh-build verification")
			}
		})
	}
}

func TestSelectedVolumeRelaxationsDoNotHidePeerChanges(t *testing.T) {
	want := &schema.Observation{
		Volumes: []schema.Volume{{Index: 0, Diskutil: map[string]any{"VolumeName": "Selected"}}, {Index: 1, Diskutil: map[string]any{"VolumeName": "Peer"}}},
		Views:   []schema.View{{Volume: 0, Entries: []schema.Entry{entry("a", 10)}}, {Volume: 1, Entries: []schema.Entry{entry("a", 20)}}},
	}
	got := cloneObservation(t, want)
	got.Views[0].Entries[0].Times.Change++
	got.Views[1].Entries[0].Times.Change++
	out := schema.Output{Expect: schema.Expectation{Volume: "Selected"}}
	diffs, err := (&Verifier{}).compareEditedVolumes(got, corpus.Case{Observation: want}, out, CompareOptions{IgnoreTimes: map[string]bool{"change": true}})
	if err != nil || len(diffs) != 1 || !strings.HasPrefix(diffs[0].Path, "Peer:") {
		t.Fatalf("peer change was relaxed with the selected volume: %v %v", diffs, err)
	}
	ref := schema.CaseRef{Producer: 15, Recipe: "container-volumes", Profile: "apfs", Stage: "final"}
	v := &Verifier{Cases: map[string]corpus.Case{CaseKey(ref): {Observation: want}}}
	out.Source, out.Expect.Volume = ref, "absent"
	if _, _, err := v.expectedView(out); err == nil {
		t.Fatal("unknown selected volume fell back to volume zero")
	}
}
