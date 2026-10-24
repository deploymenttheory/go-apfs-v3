package native

import (
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func snapshotEditingControl() *schema.Observation {
	live := schema.View{Entries: []schema.Entry{
		{Path: "Fixture", ID: 16, Kind: "dir", Times: schema.Times{Birth: 1, Modify: 2, Change: 3, Access: 4}},
		{Path: "Fixture/hard-link", ID: 17, Kind: "file", Times: schema.Times{Birth: 1, Modify: 2, Change: 3, Access: 4}},
		{Path: "Fixture/example.txt", ID: 17, Kind: "file", Times: schema.Times{Birth: 1, Modify: 2, Change: 3, Access: 4}},
		{Path: "Fixture/clone.bin", ID: 18, Kind: "file", Times: schema.Times{Birth: 1, Modify: 2, Change: 3, Access: 4}},
		{Path: "Fixture/untouched", ID: 19, Kind: "file", Times: schema.Times{Birth: 1, Modify: 2, Change: 3, Access: 4}},
	}}
	return &schema.Observation{Volumes: []schema.Volume{{Diskutil: map[string]any{"VolumeName": "History"}, APFS: &schema.APFSVolume{Snapshots: []schema.Snapshot{{Name: "before", XID: 10}, {Name: "after", XID: 20}}}}}, Views: []schema.View{live, {Snapshot: "before"}, {Snapshot: "after"}}}
}

func TestSnapshotEditClockProjectionPreservesUnchangedClocksAndAliases(t *testing.T) {
	before := snapshotEditingControl().Views[0]
	unchanged := before.Entries[4]
	projected, err := SnapshotEditClocks(before, "apfs", replayCommandClock)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(projected.Entries[4], unchanged) || before.Entries[1].Times.Modify != 2 {
		t.Fatal("clock projection changed its original observation or an untouched inode")
	}
	for _, index := range []int{0, 1, 2, 3} {
		got := projected.Entries[index].Times
		if got.Birth != 1 || got.Access != 4 || got.Modify != replayCommandClock || got.Change != replayCommandClock {
			t.Fatalf("declared live write lost preserved clocks at %d: %+v", index, got)
		}
	}
}

func TestSnapshotEditOutputsRequireBothProfilesAndSuccessfulContinuation(t *testing.T) {
	cases := map[string]corpus.Case{}
	var pairs []Paired
	for _, profile := range []string{"apfs", "apfsx"} {
		ref := schema.CaseRef{Producer: 26, Recipe: "snapshot-history", Profile: profile, Stage: "live"}
		cases[CaseKey(ref)] = corpus.Case{Observation: snapshotEditingControl()}
		pairs = append(pairs, Paired{Output: schema.Output{Source: ref, Operation: "edit", Format: "UDZO", Expect: schema.Expectation{CommandClockNS: replayCommandClock, Continuation: true}}})
	}
	if err := requireSnapshotEditOutputs(pairs, cases, 26); err != nil {
		t.Fatal(err)
	}
	for _, candidates := range [][]Paired{nil, pairs[:1], append(append([]Paired(nil), pairs...), pairs[0])} {
		if err := requireSnapshotEditOutputs(candidates, cases, 26); err == nil {
			t.Fatal("missing or duplicated retained-history capability escaped its gate")
		}
	}
	for _, change := range []func(*schema.Output){
		func(out *schema.Output) { out.Expect.IgnoreTimes = []string{"change"} },
		func(out *schema.Output) { out.Expect.Continuation = false },
		func(out *schema.Output) { out.Expect.ContinuationRefusal = "unsupported" },
		func(out *schema.Output) { out.Expect.CommandClockNS++ },
		func(out *schema.Output) { out.Source.Stage = "api-probe" },
		func(out *schema.Output) { out.Expect.Workspace = &schema.WorkspaceExpectation{Policy: "preserve"} },
		func(out *schema.Output) {
			out.Expect.Container = &schema.ContainerExpectation{CapacityBytes: 128 << 20}
		},
		func(out *schema.Output) { out.Source.Profile = "hfsplus" },
	} {
		candidate := append([]Paired(nil), pairs...)
		change(&candidate[0].Output)
		if err := requireSnapshotEditOutputs(candidate, cases, 26); err == nil {
			t.Fatal("weakened snapshot edit escaped its native contract")
		}
	}
	ref := schema.CaseRef{Producer: 26, Recipe: "snapshot-history", Profile: "apfs", Stage: "live"}
	missing := cloneObservation(t, cases[CaseKey(ref)].Observation)
	missing.Views = missing.Views[:2]
	cases[CaseKey(ref)] = corpus.Case{Observation: missing}
	if err := requireSnapshotEditOutputs(pairs, cases, 26); err == nil {
		t.Fatal("snapshot editing accepted a missing independent historical view")
	}
}

func TestContinuedHistoricalViewsRequireContentsForksMetadataAndIdentity(t *testing.T) {
	before, after := continuedObservations()
	history := schema.View{Snapshot: "retained", Entries: []schema.Entry{{Path: "Fixture/past", ID: 41, Kind: "file", Links: 1, Size: 3, SHA256: "native-content", ACL: "native-acl", Xattrs: []schema.Xattr{{Name: "com.apple.ResourceFork", Bytes: 7, SHA256: "native-fork"}}}}}
	before.Views = append(before.Views, history)
	after.Views = append(after.Views, history)
	if err := compareContinuedContainer(before, after, "Reserved"); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*schema.View){
		func(view *schema.View) { view.Entries[0].SHA256 = "changed" },
		func(view *schema.View) { view.Entries[0].Xattrs[0].SHA256 = "changed" },
		func(view *schema.View) { view.Entries[0].ACL = "changed" },
		func(view *schema.View) { view.Entries[0].ID++ },
		func(view *schema.View) { view.Entries[0].Times.Modify++ },
		func(view *schema.View) { view.Snapshot = "different" },
	} {
		changed := cloneObservation(t, after)
		mutate(&changed.Views[len(changed.Views)-1])
		if reflect.DeepEqual(changed, after) || compareContinuedContainer(before, changed, "Reserved") == nil {
			t.Fatal("a historical mutation escaped native continuation verification")
		}
	}
}
