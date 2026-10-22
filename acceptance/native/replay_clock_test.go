package native

import (
	"encoding/json"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func multiVolumeReplayClockControl(t *testing.T) (*Verifier, *schema.Observation, *schema.Observation, schema.Output) {
	t.Helper()
	before := &schema.Observation{}
	for i, name := range []string{"Primary", "Secondary", "Third"} {
		before.Volumes = append(before.Volumes, schema.Volume{Index: i, Diskutil: map[string]any{"VolumeName": name}})
		view := schema.View{Volume: i}
		for _, named := range []struct {
			path string
			id   uint64
		}{{"Fixture", 18}, {"Fixture/data", 19}, {"Fixture/alias", 19}, {"Fixture/mode", 24}, {"Fixture/untouched", 25}} {
			e := entry(named.path, named.id)
			if named.path == "Fixture" {
				e.Kind, e.Links = "dir", 0
			} else if named.id == 19 {
				e.Links = 2
			}
			base := replayCommandClock + int64(100+i*10)
			e.Times = schema.Times{Birth: base, Modify: base + 1, Change: base + 2, Access: base + 3}
			view.Entries = append(view.Entries, e)
		}
		before.Views = append(before.Views, view)
	}
	want := cloneObservation(t, before)
	const pinnedModify = replayCommandClock - 50
	for i := range want.Views[1].Entries {
		e := &want.Views[1].Entries[i]
		switch e.Path {
		case "Fixture":
			e.Times.Modify, e.Times.Change = replayCommandClock+1000, replayCommandClock+1000
		case "Fixture/data", "Fixture/alias":
			e.SHA256, e.Links = "written bytes", 3
			e.Times.Modify, e.Times.Change = pinnedModify, replayCommandClock+1000
		case "Fixture/mode":
			e.Path, e.NameBytes = "Fixture/renamed", "72656e616d6564"
			e.Times.Change = replayCommandClock + 1000
		}
	}
	alias := want.Views[1].Entries[1]
	alias.Path, alias.NameBytes = "Fixture/another-alias", "616e6f746865722d616c696173"
	created := entry("Fixture/created", 37)
	created.Kind, created.Links = "dir", 0
	created.Times = schema.Times{Birth: replayCommandClock + 1000, Modify: replayCommandClock + 1000, Change: replayCommandClock + 1000, Access: replayCommandClock + 1000}
	want.Views[1].Entries = append(want.Views[1].Entries, alias, created)
	want.Views[2].Entries[1].Mode, want.Views[2].Entries[2].Mode = 0o600, 0o600
	want.Views[2].Entries[1].Times.Change, want.Views[2].Entries[2].Times.Change = replayCommandClock+1000, replayCommandClock+1000
	got := cloneObservation(t, want)
	for i := range got.Views[1].Entries {
		e := &got.Views[1].Entries[i]
		switch e.Path {
		case "Fixture":
			e.Times.Modify, e.Times.Change = replayCommandClock, replayCommandClock
		case "Fixture/data", "Fixture/alias", "Fixture/another-alias":
			e.Times.Birth, e.Times.Change = pinnedModify, replayCommandClock
		case "Fixture/renamed":
			e.Times.Change = replayCommandClock
		case "Fixture/created":
			e.Times = schema.Times{Birth: replayCommandClock, Modify: replayCommandClock, Change: replayCommandClock, Access: replayCommandClock}
		}
	}
	got.Views[2].Entries[1].Times.Change, got.Views[2].Entries[2].Times.Change = replayCommandClock, replayCommandClock
	ref := schema.CaseRef{Producer: 15, Recipe: "apfs-container-geometry", Profile: "apfs", Stage: "source"}
	out := schema.Output{Operation: "edit", Source: ref, Expect: schema.Expectation{View: "edited", NewIdentities: true}}
	v := &Verifier{Cases: map[string]corpus.Case{CaseKey(ref): {Observation: before}}, Recipes: map[string]schema.Recipe{ref.Recipe: {Stages: []schema.Stage{
		{Name: "source"}, {Name: "edited", Steps: []schema.Step{
			{FS: &schema.FSStep{Op: "write", Path: "$MOUNT:Secondary/Fixture/alias"}},
			{FS: &schema.FSStep{Op: "settimes", Path: "$MOUNT:Secondary/Fixture/alias", Times: &schema.TimeSpec{Modify: pinnedModify}}},
			{FS: &schema.FSStep{Op: "mkdir", Path: "$MOUNT:Secondary/Fixture/created"}},
			{FS: &schema.FSStep{Op: "rename", Path: "$MOUNT:Secondary/Fixture/mode", Target: "$MOUNT:Secondary/Fixture/renamed"}},
			{Tool: &schema.ToolStep{Program: "ln", Args: []string{"$MOUNT:Secondary/Fixture/data", "$MOUNT:Secondary/Fixture/another-alias"}, Expect: "0"}},
			{FS: &schema.FSStep{Op: "chmod", Path: "$MOUNT:Third/Fixture/data", Mode: 0o600}},
			{FS: &schema.FSStep{Op: "chmod", Path: "$MOUNT:Primary/Fixture/data", Mode: 0o600}, Only: []string{"apfsx"}},
		}},
	}}}}
	return v, want, got, out
}

func TestReplayClocksFollowEveryEditedVolumeAndPreserveUntouchedPeers(t *testing.T) {
	v, want, got, out := multiVolumeReplayClockControl(t)
	before, _ := json.Marshal(want)
	// The old output contract declares variable command times. Multi-volume
	// projection must still check exact clocks, rather than spread this mask
	// to all volumes or all entries in either edited volume.
	opts := CompareOptions{IgnoreTimes: map[string]bool{"birth": true, "modify": true, "change": true, "access": true}}
	if diffs, err := v.compareEditedVolumes(got, corpus.Case{Observation: want}, out, opts); err != nil || len(diffs) != 0 {
		t.Fatalf("correctly replayed independent peers differ: %v %v", diffs, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*schema.Observation)
	}{
		{"untouched primary clock", func(o *schema.Observation) { o.Views[0].Entries[1].Times.Change++ }},
		{"untouched entry on edited peer", func(o *schema.Observation) { o.Views[1].Entries[4].Times.Change++ }},
		{"wrong edited peer command clock", func(o *schema.Observation) { o.Views[2].Entries[1].Times.Change++ }},
		{"wrong pinned modification clock", func(o *schema.Observation) { o.Views[1].Entries[1].Times.Modify++ }},
		{"alias failed birth clipping", func(o *schema.Observation) { o.Views[1].Entries[2].Times.Birth++ }},
		{"created directory wrong access clock", func(o *schema.Observation) { o.Views[1].Entries[6].Times.Access++ }},
		{"untouched peer content", func(o *schema.Observation) { o.Views[0].Entries[1].SHA256 = "wrong" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := cloneObservation(t, got)
			tc.change(changed)
			if diffs, err := v.compareEditedVolumes(changed, corpus.Case{Observation: want}, out, opts); err != nil || len(diffs) == 0 {
				t.Fatalf("changed peer metadata must remain an exact difference: %v %v", diffs, err)
			}
		})
	}
	after, _ := json.Marshal(want)
	if string(before) != string(after) {
		t.Fatal("replay clock projection changed the retained native observation")
	}
}

func TestReplayClockProjectionRequiresTheDeclaredNativeCommands(t *testing.T) {
	for _, fault := range []string{"wrong source stage", "missing recipe", "unknown volume", "unsupported command", "unnamed target volume", "rename into source subtree"} {
		t.Run(fault, func(t *testing.T) {
			v, want, _, out := multiVolumeReplayClockControl(t)
			recipe := v.Recipes[out.Source.Recipe]
			switch fault {
			case "wrong source stage":
				recipe.Stages[1].From = "different"
			case "missing recipe":
				delete(v.Recipes, out.Source.Recipe)
			case "unknown volume":
				recipe.Stages[1].Steps[0].FS.Path = "$MOUNT:absent/Fixture/alias"
			case "unsupported command":
				recipe.Stages[1].Steps[0].FS.Op = "clone"
			case "unnamed target volume":
				recipe.Stages[1].Steps[0].FS.Path = "$MOUNT/Fixture/alias"
			case "rename into source subtree":
				recipe.Stages[1].Steps[3].FS.Target = "$MOUNT:Secondary/Fixture/mode/descendant"
			}
			if fault != "missing recipe" {
				v.Recipes[out.Source.Recipe] = recipe
			}
			if _, err := v.replayClockViews(out, want); err == nil {
				t.Fatal("undeclared replay policy changed expected clocks")
			}
		})
	}
}
