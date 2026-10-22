package native

import (
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func encryptedClockFixture() (*Verifier, schema.Output, *schema.Observation) {
	ref := schema.CaseRef{Producer: 15, Recipe: "encrypted-image-edits", Profile: "apfs", Stage: "before-aes128"}
	volume := schema.Volume{Index: 0, Diskutil: map[string]any{"VolumeName": "Primary"}}
	view := schema.View{Entries: []schema.Entry{editedClockEntry("Fixture", "dir", 1), editedClockEntry("Fixture/file", "file", 2), editedClockEntry("Fixture/untouched", "file", 3)}}
	source := corpus.Case{Producer: ref.Producer, Recipe: ref.Recipe, Profile: ref.Profile, Stage: ref.Stage, Observation: &schema.Observation{Volumes: []schema.Volume{volume}, Views: []schema.View{view}}}
	recipe := schema.Recipe{Stages: []schema.Stage{{Name: "before"}, {Name: "after", Steps: []schema.Step{editedClockStep("write", "Fixture/file")}}}, Derive: []schema.Derivation{{Name: "before-aes128", From: "before"}, {Name: "after-aes128", From: "after"}}}
	v := &Verifier{Cases: map[string]corpus.Case{CaseKey(ref): source}, Recipes: map[string]schema.Recipe{ref.Recipe: recipe}}
	out := schema.Output{Operation: "edit", Source: ref, Expect: schema.Expectation{View: "after-aes128", NewIdentities: true}}
	return v, out, &schema.Observation{Volumes: []schema.Volume{volume}, Views: []schema.View{view}}
}

func TestEncryptedDerivationsRetainTheDeclaredEditClockAndUntouchedClocks(t *testing.T) {
	v, out, target := encryptedClockFixture()
	projected, err := v.replayClockViews(out, target)
	if err != nil {
		t.Fatal(err)
	}
	view := projected["Primary"]
	if view.Entries[1].Times.Modify != replayCommandClock || view.Entries[1].Times.Change != replayCommandClock || view.Entries[1].Times.Birth != 1 || view.Entries[1].Times.Access != 4 {
		t.Fatal("edit operation did not retain its precise clock contract", view.Entries[1].Times)
	}
	if view.Entries[2].Times != target.Views[0].Entries[2].Times || target.Views[0].Entries[1].Times.Modify != 50 {
		t.Fatal("untouched clocks or original native target were changed")
	}
}

func TestImageEditClockBindingsRefuseMissingOrMismatchedNativeStages(t *testing.T) {
	for name, corrupt := range map[string]func(*Verifier, *schema.Output){
		"missing before":          func(v *Verifier, out *schema.Output) { delete(v.Cases, CaseKey(out.Source)) },
		"unknown target":          func(_ *Verifier, out *schema.Output) { out.Expect.View = "missing" },
		"ignored timestamps":      func(_ *Verifier, out *schema.Output) { out.Expect.IgnoreTimes = []string{"modify"} },
		"missing identity policy": func(_ *Verifier, out *schema.Output) { out.Expect.NewIdentities = false },
		"wrong prerequisite": func(v *Verifier, out *schema.Output) {
			recipe := v.Recipes[out.Source.Recipe]
			recipe.Stages[1].From = "unrelated"
			v.Recipes[out.Source.Recipe] = recipe
		},
		"cyclic derivation": func(v *Verifier, out *schema.Output) {
			recipe := v.Recipes[out.Source.Recipe]
			recipe.Derive[0].From = "before-aes128"
			v.Recipes[out.Source.Recipe] = recipe
		},
	} {
		t.Run(name, func(t *testing.T) {
			v, out, target := encryptedClockFixture()
			corrupt(v, &out)
			if _, err := v.replayClockViews(out, target); err == nil {
				t.Fatal("unbound image-edit clock expectation was accepted")
			}
		})
	}
}
