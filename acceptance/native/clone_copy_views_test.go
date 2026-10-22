package native

import (
	"slices"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func cloneCopyClockFixture(t *testing.T) (*Verifier, schema.Output, *schema.Observation) {
	t.Helper()
	stages := []string{"before", "copied", "data-replaced", "fork-replaced", "attribute-replaced", "source-removed", "refused"}
	volume := schema.Volume{Index: 0, Diskutil: map[string]any{"VolumeName": "Primary"}}
	before := schema.View{Entries: []schema.Entry{editedClockEntry("Fixture", "dir", 1), editedClockEntry("Fixture/source", "file", 2)}}
	after := schema.View{Entries: append(slices.Clone(before.Entries), editedClockEntry("Fixture/clone", "file", 10))}
	v := &Verifier{Cases: map[string]corpus.Case{}, Recipes: map[string]schema.Recipe{}}
	var views []schema.View
	recipe := schema.Recipe{Name: "clone-copy"}
	for i, stage := range stages {
		view := before
		if i > 0 {
			view = after
		}
		views = append(views, view)
		ref := schema.CaseRef{Producer: 15, Recipe: recipe.Name, Profile: "apfs", Stage: stage}
		v.Cases[CaseKey(ref)] = corpus.Case{Producer: 15, Recipe: recipe.Name, Profile: "apfs", Stage: stage, Observation: &schema.Observation{Volumes: []schema.Volume{volume}, Views: []schema.View{view}}}
		recipe.Stages = append(recipe.Stages, schema.Stage{Name: stage})
	}
	recipe.Stages[1].Steps = []schema.Step{cloneClockTool("-c", "Fixture/source", "Fixture/clone", "0")}
	v.Recipes[recipe.Name] = recipe
	clock, err := CloneCopyCommandClock(views)
	if err != nil {
		t.Fatal(err)
	}
	out := schema.Output{Operation: "edit", Source: schema.CaseRef{Producer: 15, Recipe: recipe.Name, Profile: "apfs", Stage: "before"}, Expect: schema.Expectation{View: "copied", NewIdentities: true, CommandClockNS: clock}}
	return v, out, &schema.Observation{Volumes: []schema.Volume{volume}, Views: []schema.View{after}}
}

func TestCloneCopyOutputClockBindsEveryNativeStageAndDeclaredEffects(t *testing.T) {
	v, out, target := cloneCopyClockFixture(t)
	for _, operation := range []string{"edit", "build"} {
		out.Operation = operation
		view, err := v.cloneCopyClockView(out, target)
		if err != nil || view.Entries[2].Times.Change != out.Expect.CommandClockNS || view.Entries[2].Times.Birth != 1 || view.Entries[1].Times != target.Views[0].Entries[1].Times {
			t.Fatal("clone-copy replay clock lost command or preserved source clocks", err, view)
		}
	}
	for name, corrupt := range map[string]func(*Verifier, *schema.Output){
		"clock omitted":  func(_ *Verifier, o *schema.Output) { o.Expect.CommandClockNS = 0 },
		"clock unbound":  func(_ *Verifier, o *schema.Output) { o.Expect.CommandClockNS += 1_000_000_000 },
		"ignored clocks": func(_ *Verifier, o *schema.Output) { o.Expect.IgnoreTimes = []string{"change"} },
		"workspace diverted": func(_ *Verifier, o *schema.Output) {
			o.Expect.Workspace = &schema.WorkspaceExpectation{Policy: "commands"}
		},
		"wrong source": func(_ *Verifier, o *schema.Output) { o.Source.Stage = "copied" },
		"missing final control": func(v *Verifier, o *schema.Output) {
			ref := o.Source
			ref.Stage = "refused"
			delete(v.Cases, CaseKey(ref))
		},
		"undeclared prerequisite": func(v *Verifier, o *schema.Output) {
			r := v.Recipes[o.Source.Recipe]
			r.Stages[1].From = "source-removed"
			v.Recipes[o.Source.Recipe] = r
		},
	} {
		t.Run(name, func(t *testing.T) {
			v, out, target := cloneCopyClockFixture(t)
			corrupt(v, &out)
			if _, err := v.cloneCopyClockView(out, target); err == nil {
				t.Fatal("unbound clone-copy clock accepted")
			}
		})
	}
}

func TestCloneCopyReplacementRetainsOnlySurvivingIdentitiesAndExactAliases(t *testing.T) {
	before := schema.View{Entries: []schema.Entry{entry("old", 1), entry("overwrite", 2), entry("old-alias", 2)}}
	after := schema.View{Entries: []schema.Entry{entry("old", 1), entry("overwrite", 3), entry("old-alias", 2), entry("new-alias", 3)}}
	existing := retainedCloneCopyIdentities(before, after)
	if !existing["old"] || !existing["old-alias"] || existing["overwrite"] || existing["new-alias"] {
		t.Fatal("replaced destination incorrectly retains old inode requirement", existing)
	}
	got := schema.View{Entries: slices.Clone(after.Entries)}
	got.Entries[1].ID, got.Entries[3].ID = 10, 10
	if diffs := CompareViews(got, after, CompareOptions{Existing: existing}); len(diffs) != 0 {
		t.Fatal("independent allocator identities refused", diffs)
	}
	got.Entries[3].ID = 11
	if diffs := CompareViews(got, after, CompareOptions{Existing: existing}); len(diffs) != 1 || diffs[0].Field != "identity.aliases" {
		t.Fatal("new hard-link class flattened", diffs)
	}
	got.Entries[3].ID = 1
	if diffs := CompareViews(got, after, CompareOptions{Existing: existing}); len(diffs) < 1 {
		t.Fatal("clone incorrectly merged into independent source inode")
	}
}
