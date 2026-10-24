package native

import (
	"fmt"
	"maps"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func cloneCopyOutputInventory(major int) ([]Paired, map[string]corpus.Case) {
	cases := map[string]corpus.Case{}
	var pairs []Paired
	stages := []string{"before", "copied", "data-replaced", "fork-replaced", "attribute-replaced", "source-removed", "refused"}
	for _, profile := range []string{"apfs", "apfsx", "hfsplus", "hfsx"} {
		for index, stage := range stages {
			ref := schema.CaseRef{Producer: major, Recipe: "clone-copy", Profile: profile, Stage: stage}
			cases[CaseKey(ref)] = corpus.Case{Producer: major, Recipe: ref.Recipe, Profile: profile, Stage: stage}
			if index == 0 {
				continue
			}
			for _, operation := range []string{"edit", "build"} {
				for _, format := range []string{"UDRO", "UDZO"} {
					if operation == "build" && format == "UDRO" {
						continue
					}
					out := schema.Output{
						Name: fmt.Sprintf("%d/%s/%s/%s/%s", major, profile, stage, operation, format), Operation: operation, Format: format,
						Source: schema.CaseRef{Producer: major, Recipe: "clone-copy", Profile: profile, Stage: stages[index-1]},
						Expect: schema.Expectation{View: stage, NewIdentities: true, CommandClockNS: 1_800_000_000_000_000_000, Continuation: stage == "refused" && format == "UDZO"},
					}
					if operation == "build" {
						out.Source.Stage, out.Expect.Subtree = "before", "Fixture"
					}
					pairs = append(pairs, Paired{Output: out})
				}
			}
		}
	}
	return pairs, cases
}

func TestCloneCopyQualificationRequiresEveryNativeControlAndOutput(t *testing.T) {
	for _, major := range schema.Producers {
		pairs, cases := cloneCopyOutputInventory(major)
		if len(pairs) != 72 || len(cases) != 28 {
			t.Fatal("invalid independent clone-copy capability inventory")
		}
		if err := requireCloneCopyOutputs(pairs, cases, major); err != nil {
			t.Fatal(err)
		}
		for i := range pairs {
			remaining := append(append([]Paired(nil), pairs[:i]...), pairs[i+1:]...)
			if err := requireCloneCopyOutputs(remaining, cases, major); err == nil {
				t.Fatal("a shared omission disappeared from native qualification", pairs[i].Output.Name)
			}
		}
		for key := range cases {
			remaining := maps.Clone(cases)
			delete(remaining, key)
			if err := requireCloneCopyOutputs(pairs, remaining, major); err == nil {
				t.Fatal("missing native source or target control passed", key)
			}
		}
		if err := requireCloneCopyOutputs(append(pairs, pairs[0]), cases, major); err == nil {
			t.Fatal("duplicate transition passed")
		}
	}
}

func TestCloneCopyQualificationRejectsWeakenedPreservationPolicies(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*schema.Output)
	}{
		{"wrong source", func(out *schema.Output) { out.Source.Stage = "copied" }},
		{"missing clock", func(out *schema.Output) { out.Expect.CommandClockNS = 0 }},
		{"fractional clock", func(out *schema.Output) { out.Expect.CommandClockNS++ }},
		{"ignored clocks", func(out *schema.Output) { out.Expect.IgnoreTimes = []string{"change"} }},
		{"source view", func(out *schema.Output) { out.Expect.View = "before" }},
		{"workspace route", func(out *schema.Output) { out.Expect.Workspace = &schema.WorkspaceExpectation{Policy: "commands"} }},
		{"lost creation identity policy", func(out *schema.Output) { out.Expect.NewIdentities = false }},
		{"unqualified encryption", func(out *schema.Output) { out.Encrypted = true }},
		{"unqualified password", func(out *schema.Output) { out.Password = "output" }},
		{"refused continuation", func(out *schema.Output) { out.Expect.ContinuationRefusal = "unsupported" }},
		{"wrong subtree", func(out *schema.Output) { out.Expect.Subtree = "other" }},
		{"wrong encoding", func(out *schema.Output) { out.Format = "UDBZ" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, index := range []int{0, 2} { // First existing-image and session outputs.
				pairs, cases := cloneCopyOutputInventory(15)
				test.change(&pairs[index].Output)
				if err := requireCloneCopyOutputs(pairs, cases, 15); err == nil {
					t.Fatal("weakened clone-copy expectation passed", pairs[index].Output)
				}
			}
		})
	}
	pairs, cases := cloneCopyOutputInventory(15)
	for i := range pairs {
		if pairs[i].Output.Expect.Continuation {
			changed := append([]Paired(nil), pairs...)
			changed[i].Output.Expect.Continuation = false
			if err := requireCloneCopyOutputs(changed, cases, 15); err == nil {
				t.Fatal("required native continuation was omitted", pairs[i].Output.Name)
			}
		}
	}
}

func TestCloneCopyQualificationRetainsOtherFamiliesAndRejectsUnknownControls(t *testing.T) {
	pairs, cases := cloneCopyOutputInventory(15)
	pairs = append(pairs, Paired{Output: schema.Output{Operation: "repack", Source: schema.CaseRef{Producer: 15, Recipe: "clone-copy", Profile: "apfs", Stage: "before"}}})
	pairs = append(pairs, Paired{Output: schema.Output{Operation: "edit", Source: schema.CaseRef{Producer: 26, Recipe: "clone-copy"}}})
	if err := requireCloneCopyOutputs(pairs, cases, 15); err != nil {
		t.Fatal("clone-copy matrix rejected an independently checked output family", err)
	}
	cases["15/clone-copy/apfs/unknown"] = corpus.Case{Producer: 15, Recipe: "clone-copy", Profile: "apfs", Stage: "unknown"}
	if err := requireCloneCopyOutputs(pairs, cases, 15); err == nil {
		t.Fatal("new native stage passed without a qualified consumer")
	}
}
