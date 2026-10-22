package native

import (
	"fmt"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestReopenedAndHistoricalPreservationOutputsCannotDisappear(t *testing.T) {
	cases := map[string]corpus.Case{}
	var pairs []Paired
	for _, profile := range []string{"apfs", "apfsx", "hfsplus", "hfsx"} {
		ref := schema.CaseRef{Producer: 15, Recipe: "file-corpus", Profile: profile, Stage: "final"}
		cases[CaseKey(ref)] = corpus.Case{Observation: &schema.Observation{}}
		pairs = append(pairs, Paired{Output: schema.Output{Name: profile + ".build.session.UDZO.dmg", Operation: "build", Format: "UDZO", Source: ref, Expect: schema.Expectation{Subtree: "Fixture"}}})
	}
	for _, profile := range []string{"apfs", "apfsx"} {
		ref := schema.CaseRef{Producer: 15, Recipe: "snapshot-history", Profile: profile, Stage: "live"}
		obs := &schema.Observation{}
		for i := range 2 {
			name := fmt.Sprintf("native-%d", i)
			obs.Views = append(obs.Views, schema.View{Snapshot: name})
			pairs = append(pairs, Paired{Output: schema.Output{Operation: "workspace-snapshot", Format: "workspace", Source: ref, Expect: schema.Expectation{Snapshot: name, Subtree: "Fixture", Workspace: &schema.WorkspaceExpectation{Policy: "preserve"}}}})
		}
		cases[CaseKey(ref)] = corpus.Case{Observation: obs}
	}
	if err := requirePreservationSourceOutputs(pairs, cases, 15); err != nil {
		t.Fatal(err)
	}
	for i := range pairs {
		remaining := append([]Paired(nil), pairs[:i]...)
		remaining = append(remaining, pairs[i+1:]...)
		if err := requirePreservationSourceOutputs(remaining, cases, 15); err == nil {
			t.Errorf("all-host omission %d escaped verification", i)
		}
	}
	if expectationsEqual(schema.Expectation{Snapshot: "first"}, schema.Expectation{Snapshot: "second"}) {
		t.Fatal("different historical views paired across hosts")
	}
}
