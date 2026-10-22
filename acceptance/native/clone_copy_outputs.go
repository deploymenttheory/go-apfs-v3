package native

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// requireCloneCopyOutputs closes the copy and reopened-session capability
// matrix independently of the names supplied by portable producers. Pairing
// checks every host; this check also catches omissions shared by all hosts.
func requireCloneCopyOutputs(pairs []Paired, cases map[string]corpus.Case, major int) error {
	profiles := []string{"apfs", "apfsx", "hfsplus", "hfsx"}
	stages := []string{"before", "copied", "data-replaced", "fork-replaced", "attribute-replaced", "source-removed", "refused"}
	for _, k := range cases {
		if k.Producer == major && k.Recipe == "clone-copy" && (!slices.Contains(profiles, k.Profile) || !slices.Contains(stages, k.Stage)) {
			return fmt.Errorf("unqualified native clone-copy control %s/%s", k.Profile, k.Stage)
		}
	}
	type outputKey struct{ profile, stage, operation, format string }
	wanted := map[outputKey]bool{}
	for _, profile := range profiles {
		for i, stage := range stages {
			ref := schema.CaseRef{Producer: major, Recipe: "clone-copy", Profile: profile, Stage: stage}
			if _, exists := cases[CaseKey(ref)]; !exists {
				return fmt.Errorf("missing native clone-copy control %s", CaseKey(ref))
			}
			if i == 0 {
				continue
			}
			for _, format := range []string{"UDRO", "UDZO"} {
				wanted[outputKey{profile, stage, "edit", format}] = false
			}
			wanted[outputKey{profile, stage, "build", "UDZO"}] = false
		}
	}
	for _, pair := range pairs {
		out := pair.Output
		if out.Source.Producer != major || out.Source.Recipe != "clone-copy" || out.Operation != "edit" && out.Operation != "build" {
			continue
		}
		key := outputKey{out.Source.Profile, out.Expect.View, out.Operation, out.Format}
		seen, exists := wanted[key]
		if !exists || seen {
			return fmt.Errorf("unexpected or duplicate clone-copy output %s: %+v", out.Name, key)
		}
		index := slices.Index(stages, out.Expect.View)
		sourceStage := stages[index-1]
		expect := schema.Expectation{
			View: out.Expect.View, NewIdentities: true,
			CommandClockNS: out.Expect.CommandClockNS,
			Continuation:   out.Expect.View == "refused" && out.Format == "UDZO",
		}
		if out.Operation == "build" {
			sourceStage, expect.Subtree = "before", "Fixture"
		}
		// The verifier independently binds this clock to all captured stages;
		// producers cannot opt out of that comparison or any preservation field.
		if out.Source.Stage != sourceStage || out.Encrypted || out.Password != "" || expect.CommandClockNS <= 0 || expect.CommandClockNS%1_000_000_000 != 0 || !reflect.DeepEqual(out.Expect, expect) {
			return fmt.Errorf("clone-copy output %s lost its exact source, command-clock or continuation policy", out.Name)
		}
		wanted[key] = true
	}
	for key, seen := range wanted {
		if !seen {
			return fmt.Errorf("missing clone-copy output for macOS %d: %+v", major, key)
		}
	}
	return nil
}
