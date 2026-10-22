package native

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// singleVolumeEditClocks binds a new feature's declared operation clock to its
// native before/after states, including encrypted derivations of those states.
func (v *Verifier) singleVolumeEditClocks(out schema.Output, target *schema.Observation) (map[string]schema.View, error) {
	if out.Operation != "edit" {
		return nil, nil
	}
	if !out.Expect.NewIdentities || out.Expect.View == "" || len(out.Expect.IgnoreTimes) != 0 || target == nil || len(target.Volumes) != 1 {
		return nil, fmt.Errorf("image edit lacks a strict single-volume clock expectation")
	}
	source, ok := v.Cases[CaseKey(out.Source)]
	if !ok || source.Observation == nil || len(source.Observation.Volumes) != 1 {
		return nil, fmt.Errorf("image edit lacks its independent native before-state")
	}
	recipe, ok := v.Recipes[out.Source.Recipe]
	if !ok {
		return nil, fmt.Errorf("image edit lacks its command recipe")
	}
	from, err := clockBaseStage(recipe, out.Source.Stage)
	if err != nil {
		return nil, err
	}
	to, err := clockBaseStage(recipe, out.Expect.View)
	if err != nil {
		return nil, err
	}
	var steps []schema.Step
	found := false
	for i, stage := range recipe.Stages {
		if stage.Name != to {
			continue
		}
		if found || i == 0 {
			return nil, fmt.Errorf("image edit has an ambiguous target stage %q", to)
		}
		previous := stage.From
		if previous == "" {
			previous = recipe.Stages[i-1].Name
		}
		if previous != from {
			return nil, fmt.Errorf("image edit stage %q starts from %q, expected %q", to, previous, from)
		}
		steps, found = stage.Steps, true
	}
	if !found {
		return nil, fmt.Errorf("image edit has no native target stage %q", to)
	}
	before, err := observedView(source.Observation, source.Observation.Volumes[0].Index, "")
	if err != nil {
		return nil, err
	}
	after, err := observedView(target, target.Volumes[0].Index, "")
	if err != nil {
		return nil, err
	}
	if volumeName(source.Observation.Volumes[0]) != volumeName(target.Volumes[0]) {
		return nil, fmt.Errorf("image edit changed the selected volume identity")
	}
	projected, err := ProjectEditedViewClocks(before, after, steps, out.Source.Profile, replayCommandClock)
	if err != nil {
		return nil, err
	}
	return map[string]schema.View{volumeName(target.Volumes[0]): projected}, nil
}

func clockBaseStage(recipe schema.Recipe, name string) (string, error) {
	seen := map[string]bool{}
	for {
		if seen[name] {
			return "", fmt.Errorf("cyclic image derivation at %q", name)
		}
		seen[name] = true
		for _, stage := range recipe.Stages {
			if stage.Name == name {
				return name, nil
			}
		}
		from := ""
		for _, derive := range recipe.Derive {
			if derive.Name == name {
				if from != "" {
					return "", fmt.Errorf("ambiguous image derivation %q", name)
				}
				from = derive.From
			}
		}
		if from == "" {
			return "", fmt.Errorf("missing native image stage %q", name)
		}
		name = from
	}
}
