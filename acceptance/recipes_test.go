package acceptance_test

import (
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestEveryRecipeInTheTreeIsValid(t *testing.T) {
	recipes, err := schema.LoadRecipes("recipes")
	if err != nil {
		t.Fatal(err)
	}
	for _, recipe := range recipes {
		t.Logf("%s: %d profiles, %d stages, %d derivations", recipe.Name, len(recipe.Profiles), len(recipe.Stages), len(recipe.Derive))
	}
}

func TestKnownDriftNamesExistingRecipes(t *testing.T) {
	drift, err := schema.ReadKnownDrift("known-drift.json")
	if err != nil {
		t.Fatal(err)
	}
	recipes, err := schema.LoadRecipes("recipes")
	if err != nil {
		t.Fatal(err)
	}
	names := map[string]bool{}
	for _, r := range recipes {
		names[r.Name] = true
	}
	for _, entry := range drift.Entries {
		if !names[entry.Recipe] {
			t.Errorf("known drift names recipe %q, which does not exist", entry.Recipe)
		}
	}
}
