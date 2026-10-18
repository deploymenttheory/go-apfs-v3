package acceptance_test

import (
	"strconv"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// A recipe change must be followed by a fresh capture and a reviewed lock
// update. Comparing the tree digest here means a recipe cannot drift away
// from the corpus the tests actually run against.
func TestLockPinsTheRecipesInTheTree(t *testing.T) {
	lock, err := schema.ReadLock("fixtures.lock.json")
	if err != nil {
		t.Fatal(err)
	}
	digest, err := schema.TreeDigest("recipes")
	if err != nil {
		t.Fatal(err)
	}
	if lock.RecipesSHA256 != digest {
		t.Fatalf("fixtures.lock.json pins recipes %s but the tree hashes to %s; recapture the corpus and update the lock", lock.RecipesSHA256, digest)
	}
	for _, major := range schema.Producers {
		key := "macos-" + strconv.Itoa(major)
		if len(lock.Bundles) > 0 {
			if _, ok := lock.Bundles[key]; !ok {
				t.Errorf("lock pins bundles but not %s; every producer is required", key)
			}
		}
	}
}
