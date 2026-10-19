//go:build slow

package acceptance_test

// The 119,000-file catalog growth takes minutes per profile, so it runs in
// the separate slow job: go test -tags slow -run 'TestGoEditsReproduceAppleStageStates/.*/hfs-catalog-map-growth'.
func init() {
	replayedRecipes["hfs-catalog-map-growth"] = true
}
