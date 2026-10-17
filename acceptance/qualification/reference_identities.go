package main

import (
	"cmp"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
)

type referenceSource struct {
	ID       string `json:"id"`
	Major    int    `json:"source_major"`
	Identity string `json:"source_sha256"`
	Class    string `json:"capture_class"`
}

// Called only after complete reference asset admission. These are the same
// per-source identities used for original replay indexes, not a second digest
// algorithm implemented in the comparison controller.
func referenceSourceIdentities(catalog corpus.Catalog) ([]referenceSource, error) {
	result := []referenceSource{}
	for _, entry := range catalog.Entries {
		class := "apple-independent"
		if slices.ContainsFunc(entry.Bindings, func(binding corpus.Binding) bool { return binding.CaptureClass == "current-go-experiment" }) {
			class = "current-go-experiment"
		}
		for _, major := range []int{15, 26, 27} {
			if !slices.ContainsFunc(entry.Captures, func(capture corpus.Capture) bool { return capture.Major == major }) {
				continue
			}
			identity, err := referenceSourceIdentity(entry, major)
			if err != nil {
				return nil, err
			}
			result = append(result, referenceSource{entry.ID, major, identity, class})
		}
	}
	slices.SortFunc(result, func(a, b referenceSource) int {
		if order := strings.Compare(a.ID, b.ID); order != 0 {
			return order
		}
		return cmp.Compare(a.Major, b.Major)
	})
	return result, nil
}
