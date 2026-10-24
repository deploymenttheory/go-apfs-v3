package native

import (
	"fmt"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// Keep this dense measurement scope identical to the frozen clone-copy recipe.
// Compressed and sparse logical bytes/forks/metadata are still fully compared;
// Apple's F_LOG2PHYS_EXT cannot measure those shapes through this adapter.
func cloneCopyExtentPaths(subtree string) []string {
	paths := []string{
		"Fixture/source", "Fixture/clone", "Fixture/clone-alias", "Fixture/preserved",
		"Fixture/overwrite", "Fixture/overwrite-alias", "Fixture/destination-link",
		"Fixture/followed", "Fixture/equal-independent", "Fixture/tree/nested/leaf",
		"Fixture/tree/nested/alias", "Fixture/copied-tree/nested/leaf", "Fixture/copied-tree/nested/alias",
	}
	if subtree != "" {
		for i := range paths {
			paths[i] = strings.TrimPrefix(paths[i], subtree+"/")
		}
	}
	return paths
}

func cloneCopyPhysicalForks(view schema.View, paths []string) (map[string][][3]int64, error) {
	selected := map[string]bool{}
	for _, path := range paths {
		selected[path] = true
	}
	forks := map[string][][3]int64{}
	seen := map[string]bool{}
	for _, entry := range view.Entries {
		if !selected[entry.Path] {
			continue
		}
		if seen[entry.Path] {
			return nil, fmt.Errorf("duplicate clone-copy physical path %q", entry.Path)
		}
		seen[entry.Path] = true
		if entry.Kind != "file" {
			continue // Before copying, destination-link is a symlink.
		}
		if entry.Extents == nil {
			return nil, fmt.Errorf("clone-copy dense file %q lacks native physical evidence", entry.Path)
		}
		if err := validatePhysicalRuns(entry.Extents.Data, entry.Size); err != nil {
			return nil, fmt.Errorf("%s data: %w", entry.Path, err)
		}
		var resource int64
		for _, attribute := range entry.Xattrs {
			if attribute.Name == "com.apple.ResourceFork" {
				resource = attribute.Bytes
			}
		}
		if err := validatePhysicalRuns(entry.Extents.Resource, resource); err != nil {
			return nil, fmt.Errorf("%s resource: %w", entry.Path, err)
		}
		forks[entry.Path+"/data"], forks[entry.Path+"/resource"] = entry.Extents.Data, entry.Extents.Resource
	}
	if len(forks) == 0 {
		return nil, fmt.Errorf("clone-copy view has no dense native measurements")
	}
	return forks, nil
}

// cloneCopyOutputDifferences compares the complete relation graph, including
// the equal-byte independent negative and data/fork-only detachment. Addresses
// can differ across images; every measured shared-byte relationship must match.
func cloneCopyOutputDifferences(observed *schema.Observation, want schema.View, subtree string) ([]Difference, error) {
	actualView, err := onlyLiveView(observed)
	if err != nil {
		return nil, err
	}
	expected, err := cloneCopyPhysicalForks(want, cloneCopyExtentPaths(""))
	if err != nil {
		return nil, fmt.Errorf("retained clone-copy evidence: %w", err)
	}
	actual, err := cloneCopyPhysicalForks(actualView, cloneCopyExtentPaths(subtree))
	if err != nil {
		return nil, fmt.Errorf("output clone-copy evidence: %w", err)
	}
	var names []string
	projected := map[string][][3]int64{}
	for name, runs := range expected {
		if subtree != "" {
			name = strings.TrimPrefix(name, subtree+"/")
		}
		projected[name] = runs
		if _, ok := actual[name]; !ok {
			return nil, fmt.Errorf("clone-copy output lacks measured fork %q", name)
		}
		names = append(names, name)
	}
	if len(projected) != len(actual) {
		return nil, fmt.Errorf("clone-copy physical fork inventory differs")
	}
	sort.Strings(names)
	var differences []Difference
	for i, first := range names {
		for _, second := range names[i+1:] {
			expectedBytes, actualBytes := sharedPhysicalBytes(projected[first], projected[second]), sharedPhysicalBytes(actual[first], actual[second])
			if actualBytes != expectedBytes {
				differences = append(differences, Difference{Path: first + " <> " + second, Field: "sharedPhysicalBytes", Got: fmt.Sprint(actualBytes), Want: fmt.Sprint(expectedBytes)})
			}
		}
	}
	return differences, nil
}
