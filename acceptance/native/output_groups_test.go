package native

import (
	"fmt"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestNativeOutputGroupsPartitionEveryHostCopy(t *testing.T) {
	var pairs []Paired
	for _, operation := range []string{"build", "repack", "change-password", "create-encrypted"} {
		for _, major := range schema.Producers {
			name := fmt.Sprintf("macos-%d.%s", major, operation)
			out := schema.Output{Name: name, Operation: operation, Encrypted: true}
			pairs = append(pairs, Paired{Name: name, Output: out, ByHost: map[string]schema.Output{"linux": out, "windows": out, "darwin": out}})
		}
	}
	seen := map[string]int{}
	for _, group := range []string{"main", "encrypted-construction"} {
		selected, err := selectNativeOutputs(group, pairs)
		if err != nil || len(selected) == 0 {
			t.Fatalf("%s lost required work: %v", group, err)
		}
		for _, p := range selected {
			if (p.Output.Operation == "create-encrypted") != (group == "encrypted-construction") || len(p.ByHost) != 3 {
				t.Fatalf("%s misrouted %s or lost a host", group, p.Name)
			}
			seen[p.Name]++
		}
	}
	for _, original := range pairs {
		if seen[original.Name] != 1 {
			t.Fatalf("%s was qualified %d times, want exactly once", original.Name, seen[original.Name])
		}
	}
	for _, group := range []string{"", "slow"} {
		all, err := selectNativeOutputs(group, pairs)
		if err != nil || !reflect.DeepEqual(all, pairs) {
			t.Fatalf("%q changed the complete unpartitioned cohort: %v", group, err)
		}
	}
}

func TestNativeOutputGroupsRefuseUnknownAndEmptyWorkloads(t *testing.T) {
	pairs := []Paired{{Output: schema.Output{Operation: "create-encrypted"}}}
	for _, group := range []string{"unknown", "main"} {
		if _, err := selectNativeOutputs(group, pairs); err == nil {
			t.Fatalf("%s accepted an unknown or empty workload", group)
		}
	}
	if _, err := selectNativeOutputs("encrypted-construction", []Paired{{Output: schema.Output{Operation: "repack"}}}); err == nil {
		t.Fatal("missing encrypted construction passed")
	}
}
