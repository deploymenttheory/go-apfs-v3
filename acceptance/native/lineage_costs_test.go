package native

import (
	"reflect"
	"testing"
)

func TestNativeLineagePriorityRetainsUnmeasuredSourcesAndUsesProducerIndependentOutputCosts(t *testing.T) {
	keys := []string{"macos-27/new-capability/apfs", "macos-26/partitioned-disks/hfsplus", "macos-26/new-capability/apfs", "builds", "macos-15/partitioned-disks/hfsplus"}
	prioritizeLineages(keys, "outputs")
	want := []string{"builds", "macos-26/new-capability/apfs", "macos-27/new-capability/apfs", "macos-15/partitioned-disks/hfsplus", "macos-26/partitioned-disks/hfsplus"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("longest-first ordering lost an unmeasured source, a producer or deterministic ties: %v", keys)
	}
	fixtures := []string{"macos-15/file-corpus/apfs", "macos-27/apfs-directory-statistics/apfs"}
	prioritizeLineages(fixtures, "fixtures")
	if fixtures[0] != "macos-27/apfs-directory-statistics/apfs" {
		t.Fatal("fixture ordering lost the captured producer's measured cost")
	}
}
