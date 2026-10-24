package native

import (
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestNativeLineagePriorityRetainsUnmeasuredSourcesAndUsesProducerIndependentOutputCosts(t *testing.T) {
	keys := []string{"macos-27/new-capability/apfs", "macos-26/partitioned-disks/hfsplus", "macos-26/new-capability/apfs", "builds", "macos-27/partitioned-disks/hfsplus"}
	prioritizeLineages(keys, "outputs")
	want := []string{"builds", "macos-26/new-capability/apfs", "macos-27/new-capability/apfs", "macos-26/partitioned-disks/hfsplus", "macos-27/partitioned-disks/hfsplus"}
	if !reflect.DeepEqual(keys, want) {
		t.Fatalf("longest-first ordering lost an unmeasured source, a producer or deterministic ties: %v", keys)
	}
	fixtures := []string{"macos-26/file-corpus/apfs", "macos-27/apfs-directory-statistics/apfs"}
	prioritizeLineages(fixtures, "fixtures")
	if fixtures[0] != "macos-27/apfs-directory-statistics/apfs" {
		t.Fatal("fixture ordering lost the captured producer's measured cost")
	}
}

func TestNativeLineageTimingKeepsHistoricalBytesOutsideActiveScheduling(t *testing.T) {
	var historical map[string]map[string]int
	if err := json.Unmarshal(lineageCosts, &historical); err != nil {
		t.Fatal(err)
	}
	if historical["fixtures"]["macos-15/file-corpus/apfs"] <= 0 {
		t.Fatal("historical producer timing was removed")
	}
	for key, seconds := range historical["fixtures"] {
		producer, _, _ := strings.Cut(key, "/")
		major, err := strconv.Atoi(strings.TrimPrefix(producer, "macos-"))
		if err != nil {
			t.Fatal(err)
		}
		got, active := measuredLineageSeconds["fixtures"][key]
		if active != schema.IsSupportedProducer(major) || active && got != seconds {
			t.Fatal("active timing projection changed support or recorded seconds", key, got, seconds)
		}
	}
	if !reflect.DeepEqual(measuredLineageSeconds["outputs"], historical["outputs"]) {
		t.Fatal("producer-independent output timings changed")
	}
}
