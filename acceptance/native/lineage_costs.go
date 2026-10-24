package native

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// lineageCosts are maximum complete-lineage wall seconds from the successful
// native phases in runs 39749828710 (e638a67, full green) and 39760552842
// (81eca7f, only macOS 15/27 green; macOS 26 failed fixture inventory).
// These estimates order work only; they are neither oracles nor qualification.
//
//go:embed lineage_costs.json
var lineageCosts []byte

var measuredLineageSeconds = func() map[string]map[string]int {
	var costs map[string]map[string]int
	if err := json.Unmarshal(lineageCosts, &costs); err != nil {
		panic(err)
	}
	// Keep every original timing byte above, while only supported producer
	// measurements participate in the default active fixture schedule.
	for key := range costs["fixtures"] {
		producer, _, _ := strings.Cut(key, "/")
		major, err := strconv.Atoi(strings.TrimPrefix(producer, "macos-"))
		if err != nil {
			panic(err)
		}
		if !schema.IsSupportedProducer(major) {
			delete(costs["fixtures"], key)
		}
	}
	return costs
}()

// prioritizeLineages changes only group start order. Every group and its ordered
// members remain required. Unmeasured capabilities use a positive default cost.
func prioritizeLineages(keys []string, kind string) {
	cost := func(key string) int {
		if kind == "outputs" && strings.HasPrefix(key, "macos-") {
			_, key, _ = strings.Cut(key, "/")
		}
		if seconds := measuredLineageSeconds[kind][key]; seconds > 0 {
			return seconds
		}
		return 60
	}
	sort.SliceStable(keys, func(i, j int) bool {
		if a, b := cost(keys[i]), cost(keys[j]); a != b {
			return a > b
		}
		return keys[i] < keys[j]
	})
}
