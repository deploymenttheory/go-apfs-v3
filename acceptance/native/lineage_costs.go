package native

import (
	_ "embed"
	"encoding/json"
	"sort"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// lineageCosts are rounded-up maximum complete-lineage wall seconds across all
// three kernels in successful warm PR run 39793190385 (277a0c1). The retained
// timing projection in testdata/lineage_timings.json binds each original log's
// SHA256 and preserves every group, including encrypted edits and APFS clones.
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

// Complete encrypted output timings from run 40361771436, job 121728202582.
// testdata/encrypted_lineage_timings.json retains all 74 groups and the original
// log digest. Keep the older measurements intact; these current estimates cover
// fresh encrypted construction and retained encrypted history added since then.
var encryptedOutputLineageSeconds = map[string]int{
	"encrypted-volumes/apfs":           1388,
	"encrypted-volumes/apfsx":          1490,
	"encrypted-snapshot-history/apfs":  905,
	"encrypted-snapshot-history/apfsx": 928,
}

// prioritizeLineages changes only group start order. Every group and its ordered
// members remain required. Unmeasured capabilities use a positive default cost.
func prioritizeLineages(keys []string, kind string) {
	cost := func(key string) int {
		if kind == "outputs" && strings.HasPrefix(key, "macos-") {
			_, key, _ = strings.Cut(key, "/")
		}
		seconds := measuredLineageSeconds[kind][key]
		if kind == "outputs" {
			seconds = max(seconds, encryptedOutputLineageSeconds[key])
		}
		if seconds > 0 {
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
