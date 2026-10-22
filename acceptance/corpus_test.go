package acceptance_test

import (
	"context"
	"slices"
	"sort"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
)

var (
	corpusOnce   sync.Once
	corpusValue  *corpus.Corpus
	corpusCases  []corpus.Case
	corpusLoadEr error
)

// loadCorpus resolves the pinned corpus once per test binary. A corpus that
// cannot be resolved fails every test that needs it; nothing skips.
func loadCorpus(t *testing.T) ([]corpus.Case, *corpus.Corpus) {
	t.Helper()
	corpusOnce.Do(func() {
		c, err := corpus.Resolve(context.Background(), corpus.Options{Root: ".."})
		if err != nil {
			corpusLoadEr = err
			return
		}
		cases, err := c.Cases()
		if err != nil {
			corpusLoadEr = err
			return
		}
		corpusValue, corpusCases = c, cases
	})
	if corpusLoadEr != nil {
		t.Fatalf("fixture corpus: %v", corpusLoadEr)
	}
	return corpusCases, corpusValue
}

// consumers names the test functions that assert on each recipe beyond
// TestReadParity, which covers every recipe. A recipe present in the corpus
// without any consumer fails: a fixture nobody checks proves nothing.
var consumers = map[string][]string{
	"apfs-clones":                  {"TestReadParity", "TestGoEditsReproduceAppleStageStates"},
	"clone-copy":                   {"TestReadParity", "TestCloneCopyEditsMatchAppleStates", "TestReopenedSessionCloneStreamsPackToAppleStates"},
	"encrypted-image-edits":        {"TestReadParity", "TestEncryptedImageEditsMatchAppleStates"},
	"lzfse-images":                 {"TestReadParity", "TestRepackPreservesEverySector"},
	"hfs-journal-interruption":     {"TestRecoveryMatchesAppleStates"},
	"apfs-checkpoint-interruption": {"TestReadParity", "TestRecoveryMatchesAppleStates"},
	"file-corpus":                  {"TestReadParity", "TestBuildFromFixtures", "TestPackingReopenedPreservationSourcesMatchesNativeFiles", "TestRepackPreservesEverySector", "TestAppleDoubleMatchesNativeExports", "TestStorageAccountingMatchesNativeAllocation"},
	"compressed-files":             {"TestReadParity", "TestBuildFromFixtures", "TestRepackPreservesEverySector"},
	"encrypted-volumes":            {"TestReadParity", "TestRepackPreservesEverySector", "TestCloneReadsUseNativeSharedExtents", "TestHistoryAndEncryptedWritersRefuseWithoutPublication"},
	"encrypted-images":             {"TestReadParity", "TestRepackPreservesEverySector", "TestRepackRefusesSignedAndLockedImages"},
	"snapshot-history":             {"TestReadParity", "TestRepackPreservesEverySector", "TestStorageAccountingMatchesNativeAllocation", "TestSnapshotReadersKeepTheirHistoricalOwnership", "TestSnapshotSessionsRetainTheSelectedHistoricalView", "TestHistoryAndEncryptedWritersRefuseWithoutPublication"},
	"container-volumes":            {"TestReadParity", "TestRepackPreservesEverySector", "TestConstructedContainersMatchNativeVolumes", "TestStorageAccountingMatchesNativeAllocation", "TestMultipleVolumeEditingRefusesMissingAndUnknownSelectors"},
	"volume-groups":                {"TestReadParity", "TestRepackPreservesEverySector", "TestConstructedContainersMatchNativeVolumes"},
	"partitioned-disks":            {"TestReadParity", "TestRepackPreservesEverySector", "TestRepackRefusesSignedAndLockedImages"},
	"hfs-mutation-sources":         {"TestReadParity", "TestExistingImageEditsMatchAppleStates"},
	"apfs-mutation-sources":        {"TestReadParity", "TestExistingImageEditsMatchAppleStates", "TestStorageAccountingMatchesNativeAllocation"},
	"file-command-journeys":        {"TestReadParity", "TestFileCommandSessionsMatchAppleJourney"},
	"workspace-edits":              {"TestReadParity", "TestWorkspaceOperationsMatchAppleStates", "TestRecursiveHostImportsPreserveNativeLogicalTrees"},
	"permission-inheritance":       {"TestReadParity", "TestSessionPermissionsMatchAppleStates"},
	// Stage sequences the image editor replays from Apple's prior state.
	"apfs-container-geometry":       {"TestReadParity", "TestGoEditsReproduceAppleStageStates"},
	"apfs-directory-statistics":     {"TestReadParity", "TestGoEditsReproduceAppleStageStates"},
	"hfs-attributes-initialization": {"TestReadParity", "TestGoEditsReproduceAppleStageStates"},
	"hfs-catalog-map-growth":        {"TestReadParity", "TestGoEditsReproduceAppleStageStates (slow build tag)"},
	"hfs-fragmented-metadata":       {"TestReadParity", "TestGoEditsReproduceAppleStageStates"},
}

func TestEveryCorpusCaseHasAConsumer(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipes := map[string]bool{}
	for _, k := range cases {
		recipes[k.Recipe] = true
	}
	var names []string
	for name := range recipes {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !slices.ContainsFunc(consumers[name], func(test string) bool { return test != "TestReadParity" }) {
			t.Errorf("recipe %s is in the corpus but no test beyond read parity consumes it", name)
		}
	}
	producers := map[int]bool{}
	for _, k := range cases {
		producers[k.Producer] = true
	}
	for _, major := range []int{15, 26, 27} {
		if !producers[major] {
			t.Errorf("corpus has no cases from macOS %d", major)
		}
	}
}
