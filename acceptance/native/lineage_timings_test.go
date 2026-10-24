package native

import (
	"encoding/json"
	"flag"
	"math"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

var (
	lineageReplayBudget   = flag.Duration("native-lineage-budget", 0, "optional wall-clock budget for the retained native scheduling replay")
	lineageReplayObserved = flag.Bool("native-lineage-observed", false, "replay the observed run instead of projecting ordered admission")
)

// These are timing projections of immutable job logs, not filesystem evidence.
// Start offsets are measured from each phase's step start; elapsed seconds come
// from complete Go subtest summaries, whose print timestamps are buffered.
type timedLineage struct {
	Key     string
	Start   float64
	Seconds float64
}

type timedPhase struct {
	Kind           string
	Start          float64
	Seconds        float64
	ArtifactsReady float64
	Groups         []timedLineage
}

type timedKernel struct {
	Major          int
	LogSHA256      string
	RawProofs      int
	ParityVerdicts int
	SlowVerdicts   int
	MainVerdicts   int
	Phases         []timedPhase
}

type lineageTimings struct {
	Run              string
	Head             string
	CreatedAt        time.Time
	GateCompletedAt  time.Time
	Jobs             int
	GoCacheHits      int
	FixtureCacheHits int
	GateTailSeconds  float64
	Native           []timedKernel
}

func retainedLineageTimings(t *testing.T) lineageTimings {
	t.Helper()
	data, err := os.ReadFile("testdata/lineage_timings.json")
	if err != nil {
		t.Fatal(err)
	}
	var timings lineageTimings
	if err := json.Unmarshal(data, &timings); err != nil {
		t.Fatal(err)
	}
	return timings
}

func TestNativeLineageCostsCoverEverySupportedRetainedCompleteGroup(t *testing.T) {
	for _, kernel := range retainedLineageTimings(t).Native {
		if !schema.IsSupportedProducer(kernel.Major) {
			continue
		}
		for _, phase := range kernel.Phases {
			kind := "outputs"
			if phase.Kind == "fixtures" {
				kind = "fixtures"
			}
			for _, group := range phase.Groups {
				if !supportedTimedLineage(group.Key) {
					continue
				}
				key := group.Key
				if kind == "outputs" && strings.HasPrefix(key, "macos-") {
					_, key, _ = strings.Cut(key, "/")
				}
				if got, want := measuredLineageSeconds[kind][key], int(math.Ceil(group.Seconds)); got < want {
					t.Errorf("macOS %d %s %s: cost %d omits measured complete work of %ds", kernel.Major, phase.Kind, key, got, want)
				}
			}
		}
	}
}

// supportedTimedLineage projects the historical archive onto current producer
// support. Producer-independent build/container groups remain part of the replay.
func supportedTimedLineage(key string) bool {
	if !strings.HasPrefix(key, "macos-") {
		return true
	}
	producer, _, ok := strings.Cut(key, "/")
	if !ok {
		return false
	}
	major, err := strconv.Atoi(strings.TrimPrefix(producer, "macos-"))
	return err == nil && schema.IsSupportedProducer(major)
}

// projectLineagePhase changes admission only: every complete group retains its
// observed duration. Serial proofs/setup before the first group and the phase
// suffix remain. This cannot predict changed native IO contention or new work.
func projectLineagePhase(p timedPhase, workers int, ordered bool) float64 {
	groups := make(map[string]timedLineage, len(p.Groups))
	keys := make([]string, 0, len(p.Groups))
	prefix, last := math.Inf(1), float64(0)
	for _, group := range p.Groups {
		// Preserve the original serial setup/suffix boundaries. Recomputing
		// them after filtering would relabel retired work as serial overhead.
		prefix = min(prefix, group.Start)
		last = max(last, group.Start+group.Seconds)
		if !supportedTimedLineage(group.Key) {
			continue
		}
		keys = append(keys, group.Key)
		groups[group.Key] = group
	}
	kind := "outputs"
	if p.Kind == "fixtures" {
		kind = "fixtures"
	}
	if ordered {
		prioritizeLineages(keys, kind)
	} else {
		// Isolate priority from concurrency by replaying the observed
		// admission order with the same changed worker bound.
		sort.SliceStable(keys, func(i, j int) bool { return groups[keys[i]].Start < groups[keys[j]].Start })
	}
	slots := make([]float64, workers)
	for _, key := range keys {
		free := 0
		for i, seconds := range slots {
			if seconds < slots[free] {
				free = i
			}
		}
		slots[free] += groups[key].Seconds
	}
	end := float64(0)
	for _, seconds := range slots {
		end = max(end, seconds)
	}
	// Step timestamps have one-second precision; group summaries are rounded
	// to hundredths. Do not subtract a negative quantization remainder.
	return prefix + end + max(0, p.Seconds-last)
}

func projectLineageRun(timings lineageTimings, workers int, ordered bool) (float64, map[int][]float64) {
	last := float64(0)
	phases := map[int][]float64{}
	for _, kernel := range timings.Native {
		if !schema.IsSupportedProducer(kernel.Major) {
			continue
		}
		previous, observedPrevious := float64(0), float64(0)
		for _, phase := range kernel.Phases {
			start := phase.Start
			if phase.Kind != "fixtures" {
				// Keep actual producer readiness and the observed transition,
				// polling and download delay after the inputs are ready.
				delay := phase.Start - max(observedPrevious, phase.ArtifactsReady)
				start = max(previous, phase.ArtifactsReady) + delay
			}
			seconds := projectLineagePhase(phase, workers, ordered)
			phases[kernel.Major] = append(phases[kernel.Major], seconds)
			previous = start + seconds
			observedPrevious = phase.Start + phase.Seconds
		}
		last = max(last, previous)
	}
	return last + timings.GateTailSeconds, phases
}

func TestNativeLineageTimingReplay(t *testing.T) {
	timings := retainedLineageTimings(t)
	observed := timings.GateCompletedAt.Sub(timings.CreatedAt).Seconds()
	if observed != 3180 || timings.Jobs != 11 || timings.GoCacheHits != 10 || timings.FixtureCacheHits != 8 {
		t.Fatalf("retained full warm-run provenance changed: %+v", timings)
	}
	if len(timings.Native) != 3 {
		t.Fatal("historical timing archive must preserve all three original native kernels")
	}
	last := float64(0)
	for _, kernel := range timings.Native {
		if kernel.RawProofs != 8 || kernel.ParityVerdicts != 558 || kernel.SlowVerdicts != 2 || kernel.MainVerdicts != 1016 || len(kernel.LogSHA256) != 64 {
			t.Fatalf("macOS %d lost complete native workload provenance", kernel.Major)
		}
		if len(kernel.Phases) != 3 || kernel.Phases[0].Kind != "fixtures" || kernel.Phases[1].Kind != "slow" || kernel.Phases[2].Kind != "main" {
			t.Fatalf("macOS %d replay changed phase order", kernel.Major)
		}
		for i, phase := range kernel.Phases {
			if len(phase.Groups) != []int{124, 2, 64}[i] {
				t.Fatalf("macOS %d %s replay lost complete groups", kernel.Major, phase.Kind)
			}
			seen := map[string]bool{}
			lastGroup := float64(0)
			for _, group := range phase.Groups {
				if seen[group.Key] || group.Start < 0 || group.Seconds <= 0 || group.Start+group.Seconds > phase.Seconds+1 {
					t.Fatalf("macOS %d %s has invalid complete-group timing: %+v", kernel.Major, phase.Kind, group)
				}
				seen[group.Key] = true
				lastGroup = max(lastGroup, group.Start+group.Seconds)
			}
			if math.Abs(lastGroup-phase.Seconds) > 1 {
				t.Fatalf("macOS %d %s elapsed summaries do not reproduce this phase's end", kernel.Major, phase.Kind)
			}
		}
		main := kernel.Phases[2]
		last = max(last, main.Start+main.Seconds)
	}
	if last+timings.GateTailSeconds != observed {
		t.Fatal("retained phase timeline no longer reproduces the observed gate completion")
	}
	t.Logf("observed run %s: %.2fs, 45-minute budget exceeded by %.2fs", timings.Run, observed, observed-2700)
	for _, workers := range []int{5, 6, 7} {
		seconds, phases := projectLineageRun(timings, workers, true)
		for _, major := range schema.Producers {
			t.Logf("supported-producer projection only: %d workers, macOS %d fixture/slow/main seconds %.2f", workers, major, phases[major])
		}
		t.Logf("supported-producer projection only: %d workers, wall %.2fs (difference from historical run %.2fs)", workers, seconds, seconds-observed)
		if seconds >= observed {
			t.Errorf("ordered %d-worker projection regressed the retained baseline: %.2fs", workers, seconds)
		}
	}
	unordered, _ := projectLineageRun(timings, 7, false)
	ordered, _ := projectLineageRun(timings, 7, true)
	t.Logf("projection only: 7 workers retaining observed admission order %.2fs, ordered admission saves %.2fs", unordered, unordered-ordered)
	if ordered >= unordered {
		t.Error("priority admission no longer improves the retained same-concurrency control")
	}
	if *lineageReplayBudget > 0 {
		seconds := observed
		if !*lineageReplayObserved {
			workers, err := strconv.Atoi(flag.Lookup("test.parallel").Value.String())
			if err != nil || workers < 1 {
				t.Fatal("replay needs a positive -parallel bound")
			}
			seconds, _ = projectLineageRun(timings, workers, true)
		}
		if seconds > lineageReplayBudget.Seconds() {
			t.Fatalf("retained scheduling replay %.2fs exceeds budget %s (projection=%t)", seconds, *lineageReplayBudget, !*lineageReplayObserved)
		}
	}
}

// The archive is historical. Filtering work must not silently add its removed
// tail back as serial time, schedule a retired kernel, or mutate the archive.
func TestNativeLineageProjectionExcludesRetiredProducersWithoutInventedSerialTail(t *testing.T) {
	phase := timedPhase{Kind: "fixtures", Seconds: 101, Groups: []timedLineage{
		{Key: "macos-15/example/apfs", Start: 1, Seconds: 100},
		{Key: "macos-26/example/apfs", Start: 1, Seconds: 2},
	}}
	if got := projectLineagePhase(phase, 1, true); got != 3 {
		t.Fatalf("retired producer became work or invented serial overhead: %.2fs", got)
	}
	timings := lineageTimings{Native: []timedKernel{
		{Major: 15, Phases: []timedPhase{{Kind: "fixtures", Seconds: 100, Groups: []timedLineage{{Key: "macos-15/example/apfs", Seconds: 100}}}}},
		{Major: 26, Phases: []timedPhase{phase}},
		{Major: 27, Phases: []timedPhase{{Kind: "fixtures", Seconds: 4, Groups: []timedLineage{{Key: "macos-26/example/apfs", Seconds: 4}}}}},
	}}
	seconds, phases := projectLineageRun(timings, 1, true)
	if seconds != 4 || len(phases) != len(schema.Producers) {
		t.Fatalf("projection retained a retired native worker: %.2fs, %v", seconds, phases)
	}
	for major := range phases {
		if !schema.IsSupportedProducer(major) {
			t.Fatal("projection retained an unsupported producer", major)
		}
	}
	if len(timings.Native) != 3 || len(phase.Groups) != 2 || !supportedTimedLineage("builds") || !supportedTimedLineage("containers") {
		t.Fatal("projection changed its historical input or lost producer-independent work")
	}
}
