package native

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestForkMappingTrialsAreFixedAlternatingPairsWithBoundedFreshInputs(t *testing.T) {
	trials := forkMappingTrials(27)
	if len(trials) != 16 || len(forkMappingTrials(26)) != 2 || len(forkMappingTrials(28)) != 0 {
		t.Fatal("undeclared trial count", trials)
	}
	for pair := range 8 {
		want := []string{"data", "resource"}
		if pair%2 != 0 {
			want[0], want[1] = want[1], want[0]
		}
		for arm := range 2 {
			if got := trials[2*pair+arm]; got.Pair != pair+1 || got.Target != want[arm] {
				t.Fatal("trial order changed", got)
			}
		}
	}
	for _, test := range []struct {
		bytes int64
		arms  int
		valid bool
	}{{64 << 20, 16, true}, {256 << 20, 2, true}, {64<<20 + 1, 16, false}, {1, 17, false}, {0, 2, false}, {1, 0, false}, {1 << 62, 16, false}} {
		if err := checkForkMappingRawBudget(test.bytes, test.arms); (err == nil) != test.valid {
			t.Fatal("raw aggregate bound", test, err)
		}
	}
	cause := errors.New("original predicate")
	calls := 0
	err := runForkMappingSeries(context.Background(), len(trials), func(int) (error, error) { calls++; return cause, nil })
	if calls != 16 || !errors.Is(err, cause) {
		t.Fatal("fixed trials became verdict retries", calls, err)
	}
	calls = 0
	err = runForkMappingSeries(context.Background(), 16, func(int) (error, error) { calls++; return errForkMappingEvidence, nil })
	if calls != 1 || !errors.Is(err, errForkMappingEvidence) {
		t.Fatal("continued without retainable evidence", calls, err)
	}
}

func TestForkMappingAPFSXSeriesRequiresTheExactOriginalContinuation(t *testing.T) {
	name := cloneForkMappingInputName(27)
	p := Paired{Name: name, Output: schema.Output{Name: name, Source: schema.CaseRef{Producer: 27, Recipe: "clone-copy", Profile: "apfsx", Stage: "source-removed"}, Operation: "edit", Format: "UDZO", Expect: schema.Expectation{View: "refused", Continuation: true}}}
	if err := requireCloneForkMappingInput([]Paired{p}, 27); err != nil {
		t.Fatal(err)
	}
	p.Output.Source.Profile = "apfs"
	if err := requireCloneForkMappingInput([]Paired{p}, 27); err == nil {
		t.Fatal("affected input replaced by unrelated profile")
	}
}

func TestForkMappingObservationsStartAfterTheOriginalWriterReturns(t *testing.T) {
	cause := errors.New("original physical predicate")
	for _, failed := range []bool{false, true} {
		var events []string
		returned := false
		err := runForkMappingObservedWriter(func(hook cloneForkCheckpoint) (result error) {
			defer func() { returned = true; events = append(events, "writer-return") }()
			for _, point := range []string{"retained-created", "retained-data-written", "retained-resource-written", "retained-original-forks-synced"} {
				if err := hook.record(point, nil, nil); err != nil {
					return err
				}
			}
			if len(events) != 0 {
				t.Fatal("extra observation preceded original predicate", events)
			}
			var verdict error
			if failed {
				verdict = cause
			}
			state := nativeCloneState{DataRuns: [][3]int64{{0, 10, 100}}}
			if err := hook.record("retained-original-verdict", &state, verdict); err != nil {
				return errors.Join(verdict, err)
			}
			if verdict != nil {
				return verdict
			}
			events = append(events, "original-peer-checks")
			return nil
		}, func(nativeCloneState, error) error { events = append(events, "persist-original"); return nil }, func() error {
			if !returned {
				t.Fatal("intervention preceded natural writer return")
			}
			events = append(events, "extra-observations")
			return nil
		})
		want := []string{"persist-original", "original-peer-checks", "writer-return", "extra-observations"}
		if failed {
			want = []string{"persist-original", "writer-return", "extra-observations"}
		}
		if !slices.Equal(events, want) || errors.Is(err, cause) != failed {
			t.Fatal("original procedure/verdict changed", events, err)
		}
	}
	observed := false
	retention := errors.Join(errForkMappingEvidence, errors.New("write failed"))
	err := runForkMappingObservedWriter(func(h cloneForkCheckpoint) error {
		return errors.Join(cause, h.record("original", &nativeCloneState{}, cause))
	}, func(nativeCloneState, error) error { return retention }, func() error { observed = true; return nil })
	if observed || !errors.Is(err, cause) || !errors.Is(err, retention) {
		t.Fatal("unretained original allowed intervention", observed, err)
	}
}

func TestForkMappingDescriptorControlsPrecedeExactlyOneIntervention(t *testing.T) {
	var common []forkMappingPhase
	for _, target := range []string{"data", "resource"} {
		var phases []forkMappingPhase
		flushes := 0
		if err := runForkMappingMeasurements(context.Background(), func(phase forkMappingPhase) error {
			phases = append(phases, phase)
			if phase.Action == "flush" {
				flushes++
			}
			return nil
		}); err != nil {
			t.Fatal(target, err)
		}
		if flushes != 1 {
			t.Fatal("intervention repeated", flushes)
		}
		if common == nil {
			common = phases
		} else if !slices.Equal(common, phases) {
			t.Fatal("targets have different observation ordering")
		}
	}
	var before []string
	for _, phase := range common {
		if phase.Action == "flush" {
			break
		}
		before = append(before, phase.Action)
	}
	want := []string{"open-retained", "map-retained", "map-retained", "open-fresh", "map-fresh", "map-retained", "close-fresh", "read-retained", "map-retained"}
	if !slices.Equal(before, want) {
		t.Fatal("old/new/old or readback control missing", before)
	}
	for _, failure := range []string{"open-retained", "map-fresh", "close-fresh", "flush"} {
		cause := errors.New(failure)
		last := ""
		err := runForkMappingMeasurements(context.Background(), func(phase forkMappingPhase) error {
			last = phase.Action
			if last == failure {
				return cause
			}
			return nil
		})
		if !errors.Is(err, cause) || last != failure {
			t.Fatal("measurement error was retried or suppressed", failure, last, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	err := runForkMappingMeasurements(ctx, func(phase forkMappingPhase) error {
		if phase.Action == "read-retained" {
			cancel()
		}
		if phase.Action == "flush" {
			t.Fatal("flush after cancellation")
		}
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestForkMappingOriginalReceiptsAreExclusiveAndBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "original-verdict.json")
	budget := &forkMappingEvidence{}
	if err := budget.write(path, struct{ Error string }{"original failure"}); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := budget.write(path, struct{ Error string }{"later pass"}); !errors.Is(err, errForkMappingEvidence) {
		t.Fatal("original overwritten", err)
	}
	actual, _ := os.ReadFile(path)
	if !slices.Equal(original, actual) || budget.bytes != int64(len(original)) {
		t.Fatal("receipt bytes or accounting changed")
	}
	budget.bytes = forkMappingReceiptLimit - 1
	if err := budget.write(filepath.Join(t.TempDir(), "over-limit.json"), true); !errors.Is(err, errForkMappingEvidence) {
		t.Fatal("aggregate receipt limit ignored", err)
	}
	if err := (&forkMappingEvidence{}).write(filepath.Join(t.TempDir(), "member-limit.json"), strings.Repeat("x", forkMappingReceiptMemberLimit)); !errors.Is(err, errForkMappingEvidence) {
		t.Fatal("member receipt limit ignored", err)
	}
}

func TestForkMappingIncludesUnchangedWriterReceiptsWithinTheSharedBudget(t *testing.T) {
	filename := filepath.Join(t.TempDir(), "writer.json")
	original := []byte("{\"originalVerdict\":\"failed\"}\n")
	if err := os.WriteFile(filename, original, 0600); err != nil {
		t.Fatal(err)
	}
	budget := &forkMappingEvidence{}
	if err := budget.include(filename); err != nil || budget.bytes != int64(len(original)) {
		t.Fatal("original writer receipt was not accounted", budget.bytes, err)
	}
	if data, err := os.ReadFile(filename); err != nil || string(data) != string(original) {
		t.Fatal("including evidence rewrote the original writer receipt", err)
	}
	budget.bytes = forkMappingReceiptLimit - int64(len(original)) + 1
	before := budget.bytes
	if err := budget.include(filename); !errors.Is(err, errForkMappingEvidence) || budget.bytes != before {
		t.Fatal("over-budget original receipt was admitted or silently truncated", err)
	}
	if err := budget.include(filepath.Dir(filename)); !errors.Is(err, errForkMappingEvidence) {
		t.Fatal("directory was treated as an original writer receipt", err)
	}
	if err := budget.include(filename + ".missing"); !errors.Is(err, os.ErrNotExist) || !errors.Is(err, errForkMappingEvidence) {
		t.Fatal("missing original receipt lost its causes", err)
	}
}

func TestForkMappingReadbackRequiresExactSizeAndActualEOF(t *testing.T) {
	const payload = "actual fork bytes"
	var offsets []int64
	digest, err := readForkMappingContents(int64(len(payload)), func(data []byte, offset int64) (int, error) {
		offsets = append(offsets, offset)
		return strings.NewReader(payload).ReadAt(data, offset)
	})
	if err != nil || digest != fmt.Sprintf("%x", sha256.Sum256([]byte(payload))) || !slices.Equal(offsets, []int64{0, int64(len(payload))}) {
		t.Fatal("actual readback/EOF not established", digest, offsets, err)
	}
	for _, reader := range []func([]byte, int64) (int, error){
		func([]byte, int64) (int, error) { return 0, nil },
		func(data []byte, offset int64) (int, error) {
			if offset == 0 {
				return len(data), nil
			}
			return 1, io.EOF
		},
		func(data []byte, offset int64) (int, error) {
			if offset == 0 {
				return len(data), nil
			}
			return 0, errors.New("I/O")
		},
	} {
		if _, err := readForkMappingContents(10, reader); err == nil {
			t.Fatal("incomplete/overlong/unreadable fork passed")
		}
	}
	called := false
	if _, err := readForkMappingContents(1<<20+1, func([]byte, int64) (int, error) { called = true; return 0, nil }); err == nil || called {
		t.Fatal("read allocation exceeded bound", err)
	}
}

func TestForkMappingKeepsRawAllocationRunsSeparateFromLogicalEOF(t *testing.T) {
	var arg [20]byte
	binary.LittleEndian.PutUint64(arg[4:12], 4096)
	binary.LittleEndian.PutUint64(arg[12:20], 8192)
	raw, logical, err := forkMappingRange(arg, 0, 100)
	if err != nil || raw != [3]int64{0, 8192, 4096} || logical != [3]int64{0, 8192, 100} {
		t.Fatal("raw ABI result clipped to EOF", raw, logical, err)
	}
	for _, bad := range []struct{ length, physical uint64 }{{0, 1}, {1, ^uint64(0)}, {^uint64(0), 1}, {4096, 1<<63 - 2}} {
		binary.LittleEndian.PutUint64(arg[4:12], bad.length)
		binary.LittleEndian.PutUint64(arg[12:20], bad.physical)
		if _, _, err := forkMappingRange(arg, 0, 100); err == nil {
			t.Fatal("invalid raw result admitted", bad)
		}
	}
}

func TestForkMappingActualWriterCompletesBeforeDiagnosticDescriptorSequence(t *testing.T) {
	for _, stale := range []bool{false, true} {
		root := filepath.Join(t.TempDir(), "volume")
		model := newForkMappingModel(t, root)
		model.stale = stale
		v := &Verifier{Vol: model}
		stage := t.TempDir()
		returned := false
		var original error
		err := runForkMappingObservedWriter(func(hook cloneForkCheckpoint) error {
			err := v.continueCloneWritesObserved(context.Background(), root, stage, "Fixture/source", "Fixture/sibling", hook)
			returned = true
			return err
		}, func(_ nativeCloneState, verdict error) error { original = verdict; return nil }, func() error {
			if !returned {
				t.Fatal("actual original writer still running")
			}
			if _, err := os.Stat(filepath.Join(stage, "clone-continuation.json")); err != nil {
				t.Fatal("original transcript not completed before measurements", err)
			}
			if !stale && !slices.Equal(model.reads[len(model.reads)-2:], []string{"source", "sibling"}) {
				t.Fatal("original peer assertions did not precede probes", model.reads)
			}
			model.stale = false // Diagnostic convergence must never erase a failure.
			return nil
		})
		if stale && (original == nil || !errors.Is(err, original)) {
			t.Fatal("actual original failure was repaired by later evidence", err)
		}
		if !stale && err != nil {
			t.Fatal("complete original writer changed", err)
		}
	}
}
