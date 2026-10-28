package native

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestForkMappingPairStopsBeforeAnotherAttachmentWhenCleanupIsUncertain(t *testing.T) {
	predicate := errors.New("original physical predicate")
	cleanup := errors.New("native release uncertain")
	for _, uncertain := range []bool{false, true} {
		calls := 0
		err := runForkMappingArms(context.Background(), func(index int) (error, error) {
			calls++
			if index == 0 {
				if uncertain {
					return predicate, cleanup
				}
				return predicate, nil
			}
			return nil, nil
		})
		want := 2
		if uncertain {
			want = 1
		}
		if calls != want || !errors.Is(err, predicate) || errors.Is(err, cleanup) != uncertain {
			t.Fatal("paired collection lost a failure or acted after uncertain release", calls, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	err := runForkMappingArms(ctx, func(index int) (error, error) {
		if index != 0 {
			t.Fatal("cancelled pair attached its next arm")
		}
		cancel()
		return predicate, nil
	})
	if !errors.Is(err, predicate) || !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled collection lost its original predicate", err)
	}
}

func TestForkMappingPairRequiresItsExactCanonicalInput(t *testing.T) {
	if err := requireCloneForkMappingInput(nil, 15); err != nil || cloneForkMappingInputName(28) != "" {
		t.Fatal("diagnostic escaped its one native producer", err)
	}
	name := cloneForkMappingInputName(26)
	p := Paired{Name: name, Output: schema.Output{Name: name, Source: schema.CaseRef{Producer: 26, Recipe: "clone-copy", Profile: "apfs", Stage: "source-removed"}, Operation: "edit", Format: "UDZO", Expect: schema.Expectation{View: "refused", Continuation: true}}}
	if err := requireCloneForkMappingInput([]Paired{p}, 26); err != nil {
		t.Fatal(err)
	}
	if err := requireCloneForkMappingInput(nil, 26); err == nil {
		t.Fatal("missing pair silently qualified")
	}
	if err := requireCloneForkMappingInput([]Paired{p, p}, 26); err == nil {
		t.Fatal("duplicate pair qualified")
	}
	p.Output.Expect.Continuation = false
	if err := requireCloneForkMappingInput([]Paired{p}, 26); err == nil {
		t.Fatal("original continuation could be omitted")
	}
}

func TestForkMappingCheckpointCannotMutateTheOriginalNativeState(t *testing.T) {
	s := nativeCloneState{Attrs: map[string][]byte{"fork": {1}}, DataRuns: [][3]int64{{0, 100, 10}}, ForkRuns: [][3]int64{{0, 200, 10}}}
	cause := errors.New("original native predicate")
	hook := cloneForkCheckpoint(func(_ string, copy *nativeCloneState, verdict error) error {
		if !errors.Is(verdict, cause) {
			t.Fatal("original failure was replaced")
		}
		copy.Attrs["fork"][0], copy.DataRuns[0][1], copy.ForkRuns[0][1] = 9, 900, 900
		return nil
	})
	if err := hook.record("original", &s, cause); err != nil || s.Attrs["fork"][0] != 1 || s.DataRuns[0][1] != 100 || s.ForkRuns[0][1] != 200 {
		t.Fatal("observer rewrote original native evidence", err)
	}
}

func TestForkMappingWriterKeepsItsOriginalFailureAfterLaterMapsChange(t *testing.T) {
	root := filepath.Join(t.TempDir(), "volume")
	model := newForkMappingModel(t, root)
	v := &Verifier{Vol: model}
	stage := t.TempDir()
	var points []string
	diagnostic := errors.New("additional diagnostic failure")
	var originalFailure error
	hook := cloneForkCheckpoint(func(point string, state *nativeCloneState, verdict error) error {
		points = append(points, point)
		if state == nil {
			return nil
		}
		originalFailure = verdict
		if verdict == nil || !strings.Contains(verdict.Error(), "private and shared") {
			t.Fatal("original fully shared resource map was not refused", verdict)
		}
		// A later simulated mapping transition must not repair that verdict.
		model.stale = false
		runs, err := model.Extents(filepath.Join(root, retainedPartialClone), "rsrc")
		if err != nil || len(runs) != 2 {
			t.Fatal("fake transition was not established", err)
		}
		return diagnostic
	})
	err := v.continueCloneWritesObserved(context.Background(), root, stage, "Fixture/source", "Fixture/sibling", hook)
	if !errors.Is(err, originalFailure) || !errors.Is(err, diagnostic) {
		t.Fatal("later measurement masked the original predicate", err)
	}
	want := "retained-created,retained-data-written,retained-resource-written,retained-original-forks-synced,retained-original-verdict"
	if strings.Join(points, ",") != want {
		t.Fatal("checkpoint order changed", points)
	}
	if got := strings.Join(model.reads[:6], ","); got != "source,sibling,source,sibling,first,second" {
		t.Fatal("diagnostic common state reads used a different order", model.reads)
	}
	raw, err := os.ReadFile(filepath.Join(stage, "clone-continuation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var proof struct{ States map[string]nativeCloneState }
	if err := json.Unmarshal(raw, &proof); err != nil || len(proof.States["retained/partial"].ForkRuns) != 1 {
		t.Fatal("original failing resource map was overwritten", err)
	}
}

func TestForkMappingNilObserverKeepsTheCompleteOriginalWriter(t *testing.T) {
	root := filepath.Join(t.TempDir(), "volume")
	model := newForkMappingModel(t, root)
	model.stale = false
	v := &Verifier{Vol: model}
	if err := v.continueCloneWritesFrom(context.Background(), root, t.TempDir(), "Fixture/source", "Fixture/sibling"); err != nil {
		t.Fatal("nil observer changed the complete original procedure", err)
	}
}

func TestForkMappingBothDiagnosticTargetsKeepTheSameCommonReadOrder(t *testing.T) {
	var reads [2][]string
	for index, target := range []string{"data", "resource"} {
		root := filepath.Join(t.TempDir(), "volume")
		model := newForkMappingModel(t, root)
		v := &Verifier{Vol: model}
		var originalFailure error
		hook := cloneForkCheckpoint(func(_ string, state *nativeCloneState, verdict error) error {
			if state == nil {
				return nil
			}
			originalFailure = verdict
			path := filepath.Join(root, retainedPartialClone)
			if target == "resource" {
				path = filepath.Join(path, "..namedfork", "rsrc")
			}
			return model.Fullfsync(path)
		})
		err := v.continueCloneWritesObserved(context.Background(), root, t.TempDir(), "Fixture/source", "Fixture/sibling", hook)
		if originalFailure == nil || !errors.Is(err, originalFailure) {
			t.Fatal("matched extra operation lost its original failure", target, err)
		}
		reads[index] = append([]string(nil), model.reads...)
	}
	if !slices.Equal(reads[0], reads[1]) {
		t.Fatal("diagnostic target changed the common read order", reads)
	}
}

// Ordinary in-memory logical files plus explicitly declared synthetic physical
// maps. This is a failure-preservation control, never native COW evidence.
type forkMappingModel struct {
	*fixture.MemoryVolume
	groups map[uint64]map[string][][3]int64
	stale  bool
	reads  []string
}

func newForkMappingModel(t *testing.T, root string) *forkMappingModel {
	t.Helper()
	m := &forkMappingModel{MemoryVolume: fixture.NewMemoryVolume(root), groups: map[uint64]map[string][][3]int64{}, stale: true}
	if err := m.Mkdir(filepath.Join(root, "Fixture"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "Fixture", "source")
	if err := m.WriteFile(source, bytes.Repeat([]byte("d"), 131073), true); err != nil {
		t.Fatal(err)
	}
	if err := m.WriteFile(filepath.Join(source, "..namedfork", "rsrc"), bytes.Repeat([]byte("r"), 32769), false); err != nil {
		t.Fatal(err)
	}
	st, _ := m.Lstat(source)
	m.groups[st.Ino] = map[string][][3]int64{"data": {{0, 100000, 131073}}, "rsrc": {{0, 300000, 32769}}}
	if err := m.Clone(source, filepath.Join(root, "Fixture", "sibling")); err != nil {
		t.Fatal(err)
	}
	return m
}

func (m *forkMappingModel) Clone(source, target string) error {
	before, err := m.Lstat(source)
	if err != nil {
		return err
	}
	if err := m.MemoryVolume.Clone(source, target); err != nil {
		return err
	}
	after, err := m.Lstat(target)
	if err != nil {
		return err
	}
	m.groups[after.Ino] = map[string][][3]int64{}
	for fork, runs := range m.groups[before.Ino] {
		m.groups[after.Ino][fork] = append([][3]int64(nil), runs...)
	}
	return nil
}

func (m *forkMappingModel) Pwrite(path string, offset int64, data []byte) error {
	fork := "data"
	if strings.HasSuffix(filepath.ToSlash(path), "/..namedfork/rsrc") {
		fork = "rsrc"
		path = filepath.Dir(filepath.Dir(path))
		value, err := m.Getxattr(path, "com.apple.ResourceFork", true)
		if err != nil {
			return err
		}
		value = bytes.Clone(value)
		copy(value[offset:], data)
		if err := m.Setxattr(path, "com.apple.ResourceFork", value, "replace"); err != nil {
			return err
		}
	} else if err := m.MemoryVolume.Pwrite(path, offset, data); err != nil {
		return err
	}
	st, err := m.Lstat(path)
	if err != nil {
		return err
	}
	old := m.groups[st.Ino][fork][0]
	m.groups[st.Ino][fork] = [][3]int64{{0, 1000000 + int64(st.Ino)*100000, 16384}, {16384, old[1] + 16384, old[2] - 16384}}
	return nil
}

func (m *forkMappingModel) Extents(path, fork string) ([][3]int64, error) {
	if fork == "data" {
		m.reads = append(m.reads, filepath.Base(path))
	}
	st, err := m.Lstat(path)
	if err != nil {
		return nil, err
	}
	if m.stale && fork == "rsrc" && strings.HasSuffix(filepath.ToSlash(path), "/"+retainedPartialClone) {
		return [][3]int64{{0, 300000, 32769}}, nil
	}
	return append([][3]int64(nil), m.groups[st.Ino][fork]...), nil
}

func (m *forkMappingModel) Fullfsync(path string) error {
	if strings.HasSuffix(filepath.ToSlash(path), "/..namedfork/rsrc") {
		path = filepath.Dir(filepath.Dir(path))
	}
	return m.MemoryVolume.Fullfsync(path)
}
