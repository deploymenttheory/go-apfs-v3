package native

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func cloneEvidenceView() schema.View {
	return schema.View{Entries: []schema.Entry{
		{Path: "Fixture/untouched-source", Kind: "file", ID: 1, Size: 8193, Xattrs: []schema.Xattr{{Name: "com.apple.ResourceFork", Bytes: 4097}}, Extents: &schema.Extents{Data: [][3]int64{{0, 10000, 8193}}, Resource: [][3]int64{{0, 30000, 4097}}}},
		{Path: "Fixture/untouched-clone", Kind: "file", ID: 2, Size: 8193, Xattrs: []schema.Xattr{{Name: "com.apple.ResourceFork", Bytes: 4097}}, Extents: &schema.Extents{Data: [][3]int64{{0, 10000, 8193}}, Resource: [][3]int64{{0, 30000, 4097}}}},
		{Path: "Fixture/edit", Kind: "file", ID: 3, Size: 2048, Extents: &schema.Extents{Data: [][3]int64{{0, 50000, 2048}}}},
	}}
}

func TestClonePhysicalComparisonRequiresNativeSharingAndSeparation(t *testing.T) {
	want := cloneEvidenceView()
	got := cloneEvidenceView()
	for _, e := range got.Entries {
		for _, runs := range [][][3]int64{e.Extents.Data, e.Extents.Resource} {
			for i := range runs {
				runs[i][1] += 1 << 20
			}
		}
	}
	if diffs, err := cloneOutputDifferences(&schema.Observation{Views: []schema.View{got}}, want); err != nil || len(diffs) != 0 {
		t.Fatal("different absolute locations changed a valid sharing relation", diffs, err)
	}
	for _, corrupt := range []func(*schema.View){
		func(v *schema.View) { v.Entries[1].Extents.Data[0][1] += 65536 },
		func(v *schema.View) { v.Entries[1].Extents.Resource[0][1] += 65536 },
		func(v *schema.View) { v.Entries[2].Extents.Data[0][1] = v.Entries[0].Extents.Data[0][1] },
		func(v *schema.View) { v.Entries[0].Extents = nil },
		func(v *schema.View) { v.Entries[1].Extents.Data[0][2]-- },
	} {
		got := cloneEvidenceView()
		corrupt(&got)
		if diffs, err := cloneOutputDifferences(&schema.Observation{Views: []schema.View{got}}, want); err == nil && len(diffs) == 0 {
			t.Fatal("native sharing corruption was accepted")
		}
	}
}

func cloneOutputMatrix() ([]Paired, map[string]corpus.Case) {
	cases := map[string]corpus.Case{}
	var pairs []Paired
	for _, profile := range []string{"apfs", "apfsx"} {
		for i, stage := range cloneEditStages {
			ref := schema.CaseRef{Producer: 15, Recipe: "apfs-clones", Profile: profile, Stage: stage}
			cases[CaseKey(ref)] = corpus.Case{Producer: 15, Recipe: ref.Recipe, Profile: profile, Stage: stage}
			if i != 0 {
				ref.Stage = cloneEditStages[i-1]
				pairs = append(pairs, Paired{Output: schema.Output{Source: ref, Operation: "edit", Format: "UDZO", Expect: schema.Expectation{View: stage, Continuation: i == len(cloneEditStages)-1, NewIdentities: true}}})
			}
		}
	}
	return pairs, cases
}

func TestCloneOutputCompletenessRequiresEveryNativeTransition(t *testing.T) {
	pairs, cases := cloneOutputMatrix()
	if err := requireCloneOutputs(pairs, cases, 15); err != nil {
		t.Fatal(err)
	}
	for i := range pairs {
		missing := append(append([]Paired{}, pairs[:i]...), pairs[i+1:]...)
		if err := requireCloneOutputs(missing, cases, 15); err == nil {
			t.Fatal("missing transition was accepted", i)
		}
	}
	for _, corrupt := range []func([]Paired){
		func(p []Paired) { p[0].Output.Expect.Continuation = true },
		func(p []Paired) { p[len(p)-1].Output.Expect.Continuation = false },
		func(p []Paired) { p[0].Output.Expect.ContinuationRefusal = "unsupported" },
		func(p []Paired) { p[0].Output.Source.Stage = "invented" },
		func(p []Paired) { p[0].Output.Operation = "repack" },
		func(p []Paired) { p[0].Output.Source.Profile = "invented" },
		func(p []Paired) { p[0].Output.Expect.NewIdentities = false },
		func(p []Paired) { p[0].Output.Expect.IgnoreTimes = []string{"change"} },
	} {
		p, _ := cloneOutputMatrix()
		corrupt(p)
		if err := requireCloneOutputs(p, cases, 15); err == nil {
			t.Fatal("invalid clone output contract was accepted")
		}
	}
	pairs = append(pairs, Paired{Output: schema.Output{Source: pairs[0].Output.Source, Operation: "repack", Format: "UDZO"}})
	if err := requireCloneOutputs(pairs, cases, 15); err != nil {
		t.Fatal("ordinary sector-preserving outputs disrupted clone edit completeness", err)
	}
	for key := range cases {
		_, incomplete := cloneOutputMatrix()
		delete(incomplete, key)
		if err := requireCloneOutputs(pairs, incomplete, 15); err == nil {
			t.Fatal("missing native stage was accepted", key)
		}
	}
}

func TestNativeCloneContinuationRejectsContentOnlyCopies(t *testing.T) {
	memory := fixture.NewMemoryVolume("/volume")
	if err := memory.Mkdir("/volume/Fixture", 0o755); err != nil {
		t.Fatal(err)
	}
	source := "/volume/Fixture/untouched-source"
	if err := memory.WriteFile(source, make([]byte, 16385), true); err != nil {
		t.Fatal(err)
	}
	if err := memory.WriteFile(filepath.Join(source, "..namedfork", "rsrc"), make([]byte, 8193), false); err != nil {
		t.Fatal(err)
	}
	if err := memory.Clone(source, "/volume/Fixture/untouched-clone"); err != nil {
		t.Fatal(err)
	}
	// MemoryVolume's clone copies bytes into a different physical range.
	// It must not qualify as an independently measured physical clone.
	v := &Verifier{Vol: memory}
	if err := v.continueCloneWrites(context.Background(), "/volume", t.TempDir()); err == nil {
		t.Fatal("equal independent copies qualified physical clone continuation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := v.continueCloneWrites(ctx, "/absent", t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatal("continuation cancellation was lost", err)
	}
}
