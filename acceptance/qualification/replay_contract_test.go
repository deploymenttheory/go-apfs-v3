package main

import (
	"context"
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
)

func TestCurrentCaptureCannotDropOrSubstituteRequiredNativeCases(t *testing.T) {
	spec := replayTest{Manifest: "macos-*/manifest.json"}
	ref := corpus.Entry{Captures: []corpus.Capture{{Manifest: "macos-15/manifest.json", Major: 15, Contract: "native-control", Cases: []string{"cases/apfs", "cases/hfsplus"}}}}
	for _, cases := range [][]string{nil, {"cases/apfs"}, {"cases/apfs", "cases/apfs"}, {"cases/apfs", "cases/other"}} {
		got := ref
		got.Captures = append([]corpus.Capture(nil), ref.Captures...)
		got.Captures[0].Cases = cases
		if err := matchCaptureCases(spec, got, ref); err == nil {
			t.Fatal("case omission/substitution accepted", cases)
		}
	}
	if err := matchCaptureCases(spec, corpus.Entry{}, ref); err == nil {
		t.Fatal("missing manifest admitted")
	}
	if err := matchCaptureCases(spec, ref, ref); err != nil {
		t.Fatal(err)
	}
}

func TestContinuationRequiresCompleteSourceProfileInventory(t *testing.T) {
	root := t.TempDir()
	native := filepath.Join(root, "native")
	if err := os.Mkdir(native, 0700); err != nil {
		t.Fatal(err)
	}
	spec := replayTest{Test: "TestNativeImageMetadataEditingContinuation", KindEnvironment: "CONTROL_KIND", Environment: "CONTROL_INPUT", Output: "CONTROL_OUTPUT"}
	t.Setenv("CONTROL_INPUT", native)
	t.Setenv("CONTROL_KIND", "hfs")
	if _, _, _, err := continuationCases(context.Background(), root, spec, "metadata"); err == nil {
		t.Fatal("missing continuation passed")
	}
	for _, source := range []string{"15", "26", "27"} {
		for _, profile := range []string{"hfsplus", "hfsx", "hfsplus-empty-attributes", "hfsx-empty-attributes"} {
			for _, ext := range []string{"raw", "json"} {
				writeControl(t, native, "macos-"+source+"-"+profile+"."+ext, "ordinary control bytes")
			}
		}
	}
	cases, _, input, err := continuationCases(context.Background(), root, spec, "metadata")
	if err != nil || len(cases) != 12 {
		t.Fatal("required source/profile dimensions lost", len(cases), err)
	}
	if err = input.verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	writeControl(t, native, "macos-15-hfsplus.raw", "changed input")
	if err = input.verify(context.Background()); err == nil {
		t.Fatal("changed native continuation accepted")
	}
	writeControl(t, native, "extra.raw", "unexpected source")
	if _, _, _, err = continuationCases(context.Background(), root, spec, "metadata"); err == nil {
		t.Fatal("extra continuation input accepted")
	}
}

func TestRecipeInventoryCannotOmitAnEntrypointOrChangeItsCorpus(t *testing.T) {
	root := replayControlModule(t, "valid")
	data, err := os.ReadFile(filepath.Join(root, "acceptance/qualification/registry.json"))
	var r registry
	if err == nil {
		err = corpus.StrictJSON(data, &r)
	}
	if err != nil {
		t.Fatal(err)
	}
	contract, err := readReplayContract(root, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*replayContract){func(c *replayContract) { c.Tests = nil }, func(c *replayContract) { c.Tests[0].Input = "missing" }, func(c *replayContract) { c.Tests[0].Input = "" }} {
		copy := contract
		copy.Tests = append([]replayTest(nil), contract.Tests...)
		change(&copy)
		data, err := json.Marshal(copy)
		if err != nil {
			t.Fatal(err)
		}
		writeControl(t, root, "acceptance/qualification/replay.json", string(data))
		if _, err = readReplayContract(root, r); err == nil {
			t.Fatal("coverage omission accepted")
		}
	}
}

func TestIndependentCorpusWritersCannotShareScratch(t *testing.T) {
	root := replayControlModule(t, "valid")
	data, err := os.ReadFile(filepath.Join(root, "acceptance/qualification/registry.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r registry
	if err = corpus.StrictJSON(data, &r); err != nil {
		t.Fatal(err)
	}
	contract, err := readReplayContract(root, r)
	if err != nil {
		t.Fatal(err)
	}
	r.Families[0].Tests = append(r.Families[0].Tests, entrypoint{Name: "TestReferenceSibling", File: "acceptance/control_test.go"})
	r.Families[0].Corpora = append(r.Families[0].Corpora, "acceptance/testdata/hfs-control")
	contract.Inputs = append(contract.Inputs, replayInput{ID: "hfs-control", Environment: "APFS_NATIVE_HFS_CONTROL"})
	sibling := contract.Tests[0]
	sibling.Test = "TestReferenceSibling"
	sibling.Input = "hfs-control"
	contract.Tests = append(contract.Tests, sibling)
	data, err = json.Marshal(contract)
	if err != nil {
		t.Fatal(err)
	}
	writeControl(t, root, "acceptance/qualification/replay.json", string(data))
	if _, err = readReplayContract(root, r); err == nil {
		t.Fatal("independent writers shared an output root")
	}
}

func TestFreshRecoveryMatchesOriginalContractBehindRetainedIndex(t *testing.T) {
	for _, scenario := range []string{"apfs-checkpoint-recovery", "hfs-journal-recovery", "hfs-header-growth"} {
		spec := replayTest{Manifest: "macos-*/recovery.json", CaptureContract: scenario}
		original := corpus.Capture{Manifest: "macos-15/recovery.json", Major: 15, Role: "native-capture", Contract: scenario, Cases: []string{"cases/committed", "cases/interrupted"}}
		indexed := original
		indexed.Role = "retained-index"
		indexed.Contract += "-reference"
		reference := corpus.Entry{Captures: []corpus.Capture{indexed}}
		if err := matchCaptureCases(spec, corpus.Entry{Captures: []corpus.Capture{original}}, reference); err != nil {
			t.Fatal("fresh original rejected in favor of retained index", err)
		}
		changed := original
		changed.Contract = "different-native-contract"
		if err := matchCaptureCases(spec, corpus.Entry{Captures: []corpus.Capture{changed}}, reference); err == nil {
			t.Fatal("unreviewed original contract admitted")
		}
		changed = original
		changed.Cases = []string{"cases/committed"}
		if err := matchCaptureCases(spec, corpus.Entry{Captures: []corpus.Capture{changed}}, reference); err == nil {
			t.Fatal("projection dropped a required case")
		}
	}
}

func TestReadableIndexesAlwaysDeclareOriginalCaptureContracts(t *testing.T) {
	root := "../.."
	data, err := regularFile(root, "acceptance/qualification/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var registry registry
	if err = corpus.StrictJSON(data, &registry); err != nil {
		t.Fatal(err)
	}
	recipes, err := readReplayContract(root, registry)
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filepath.Join(root, "acceptance/qualification/corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	catalog, err := corpus.Read(file)
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range recipes.Tests {
		for _, entry := range catalog.Entries {
			if entry.ID != spec.Input {
				continue
			}
			for _, capture := range entry.Captures {
				matched, err := path.Match(spec.Manifest, capture.Manifest)
				if err != nil {
					t.Fatal(err)
				}
				if matched && capture.Role == "retained-index" && spec.CaptureContract == "" {
					t.Errorf("%s must distinguish the original native contract from %s", spec.Test, capture.Contract)
				}
			}
		}
	}
}
