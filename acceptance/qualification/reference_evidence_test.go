package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

func TestCandidateCoverageRequiresOriginalManifestHostRaceAndControls(t *testing.T) {
	root := replayControlModule(t, "valid")
	data, err := os.ReadFile(filepath.Join(root, "acceptance/qualification/corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := corpus.Read(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	entry := catalog.Entries[0]
	entry.Files = append(entry.Files, corpus.File{Path: "macos-15/source.raw.gz", Bytes: 16, SHA256: strings.Repeat("d", 64)})
	slices.SortFunc(entry.Files, func(a, b corpus.File) int { return strings.Compare(a.Path, b.Path) })
	entry.TreeSHA256, err = entry.Identity()
	if err != nil {
		t.Fatal(err)
	}
	inputSHA256, err := referenceSourceIdentity(entry, 15)
	if err != nil {
		t.Fatal(err)
	}
	c := receipt.Case{Family: "geometry-control", Test: "TestReference/macos-15/apfs/UDRO", Corpus: entry.ID, Manifest: entry.Captures[0].Manifest, NativeCase: "cases/apfs", Source: 15, Variant: "UDRO", Outputs: []string{"APFS_GEOMETRY_OUTPUT/macos-15/apfs/edited-UDRO.dmg"}}
	for _, scenario := range []string{"valid", "reader-without-output-archive", "missing-control", "wrong-host", "wrong-race", "other-manifest", "changed-source-snapshot", "changed-disk-with-original-manifest"} {
		t.Run(scenario, func(t *testing.T) {
			directory := filepath.Join(t.TempDir(), "outputs/.qualification/execution")
			if scenario == "reader-without-output-archive" {
				directory = filepath.Join(t.TempDir(), "replay-execution")
			}
			if err := os.MkdirAll(directory, 0700); err != nil {
				t.Fatal(err)
			}
			metadata := replayEvidence{Schema: 1, OutputEnvironment: "APFS_GEOMETRY_OUTPUT", Inputs: []corpus.Entry{entry}, Continuations: []continuationEvidence{}}
			record := receipt.Receipt{Plan: receipt.Plan{Stage: "replay", Cases: []receipt.Case{c}, Inputs: []receipt.Input{{ID: entry.ID, TreeSHA256: entry.TreeSHA256, Use: "native-capture"}}, Environment: receipt.Environment{OS: "linux", Race: true, Flags: []string{"required-controls=copy-setid"}}}, Outputs: []receipt.File{{Path: c.Outputs[0], Bytes: 1, SHA256: strings.Repeat("a", 64)}}}
			obligation := referenceObligation{Case: c, Host: "linux", Race: true, ManifestSHA256: entry.Captures[0].OriginalSHA256, InputSHA256: inputSHA256, Controls: []string{"copy-setid"}}
			switch scenario {
			case "missing-control":
				record.Plan.Environment.Flags = []string{"required-controls="}
			case "wrong-host":
				record.Plan.Environment.OS = "windows"
			case "wrong-race":
				record.Plan.Environment.Race = false
			case "other-manifest":
				obligation.ManifestSHA256 = strings.Repeat("b", 64)
			case "changed-source-snapshot":
				metadata.Inputs[0].TreeSHA256 = strings.Repeat("c", 64)
			case "changed-disk-with-original-manifest":
				metadata.Inputs[0].Files = slices.Clone(entry.Files)
				metadata.Inputs[0].Files[1].SHA256 = strings.Repeat("e", 64)
				metadata.Inputs[0].TreeSHA256, err = metadata.Inputs[0].Identity()
				if err != nil {
					t.Fatal(err)
				}
				record.Plan.Inputs[0].TreeSHA256 = metadata.Inputs[0].TreeSHA256
			}
			metadataFile := "inputs.json"
			if scenario == "reader-without-output-archive" {
				metadataFile = "source-inputs.json"
				metadata.OutputEnvironment = ""
				record.Plan.Cases[0].Outputs = nil
				obligation.Case.Outputs = nil
				record.Outputs = []receipt.File{}
			}
			if err := newJSON(filepath.Join(directory, metadataFile), metadata); err != nil {
				t.Fatal(err)
			}
			key, err := referenceCaseKey(obligation.Case, obligation.Host, obligation.Race)
			if err != nil {
				t.Fatal(err)
			}
			coverage := referenceCoverage{portable: map[string]map[string]receipt.File{}, required: map[string]referenceObligation{key: obligation}}
			err = collectReferenceCoverage(context.Background(), directory, record, &coverage)
			if scenario == "changed-source-snapshot" {
				if err == nil {
					t.Fatal("rehashed source snapshot admitted")
				}
				return
			}
			if err != nil || (len(coverage.portable) == 1) != (scenario == "valid" || scenario == "reader-without-output-archive") {
				t.Fatal("candidate case coverage admitted without original obligations", scenario, err)
			}
		})
	}
}

func TestSourceProjectionPreservesExactSelectedNativeFilesAcrossJobShapes(t *testing.T) {
	entry := corpus.Entry{ID: "files", Bindings: []corpus.Binding{{Family: "reading", CaptureClass: "apple-independent"}},
		Files:    []corpus.File{{Path: "macos-15/source.gz", Bytes: 4, SHA256: strings.Repeat("a", 64)}},
		Captures: []corpus.Capture{{Manifest: "macos-15/manifest.json", Major: 15, OriginalSHA256: strings.Repeat("b", 64)}}}
	want, err := referenceSourceIdentity(entry, 15)
	if err != nil {
		t.Fatal(err)
	}
	entry.Files = append(entry.Files, corpus.File{Path: "macos-26/source.gz", Bytes: 8, SHA256: strings.Repeat("c", 64)}, corpus.File{Path: "metadata/macos-15/manifest.json", Bytes: 5, SHA256: strings.Repeat("d", 64)})
	entry.Captures = append(entry.Captures, corpus.Capture{Manifest: "metadata/macos-15/manifest.json", Major: 15})
	got, err := referenceSourceIdentity(entry, 15)
	if err != nil || got != want {
		t.Fatal("unrelated source or sibling capability changed a source projection", err)
	}
	entry.Files = append(entry.Files, corpus.File{Path: "macos-15/extra.gz", Bytes: 1, SHA256: strings.Repeat("e", 64)})
	got, err = referenceSourceIdentity(entry, 15)
	if err != nil || got == want {
		t.Fatal("extra bytes within the selected original source were ignored", err)
	}
	if _, err = referenceSourceIdentity(entry, 27); err == nil {
		t.Fatal("absent source version admitted")
	}
}

func TestRepackingAuxiliaryCasesBindTheirActualEncryptedSource(t *testing.T) {
	ctx := context.Background()
	root := replayControlModule(t, "repacking")
	data, err := os.ReadFile(filepath.Join(root, "acceptance/qualification/corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := corpus.Read(strings.NewReader(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := corpus.New(catalog, corpus.Options{Repository: root})
	if err != nil {
		t.Fatal(err)
	}
	primary := catalog.Entries[0]
	source, err := resolver.Resolve(ctx, primary.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	auxiliary := primary
	auxiliary.ID = "encrypted-dmg"
	auxiliary.Captures = slices.Clone(primary.Captures)
	auxiliary.Captures[0].OriginalSHA256 = strings.Repeat("e", 64)
	inputs := map[string]corpus.Entry{primary.ID: primary, auxiliary.ID: auxiliary}
	recipes := replayContract{Tests: []replayTest{{Test: "TestReference", Input: primary.ID, Auxiliary: []string{auxiliary.ID}, Manifest: "macos-*/manifest.json", Layout: "repacking"}}}
	families := map[string]family{"TestReference": {ID: "repacking", PortableHosts: []string{"linux"}}}
	var want referenceObligations
	if err = appendReferenceCases(&want, primary, source, recipes, families, inputs); err != nil {
		t.Fatal(err)
	}
	identity, err := referenceSourceIdentity(auxiliary, 15)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, obligation := range want.Cases {
		if obligation.Case.Corpus != auxiliary.ID {
			continue
		}
		count++
		if obligation.ManifestSHA256 != auxiliary.Captures[0].OriginalSHA256 || obligation.InputSHA256 != identity {
			t.Fatal("auxiliary encrypted input was attributed to the repacking control", obligation)
		}
	}
	if count != 2 {
		t.Fatal("encrypted raw-input branches missing", count)
	}
	delete(inputs, auxiliary.ID)
	if err = appendReferenceCases(&referenceObligations{}, primary, source, recipes, families, inputs); err == nil {
		t.Fatal("absent auxiliary input silently substituted its primary corpus")
	}
}

func TestNativeExecutionContractMatchesOriginalPythonWireIdentity(t *testing.T) {
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	want, err := nativeSourceContract(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(python, "-c", "import sys; sys.path.insert(0,sys.argv[1]+'/acceptance/native'); from qualification import native_contract; print(native_contract(sys.argv[1]))", root)
	actual, err := command.CombinedOutput()
	if err != nil || strings.TrimSpace(string(actual)) != want {
		t.Fatal("native source identity differs across wire implementations", string(actual), err)
	}
}

func TestCandidateCaptureCoverageRequiresOriginalObservationBytes(t *testing.T) {
	directory := t.TempDir()
	observation := map[string]any{"manifest": "macos-15/manifest.json", "manifest_sha256": strings.Repeat("a", 64), "native_case": "cases/apfs", "observation": map[string]any{"id": "apfs"}}
	data, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	writeControl(t, directory, "observation.json", string(data))
	file, err := digestFile(context.Background(), directory, "observation.json")
	if err != nil {
		t.Fatal(err)
	}
	c := receipt.Case{Corpus: "apfs-geometry", Manifest: "macos-15/manifest.json", NativeCase: "cases/apfs", Source: 15, Outputs: []string{"observation.json"}}
	record := receipt.Receipt{Plan: receipt.Plan{Stage: "capture", Cases: []receipt.Case{c}}, Outputs: []receipt.File{file}}
	coverage := referenceCoverage{captured: map[string]bool{}}
	if err = collectReferenceCoverage(context.Background(), directory, record, &coverage); err != nil || !coverage.captured[capturedCaseKey(c, strings.Repeat("a", 64))] {
		t.Fatal("original capture observation was not bound", err)
	}
	writeControl(t, directory, "observation.json", string(data)+" ")
	if err = collectReferenceCoverage(context.Background(), directory, record, &coverage); err == nil {
		t.Fatal("changed capture observation admitted")
	}
}

func TestNativeCiphertextEvidenceNeedsSeparateScopesAndDoesNotCountCopiesTwice(t *testing.T) {
	files := []receipt.File{{Path: "left.dmg", Bytes: 5, SHA256: strings.Repeat("a", 64)}, {Path: "right.dmg", Bytes: 5, SHA256: strings.Repeat("b", 64)}}
	record := receipt.Receipt{Fingerprint: strings.Repeat("c", 64), Plan: receipt.Plan{Stage: "apple-verification", Environment: receipt.Environment{Version: "26.0"}, Outputs: files,
		Cases: []receipt.Case{{Test: "native/combined", Outputs: []string{"left.dmg", "right.dmg"}}}}}
	coverage := referenceCoverage{native: map[int]map[string]bool{}, single: map[int]map[string]map[string]bool{}}
	if err := collectReferenceCoverage(context.Background(), t.TempDir(), record, &coverage); err != nil {
		t.Fatal(err)
	}
	if len(coverage.native[26]) != 2 || len(coverage.single[26]) != 0 {
		t.Fatal("combined native scope granted individual ciphertext verdicts")
	}
	record.Plan.Cases = []receipt.Case{{Test: "native/left", Outputs: []string{"left.dmg"}}, {Test: "native/right", Outputs: []string{"right.dmg"}}}
	for range 2 {
		if err := collectReferenceCoverage(context.Background(), t.TempDir(), record, &coverage); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range files {
		if len(coverage.single[26][nativeFileKey(file)]) != 1 {
			t.Fatal("copies of one original native scope counted as multiple ciphertext checks")
		}
	}
}
