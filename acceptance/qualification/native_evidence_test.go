package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

func TestRestoredNativeInputsBindTheReviewedPinWithoutAssertionVerdicts(t *testing.T) {
	root, directory := t.TempDir(), t.TempDir()
	pin := `{"catalog":{"sha256":"` + strings.Repeat("a", 64) + `"},"schema":1}`
	writeControl(t, root, "acceptance/qualification/references.json", pin)
	sum := sha256.Sum256([]byte(pin))
	for _, major := range []string{"15", "26", "27"} {
		text := `{"schema":1,"kind":"approved-native-input-admission","assertions_executed":false,"source_major":` + major + `,"pin_sha256":"` + hex.EncodeToString(sum[:]) + `","catalog_sha256":"` + strings.Repeat("a", 64) + `"}`
		writeControl(t, directory, "capture-approved-"+major+"/admission.json", text)
	}
	if err := checkRestoredInputEvidence(context.Background(), root, directory); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "capture-approved-26/admission.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, bytes.Replace(data, []byte(`"assertions_executed":false`), []byte(`"assertions_executed":true`), 1), 0600); err != nil {
		t.Fatal(err)
	}
	if err = checkRestoredInputEvidence(context.Background(), root, directory); err == nil {
		t.Fatal("restored input receipt invented an executed assertion")
	}
	if err = os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	writeControl(t, root, "acceptance/qualification/references.json", pin+"\n")
	if err = checkRestoredInputEvidence(context.Background(), root, directory); err == nil {
		t.Fatal("changed reviewed pin inherited old input admissions")
	}
}

// These controls manufacture ledger records for ordinary byte files. They
// exercise evidence admission and never invoke native filesystem programs.
func storeNativeEvidenceControl(t *testing.T, directory, prefix string, plan receipt.Plan, origin receipt.Origin, outputs []receipt.File) {
	t.Helper()
	var events bytes.Buffer
	encoder := json.NewEncoder(&events)
	write := func(action, name string) {
		t.Helper()
		if err := encoder.Encode(receipt.Event{Action: action, Package: "apple-native", Test: name}); err != nil {
			t.Fatal(err)
		}
	}
	write("start", "")
	for _, name := range plan.RequiredRuns {
		write("run", name)
		write("pass", name)
	}
	write("pass", "")
	verdicts, err := receipt.CheckEvents(bytes.NewReader(events.Bytes()), plan, nil, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	writeControl(t, directory, prefix+"events.jsonl", events.String())
	eventFile, err := digestFile(context.Background(), directory, prefix+"events.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	fingerprint, err := plan.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	record := receipt.Receipt{Schema: 1, Plan: plan, Fingerprint: fingerprint, Origin: origin, Verdicts: verdicts, Outputs: outputs, Events: eventFile}
	for name, value := range map[string]any{"plan.json": plan, "receipt.json": record} {
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		writeControl(t, directory, prefix+name, string(data))
	}
}

func nativeEvidenceControl(t *testing.T) (string, string, executionEvidenceOrigin) {
	t.Helper()
	root, directory, origin := ciEvidenceControl(t)
	old := filepath.Join(directory, origin.Artifacts[0].Name)
	origin.Workflow = "native"
	origin.Artifacts[0].Name = "qualification-native-portable-0"
	producer := filepath.Join(directory, origin.Artifacts[0].Name)
	if err := os.Rename(old, producer); err != nil {
		t.Fatal(err)
	}
	paths, err := filepath.Glob(filepath.Join(producer, "replay-*", "receipt.json"))
	if err != nil || len(paths) != 1 {
		t.Fatal("original portable receipt missing", err)
	}
	var portable receipt.Receipt
	if err = readEvidenceDocument(paths[0], &portable); err != nil {
		t.Fatal(err)
	}
	contract, err := nativeSourceContract(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	tools := make([]receipt.File, 7)
	for index := range tools {
		tools[index] = receipt.File{Path: "tools/" + string(rune('a'+index)), Bytes: 1, SHA256: strings.Repeat("a", 64)}
	}
	environment := receipt.Environment{OS: "darwin", Architecture: "arm64", Version: "26.0", Build: "control-build", Toolchain: "Python control", Flags: []string{}, Tools: tools}
	var cases []receipt.Case
	var files []receipt.File
	for _, file := range portable.Outputs {
		if strings.HasSuffix(file.Path, ".dmg") {
			files = append(files, file)
			cases = append(cases, receipt.Case{Family: "geometry-control", Test: "native/" + file.Path, NativeCase: "control", Outputs: []string{file.Path}})
		}
	}
	slices.SortFunc(cases, func(a, b receipt.Case) int { return strings.Compare(a.Test, b.Test) })
	plan := receipt.Plan{Schema: 1, Stage: "apple-verification", Contract: contract, Production: portable.Plan.Production, Inputs: []receipt.Input{}, Outputs: files, Environment: environment, Cases: cases, RequiredRuns: receipt.RequiredRuns(cases, nil)}
	readback := executionEvidenceArtifact{Name: "qualification-native-readback-0", Job: "readback", Host: "darwin", Major: 26}
	base := filepath.Join(directory, readback.Name)
	storeNativeEvidenceControl(t, base, "verified.", plan, receipt.Origin{Revision: origin.Origin.Revision, Run: "123", Attempt: "1", Job: "readback"}, files)
	// Apple archives legitimately carry the byte-identical producer ledger.
	if err = os.CopyFS(filepath.Join(base, "outputs", ".qualification", portable.Fingerprint), os.DirFS(filepath.Dir(paths[0]))); err != nil {
		t.Fatal(err)
	}
	// Published output copies use the richer source snapshot as inputs.json.
	snapshot, err := os.ReadFile(filepath.Join(filepath.Dir(paths[0]), "source-inputs.json"))
	if err != nil {
		t.Fatal(err)
	}
	var metadata replayEvidence
	if err = json.Unmarshal(snapshot, &metadata); err != nil {
		t.Fatal(err)
	}
	metadata.OutputEnvironment = "APFS_GEOMETRY_OUTPUT"
	snapshot, err = json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	writeControl(t, base, filepath.Join("outputs", ".qualification", portable.Fingerprint, "inputs.json"), string(snapshot))
	origin.Artifacts = append(origin.Artifacts, readback)
	return root, directory, origin
}

func TestNativeInheritanceRequiresOriginalExecutorsAndAppleEvents(t *testing.T) {
	root, directory, origin := nativeEvidenceControl(t)
	result, err := checkNativeEvidence(context.Background(), root, directory, origin)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Receipts) != 2 || result.CaseCount != 5 || result.Origin != origin.Origin {
		t.Fatal("copied producer evidence changed original counts or origin", result)
	}
	for _, mutation := range []string{"tree", "attempt", "host", "major", "missing", "duplicate"} {
		t.Run(mutation, func(t *testing.T) {
			changed := origin
			changed.Artifacts = slices.Clone(origin.Artifacts)
			switch mutation {
			case "tree":
				changed.Tree = strings.Repeat("a", 40)
			case "attempt":
				changed.Origin.Attempt = "2"
			case "host":
				changed.Artifacts[1].Host = "linux"
			case "major":
				changed.Artifacts[1].Major = 15
			case "missing":
				changed.Artifacts = changed.Artifacts[1:]
			case "duplicate":
				changed.Artifacts = append(changed.Artifacts, changed.Artifacts[0])
			}
			if _, err = checkNativeEvidence(context.Background(), root, directory, changed); err == nil {
				t.Fatal("incomplete or incompatible native campaign was inherited")
			}
		})
	}
	producer := filepath.Join(directory, origin.Artifacts[0].Name)
	hidden := producer + ".hidden"
	if err = os.Rename(producer, hidden); err != nil {
		t.Fatal(err)
	}
	// Remove the original executor directory while retaining its readback copy.
	changed := origin
	changed.Artifacts = changed.Artifacts[1:]
	other := t.TempDir()
	if err = os.Rename(hidden, filepath.Join(other, "original")); err != nil {
		t.Fatal(err)
	}
	if _, err = checkNativeEvidence(context.Background(), root, directory, changed); err == nil {
		t.Fatal("copied Go evidence replaced its original executor")
	}
	if err = os.Rename(filepath.Join(other, "original"), producer); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, origin.Artifacts[1].Name, "verified.events.jsonl")
	events, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	writeControl(t, directory, filepath.Join(origin.Artifacts[1].Name, "verified.events.jsonl"), string(events)+"\n")
	if _, err = checkNativeEvidence(context.Background(), root, directory, origin); err == nil {
		t.Fatal("altered original Apple events inherited a verdict")
	}
	writeControl(t, directory, filepath.Join(origin.Artifacts[1].Name, "verified.events.jsonl"), string(events))
	paths, err := filepath.Glob(filepath.Join(producer, "replay-*", "source-inputs.json"))
	if err != nil || len(paths) != 1 {
		t.Fatal("original input snapshot absent", err)
	}
	var metadata replayEvidence
	if err = readEvidenceDocument(paths[0], &metadata); err != nil {
		t.Fatal(err)
	}
	metadata.Inputs[0].Files[0].SHA256 = strings.Repeat("b", 64)
	data, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(paths[0], data, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = checkNativeEvidence(context.Background(), root, directory, origin); err == nil {
		t.Fatal("changed original source snapshot inherited a verdict")
	}
}

func TestNativeInheritanceUsesProducerEvidenceWithoutUploadingReadbackCopies(t *testing.T) {
	root, directory, origin := nativeEvidenceControl(t)
	if err := os.RemoveAll(filepath.Join(directory, origin.Artifacts[1].Name, "outputs", ".qualification")); err != nil {
		t.Fatal(err)
	}
	proof, err := checkNativeEvidence(context.Background(), root, directory, origin)
	if err != nil || len(proof.Receipts) != 2 || proof.CaseCount != 5 || proof.Origin != origin.Origin {
		t.Fatal("complete original producer/Apple evidence required duplicate consumer metadata", proof, err)
	}
}

func TestNativeOutputInheritanceRequiresMatchingSourceAndIndividualCiphertext(t *testing.T) {
	root := replayControlModule(t, "valid")
	file := receipt.File{Path: "outputs/encrypted/file.dmg", Bytes: 10, SHA256: strings.Repeat("a", 64)}
	c := receipt.Case{Family: "geometry-control", Test: "TestReference/macos-15/apfs/UDRO", Source: 15, Outputs: []string{file.Path}}
	r := registry{Families: []family{{ID: c.Family, NativeMajors: []int{15, 26}}}}
	records := map[string]receipt.Receipt{"portable": {Plan: receipt.Plan{Stage: "replay", Cases: []receipt.Case{c}}, Outputs: []receipt.File{file}}}
	coverage := referenceCoverage{native: map[int]map[string]bool{15: {nativeFileKey(file): true}}, single: map[int]map[string]map[string]bool{}}
	if err := checkNativeOutputEvidence(root, r, records, &coverage); err == nil {
		t.Fatal("missing native version inherited output verification")
	}
	coverage.native[26] = map[string]bool{nativeFileKey(file): true}
	if err := checkNativeOutputEvidence(root, r, records, &coverage); err == nil {
		t.Fatal("combined ciphertext evidence replaced an individual check")
	}
	for _, major := range []int{15, 26} {
		coverage.single[major] = map[string]map[string]bool{nativeFileKey(file): {"original-native-scope": true}}
	}
	if err := checkNativeOutputEvidence(root, r, records, &coverage); err != nil {
		t.Fatal(err)
	}
	records["second-host"] = records["portable"]
	if err := checkNativeOutputEvidence(root, r, records, &coverage); err == nil {
		t.Fatal("one native ciphertext verdict replaced a second output")
	}
	delete(records, "second-host")
	var recipes replayContract
	data, err := regularFile(root, "acceptance/qualification/replay.json")
	if err != nil || json.Unmarshal(data, &recipes) != nil {
		t.Fatal("control recipe missing", err)
	}
	recipes.Tests[0].NativeScope = "matching-source"
	data, err = json.Marshal(recipes)
	if err != nil {
		t.Fatal(err)
	}
	writeControl(t, root, "acceptance/qualification/replay.json", string(data))
	delete(coverage.native, 26)
	if err := checkNativeOutputEvidence(root, r, records, &coverage); err != nil {
		t.Fatal("matching-source native scope required an unrelated Apple source version", err)
	}
	record := records["portable"]
	record.Plan.Cases[0].Source = 26
	records["portable"] = record
	if err := checkNativeOutputEvidence(root, r, records, &coverage); err == nil {
		t.Fatal("matching-source native scope accepted another source version")
	}
}

func TestNativeContinuationRequiresAppleVerificationOnItsActualWriterVersion(t *testing.T) {
	root := replayControlModule(t, "valid")
	var recipes replayContract
	data, err := regularFile(root, "acceptance/qualification/replay.json")
	if err != nil || json.Unmarshal(data, &recipes) != nil {
		t.Fatal("control replay policy missing", err)
	}
	recipes.Tests[0].Layout = "continuation"
	data, err = json.Marshal(recipes)
	if err != nil {
		t.Fatal(err)
	}
	writeControl(t, root, "acceptance/qualification/replay.json", string(data))
	file := receipt.File{Path: "continued/macos-15-apfs.dmg", Bytes: 10, SHA256: strings.Repeat("a", 64)}
	c := receipt.Case{Family: "geometry-control", Test: "TestReference/macos-15/apfs/UDRO", Corpus: "native-modified", Source: 15, Continuation: true, Outputs: []string{file.Path}}
	r := registry{Families: []family{{ID: c.Family, NativeMajors: []int{15, 26, 27}}}}
	plan := receipt.Plan{Stage: "replay", Cases: []receipt.Case{c}, Inputs: []receipt.Input{{ID: c.Corpus, Use: "native-continuation", TreeSHA256: strings.Repeat("b", 64)}}, Environment: receipt.Environment{OS: "darwin", Version: "26.6.2"}}
	coverage := referenceCoverage{native: map[int]map[string]bool{26: {nativeFileKey(file): true}}}
	for _, mutation := range []string{"valid", "wrong-verifier", "missing-verifier", "missing-input", "wrong-input-use", "wrong-host", "unknown-writer", "unmarked-case"} {
		t.Run(mutation, func(t *testing.T) {
			changed := plan
			changed.Cases = append([]receipt.Case(nil), plan.Cases...)
			changed.Inputs = append([]receipt.Input(nil), plan.Inputs...)
			proof := coverage
			switch mutation {
			case "wrong-verifier":
				proof.native = map[int]map[string]bool{15: {nativeFileKey(file): true}}
			case "missing-verifier":
				proof.native = map[int]map[string]bool{}
			case "missing-input":
				changed.Inputs = nil
			case "wrong-input-use":
				changed.Inputs[0].Use = "retained"
			case "wrong-host":
				changed.Environment.OS = "linux"
			case "unknown-writer":
				changed.Environment.Version = "99.0"
			case "unmarked-case":
				changed.Cases[0].Continuation = false
			}
			err := checkNativeOutputEvidence(root, r, map[string]receipt.Receipt{"original": {Plan: changed, Outputs: []receipt.File{file}}}, &proof)
			if (err == nil) != (mutation == "valid") {
				t.Fatalf("native continuation scope %s: %v", mutation, err)
			}
		})
	}
}
