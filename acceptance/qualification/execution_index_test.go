package main

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

func comparisonInput(t *testing.T, id string, majors ...int) corpus.Entry {
	t.Helper()
	entry := corpus.Entry{ID: id, Bindings: []corpus.Binding{{Family: id, CaptureClass: "apple-independent"}}}
	for _, major := range majors {
		prefix := "macos-15/"
		if major == 26 {
			prefix = "macos-26/"
		}
		entry.Files = append(entry.Files, corpus.File{Path: prefix + "disk.raw.gz", Bytes: 42, SHA256: strings.Repeat("a", 64)})
		entry.Captures = append(entry.Captures, corpus.Capture{Manifest: prefix + "manifest.json", Major: major, OriginalSHA256: strings.Repeat("b", 64)})
	}
	var err error
	entry.TreeSHA256, err = entry.Identity()
	if err != nil {
		t.Fatal(err)
	}
	return entry
}

func TestExecutionIndexComparesCaseSourceBytesAcrossDifferentBatchSizes(t *testing.T) {
	one := comparisonInput(t, "apfs-editing", 15)
	all := comparisonInput(t, "apfs-editing", 15, 26)
	sibling := comparisonInput(t, "apfs-copy", 15)
	c := receipt.Case{Corpus: one.ID, Source: 15}
	spec := replayTest{Input: one.ID}
	project := func(entries ...corpus.Entry) []executionIndexedInput {
		t.Helper()
		inputs := []receipt.Input{}
		for position, entry := range entries {
			var err error
			entry.TreeSHA256, err = entry.Identity()
			if err != nil {
				t.Fatal(err)
			}
			entries[position] = entry
			inputs = append(inputs, receipt.Input{ID: entry.ID, TreeSHA256: entry.TreeSHA256, Use: "native-capture"})
		}
		actual, err := indexReplayCaseInputs(c, spec, replayEvidence{Schema: 1, Inputs: entries}, inputs, map[string]string{})
		if err != nil {
			t.Fatal(err)
		}
		return actual
	}
	first, batched := project(one), project(all, sibling)
	if one.TreeSHA256 == all.TreeSHA256 || !reflect.DeepEqual(first, batched) {
		t.Fatal("unrelated source versions or sibling capabilities changed this case's identity")
	}
	all.Files[1].SHA256 = strings.Repeat("c", 64)
	if !reflect.DeepEqual(first, project(all, sibling)) {
		t.Fatal("another macOS source version changed this case's identity")
	}
	all.Files[0].SHA256 = strings.Repeat("d", 64)
	if reflect.DeepEqual(first, project(all, sibling)) {
		t.Fatal("changed disk bytes inherited the original case input identity")
	}
}

func TestExecutionIndexPreservesEveryAdmittedCaseHostRaceOriginAndOutput(t *testing.T) {
	root, directory, origin := ciEvidenceControl(t)
	proof, err := checkCIEvidence(context.Background(), root, directory, origin)
	if err != nil {
		t.Fatal(err)
	}
	index, err := indexExecutionEvidence(context.Background(), root, directory, proof)
	if err != nil || !reflect.DeepEqual(index.Evidence, proof) || len(index.Cases) != 3 {
		t.Fatal("index lost original admitted execution scope", err)
	}
	outputs := 0
	if len(index.Invocations) != 1 {
		t.Fatal("one original invocation was repeated for individual cases")
	}
	invocation := index.Invocations[0]
	if invocation.Origin.Revision != origin.Origin.Revision || invocation.Origin.Run != origin.Origin.Run || invocation.Origin.Attempt != origin.Origin.Attempt || invocation.Origin.Job != "portable" || invocation.Environment.OS != origin.Artifacts[0].Host || invocation.Environment.Race || len(invocation.Environment.Tools) < 5 || invocation.Stage != "replay" {
		t.Fatal("invocation identity lost its actual execution provenance", invocation)
	}
	for _, item := range index.Cases {
		if len(item.Inputs) != 1 {
			t.Fatal("case identity lost its admitted input", item)
		}
		if item.Receipt != invocation.Receipt.SHA256 || invocation.Receipt != proof.Receipts[0] || len(item.Outputs) != len(item.Case.Outputs) {
			t.Fatal("case lost its original receipt or declared output bytes")
		}
		for _, output := range item.Outputs {
			if output.Bytes == 0 || !corpus.ValidDigest(output.SHA256) {
				t.Fatal("output identity is incomplete", output)
			}
		}
		outputs += len(item.Outputs)
	}
	if outputs != 2 {
		t.Fatal("UDRO or UDZO output identity disappeared", outputs)
	}
	for _, file := range proof.Receipts {
		actual, err := digestFile(context.Background(), directory, file.Path)
		if err != nil || actual != file {
			t.Fatal("indexing rewrote original evidence", err)
		}
	}
}

func TestExecutionIndexKeepsAuxiliaryInputsAndNativeContinuationIdentities(t *testing.T) {
	primary := comparisonInput(t, "apfs-lifecycle", 15)
	auxiliary := comparisonInput(t, "snapshots", 15)
	metadata := replayEvidence{Schema: 1, Inputs: []corpus.Entry{primary, auxiliary}}
	inputs := []receipt.Input{
		{ID: primary.ID, TreeSHA256: primary.TreeSHA256, Use: "native-capture"},
		{ID: auxiliary.ID, TreeSHA256: auxiliary.TreeSHA256, Use: "native-capture"},
	}
	c := receipt.Case{Corpus: primary.ID, Source: 15}
	spec := replayTest{Input: primary.ID, Auxiliary: []string{auxiliary.ID}}
	actual, err := indexReplayCaseInputs(c, spec, metadata, inputs, map[string]string{})
	if err != nil || len(actual) != 2 || actual[0].ID != primary.ID || actual[1].ID != auxiliary.ID {
		t.Fatal("case lost a required auxiliary input", err)
	}
	if _, err = indexReplayCaseInputs(c, spec, metadata, inputs[:1], map[string]string{}); err == nil {
		t.Fatal("missing auxiliary identity was silently discarded")
	}
	if _, err = indexReplayCaseInputs(c, spec, replayEvidence{Inputs: []corpus.Entry{primary}}, inputs, map[string]string{}); err == nil {
		t.Fatal("missing auxiliary original source snapshot was admitted")
	}
	continued := receipt.Input{ID: "apfs-after-apple", TreeSHA256: strings.Repeat("e", 64), Use: "native-continuation"}
	actual, err = indexReplayCaseInputs(receipt.Case{Corpus: continued.ID, Source: 15, Continuation: true}, replayTest{}, replayEvidence{}, []receipt.Input{continued}, map[string]string{})
	if err != nil || len(actual) != 1 || actual[0].Identity != continued.TreeSHA256 || actual[0].Use != continued.Use {
		t.Fatal("fresh Apple continuation was relabelled as an immutable source", err)
	}
}

func TestExecutionIndexDoesNotReadAChangedAdmittedReceipt(t *testing.T) {
	root := "../.."
	directory := t.TempDir()
	writeControl(t, directory, "original.json", `{}`)
	file, err := digestFile(context.Background(), directory, "original.json")
	if err != nil {
		t.Fatal(err)
	}
	file.SHA256 = strings.Repeat("f", 64)
	_, err = indexExecutionEvidence(context.Background(), root, directory, executionEvidenceSummary{Schema: 1, Receipts: []receipt.File{file}})
	if err == nil || !strings.Contains(err.Error(), "receipt changed") {
		t.Fatal("changed original execution bytes entered comparison", err)
	}
}
