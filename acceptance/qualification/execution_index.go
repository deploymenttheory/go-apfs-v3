package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/replay"
)

// An index describes original execution evidence after admission. It does not
// grant another filesystem verdict or approve the removal of an execution.
type executionIndex struct {
	Evidence    executionEvidenceSummary     `json:"evidence"`
	Invocations []executionIndexedInvocation `json:"invocations"`
	Cases       []executionIndexedCase       `json:"cases"`
	Tests       []executionIndexedTest       `json:"test_executions"`
}

type executionIndexedInput struct {
	ID       string `json:"id"`
	Identity string `json:"source_sha256"`
	Use      string `json:"use"`
}

type executionIndexedInvocation struct {
	Origin      receipt.Origin      `json:"origin"`
	Receipt     receipt.File        `json:"original_receipt"`
	Stage       string              `json:"stage"`
	Production  string              `json:"production_sha256"`
	Environment receipt.Environment `json:"environment"`
}

type executionIndexedCase struct {
	Receipt  string                  `json:"original_receipt_sha256"`
	Case     receipt.Case            `json:"case"`
	Controls []string                `json:"required_controls"`
	Inputs   []executionIndexedInput `json:"inputs"`
	Outputs  []receipt.File          `json:"outputs"`
}

func indexExecutionEvidence(ctx context.Context, root, directory string, summary executionEvidenceSummary) (executionIndex, error) {
	index := executionIndex{Evidence: summary, Invocations: []executionIndexedInvocation{}, Cases: []executionIndexedCase{}, Tests: []executionIndexedTest{}}
	data, err := regularFile(root, "acceptance/qualification/registry.json")
	if err != nil {
		return index, err
	}
	var registry registry
	if err = corpus.StrictJSON(data, &registry); err != nil {
		return index, err
	}
	recipes, err := readReplayContract(root, registry)
	if err != nil {
		return index, err
	}
	specs := map[string]replayTest{}
	for _, spec := range recipes.Tests {
		specs[spec.Test] = spec
	}
	for _, original := range summary.Receipts {
		actual, err := digestFile(ctx, directory, original.Path)
		if err != nil || actual != original {
			return index, errors.Join(err, errors.New("admitted original receipt changed before indexing"))
		}
		name := filepath.Join(directory, filepath.FromSlash(original.Path))
		var record receipt.Receipt
		if err = readEvidenceDocument(name, &record); err != nil {
			return index, err
		}
		metadata := replayEvidence{}
		controls := map[string]bool{}
		if record.Plan.Stage == "replay" {
			tests, err := indexReplayTests(ctx, filepath.Dir(name), original.SHA256, record)
			if err != nil {
				return index, err
			}
			index.Tests = append(index.Tests, tests...)
			for _, flag := range record.Plan.Environment.Flags {
				if value, ok := strings.CutPrefix(flag, "required-controls="); ok {
					controls, err = replay.RequiredControls(value)
					if err != nil {
						return index, err
					}
				}
			}
			base := filepath.Dir(name)
			if err = checkReplaySourceEvidence(base, record.Plan); err != nil {
				return index, err
			}
			member := "source-inputs.json"
			if strings.Contains(filepath.ToSlash(base), "/.qualification/") {
				member = "inputs.json"
			}
			if err = readEvidenceDocument(filepath.Join(base, member), &metadata); err != nil {
				return index, err
			}
		}
		outputs := map[string]receipt.File{}
		sourceCache := map[string]string{}
		for _, file := range record.Outputs {
			outputs[file.Path] = file
		}
		index.Invocations = append(index.Invocations, executionIndexedInvocation{
			Origin: record.Origin, Receipt: original, Stage: record.Plan.Stage,
			Production: record.Plan.Production, Environment: record.Plan.Environment,
		})
		for _, c := range record.Plan.Cases {
			if err = ctx.Err(); err != nil {
				return index, err
			}
			item := executionIndexedCase{Receipt: original.SHA256, Case: c,
				Inputs: []executionIndexedInput{}, Outputs: []receipt.File{}, Controls: []string{}}
			if record.Plan.Stage == "replay" {
				spec := specs[strings.Split(c.Test, "/")[0]]
				for _, control := range spec.Controls {
					if controls[control] {
						item.Controls = append(item.Controls, control)
					}
				}
				slices.Sort(item.Controls)
				item.Inputs, err = indexReplayCaseInputs(c, spec, metadata, record.Plan.Inputs, sourceCache)
				if err != nil {
					return index, err
				}
			} else {
				for _, input := range record.Plan.Inputs {
					item.Inputs = append(item.Inputs, executionIndexedInput{input.ID, input.TreeSHA256, input.Use})
				}
			}
			for _, name := range c.Outputs {
				file, exists := outputs[name]
				if !exists {
					return index, fmt.Errorf("admitted case lost its output identity: %s", name)
				}
				item.Outputs = append(item.Outputs, file)
			}
			index.Cases = append(index.Cases, item)
		}
	}
	if len(index.Cases) != summary.CaseCount {
		return index, errors.New("indexed case count differs from admitted evidence")
	}
	return index, nil
}

// Batching can bind additional siblings or all three source versions. Compare
// only this case's declared primary/auxiliary inputs, retaining the exact files
// and original capture documents within the source version. No bytes change.
func indexReplayCaseInputs(c receipt.Case, spec replayTest, metadata replayEvidence, inputs []receipt.Input, cache map[string]string) ([]executionIndexedInput, error) {
	result := []executionIndexedInput{}
	if c.Corpus == "" {
		return result, nil // Ordinary library assertions have no native corpus.
	}
	ids := append([]string{c.Corpus}, spec.Auxiliary...)
	if spec.Input != "" {
		ids = append(ids, spec.Input)
	}
	slices.Sort(ids)
	ids = slices.Compact(ids)
	for _, id := range ids {
		position := slices.IndexFunc(inputs, func(input receipt.Input) bool { return input.ID == id })
		if position < 0 {
			return nil, fmt.Errorf("case has no admitted input: %s", id)
		}
		input := inputs[position]
		identity := input.TreeSHA256
		if input.Use != "native-continuation" {
			position = slices.IndexFunc(metadata.Inputs, func(entry corpus.Entry) bool { return entry.ID == id })
			if position < 0 {
				return nil, fmt.Errorf("case input lacks original source snapshot: %s", id)
			}
			key := id + "/" + strconv.Itoa(c.Source)
			identity = cache[key]
			if identity == "" {
				var err error
				identity, err = referenceSourceIdentity(metadata.Inputs[position], c.Source)
				if err != nil {
					return nil, err
				}
				cache[key] = identity
			}
		}
		result = append(result, executionIndexedInput{id, identity, input.Use})
	}
	return result, nil
}
