package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/publication"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

type candidateInput struct {
	ID   string `json:"id"`
	Path string `json:"path"`
}
type candidateInputs struct {
	Schema int              `json:"schema"`
	Inputs []candidateInput `json:"inputs"`
}
type preparedReferences struct {
	Schema          int             `json:"schema"`
	CaptureContract string          `json:"capture_contract_sha256"`
	Corpus          corpus.Catalog  `json:"corpus"`
	Bundles         []corpus.Bundle `json:"bundles"`
}

type captureRule struct {
	Input    string   `json:"input"`
	Manifest string   `json:"manifest"`
	Contract string   `json:"capture_contract,omitempty"`
	Controls []string `json:"controls,omitempty"`
}

func captureContract(ctx context.Context, root string, recipes replayContract) (string, error) {
	var files []receipt.File
	command := exec.CommandContext(ctx, "git", "ls-files", "--cached", "--others", "--exclude-standard", "-z")
	command.Dir = root
	data, err := command.Output()
	if err != nil {
		return "", err
	}
	for _, name := range strings.Split(strings.TrimSuffix(string(data), "\x00"), "\x00") {
		// Independent Apple inputs do not depend on ordinary Go filesystem
		// implementation changes. All unclassified dependencies enter this
		// conservative full-capture identity, including newly added scripts,
		// build assets and helpers outside the known native directories.
		if strings.HasPrefix(name, "docs/") || strings.HasSuffix(name, ".md") || strings.HasPrefix(name, "acceptance/testdata/") || name == "acceptance/qualification/corpus.json" || name == "acceptance/qualification/references.json" {
			continue
		}
		if strings.HasSuffix(name, "_test.go") || strings.HasPrefix(name, "acceptance/native/test_") || strings.HasPrefix(name, "acceptance/qualification/test_") {
			continue
		}
		if strings.HasSuffix(name, ".go") && !strings.HasPrefix(name, "acceptance/") && !strings.HasPrefix(name, "internal/qualification/") {
			continue
		}
		file, err := digestFile(ctx, root, name)
		if err != nil {
			return "", err
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		return "", errors.New("native collector dependency closure missing")
	}
	slices.SortFunc(files, func(a, b receipt.File) int { return strings.Compare(a.Path, b.Path) })
	rules := map[string]captureRule{}
	for _, spec := range recipes.Tests {
		if spec.Input == "" {
			continue
		}
		rule := captureRule{Input: spec.Input, Manifest: spec.Manifest, Contract: spec.CaptureContract, Controls: spec.Controls}
		rules[rule.Input+"/"+rule.Manifest+"/"+rule.Contract+"/"+strings.Join(rule.Controls, ",")] = rule
	}
	keys := make([]string, 0, len(rules))
	for key := range rules {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	ordered := make([]captureRule, 0, len(keys))
	for _, key := range keys {
		ordered = append(ordered, rules[key])
	}
	return receipt.Digest(struct {
		Schema int            `json:"schema"`
		Files  []receipt.File `json:"files"`
		Rules  []captureRule  `json:"rules"`
	}{1, files, ordered})
}

func referenceRequirements(original corpus.Catalog, recipes replayContract) ([]publication.Requirement, error) {
	var required []publication.Requirement
	seen := map[string]bool{}
	for _, spec := range recipes.Tests {
		key := spec.Input + "/" + spec.Manifest
		if spec.Input == "" || seen[key] {
			continue
		}
		seen[key] = true
		index := slices.IndexFunc(original.Entries, func(e corpus.Entry) bool { return e.ID == spec.Input })
		if index < 0 {
			return nil, fmt.Errorf("unknown native reference input: %s", spec.Input)
		}
		entry := original.Entries[index]
		if slices.ContainsFunc(entry.Bindings, func(b corpus.Binding) bool { return b.CaptureClass == "current-go-experiment" }) {
			continue
		}
		requirement := publication.Requirement{ID: entry.ID, Manifest: spec.Manifest, Contract: spec.CaptureContract, Cases: map[int][]string{}}
		var references []corpus.Capture
		for _, capture := range entry.Captures {
			match, err := path.Match(spec.Manifest, capture.Manifest)
			if err != nil {
				return nil, err
			}
			if match {
				references = append(references, capture)
			}
		}
		if len(references) == 0 {
			return nil, fmt.Errorf("reviewed capture cases absent: %s", spec.Test)
		}
		if requirement.Contract == "" {
			requirement.Contract = references[0].Contract
		}
		for _, major := range []int{15, 26, 27} {
			reference := references[0]
			if n := slices.IndexFunc(references, func(c corpus.Capture) bool { return c.Major == major }); n >= 0 {
				reference = references[n]
			}
			requirement.Cases[major] = slices.Clone(reference.Cases)
		}
		required = append(required, requirement)
	}
	return required, nil
}

// prepareReferences consumes already completed native captures. It cannot
// qualify, publish or promote them. All current-Go experiments retain their
// historical pins and must execute afresh in implementation qualification.
func prepareReferences(ctx context.Context, root, registryPath, inputFile, directory string) error {
	data, err := regularFile(root, registryPath)
	if err != nil {
		return err
	}
	var registry registry
	if err = corpus.StrictJSON(data, &registry); err != nil {
		return err
	}
	recipes, err := readReplayContract(root, registry)
	if err != nil {
		return err
	}
	data, err = os.ReadFile(filepath.Join(root, "acceptance/qualification/corpus.json"))
	if err != nil {
		return err
	}
	original, err := corpus.Read(strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	data, err = readCandidateDocument(inputFile, 1<<20)
	if err != nil {
		return err
	}
	var inputs candidateInputs
	if err = corpus.StrictJSON(data, &inputs); err != nil {
		return err
	}
	if inputs.Schema != 1 {
		return errors.New("candidate input schema differs")
	}
	locations := map[string]string{}
	for _, input := range inputs.Inputs {
		if input.ID == "" || locations[input.ID] != "" || !filepath.IsAbs(input.Path) {
			return errors.New("invalid/duplicate current native capture location")
		}
		locations[input.ID] = input.Path
	}
	independent := map[string]bool{}
	for _, entry := range original.Entries {
		independent[entry.ID] = !slices.ContainsFunc(entry.Bindings, func(b corpus.Binding) bool { return b.CaptureClass == "current-go-experiment" })
	}
	for id := range locations {
		if !independent[id] {
			return fmt.Errorf("unregistered/current-Go input cannot enter independent capture publication: %s", id)
		}
	}
	for _, entry := range original.Entries {
		if independent[entry.ID] && locations[entry.ID] == "" {
			return fmt.Errorf("required native reference capture absent: %s", entry.ID)
		}
	}
	required, err := referenceRequirements(original, recipes)
	if err != nil {
		return err
	}
	if _, err = os.Lstat(directory); !errors.Is(err, os.ErrNotExist) {
		return errors.New("candidate preparation requires an absent output directory")
	}
	for _, location := range locations {
		if err = separatePaths(location, directory); err != nil {
			return err
		}
	}
	if err = os.MkdirAll(directory, 0700); err != nil {
		return err
	}
	ready := preparedReferences{Schema: 1, Corpus: corpus.Catalog{Schema: 1}, Bundles: []corpus.Bundle{}}
	ready.CaptureContract, err = captureContract(ctx, root, recipes)
	if err != nil {
		return err
	}
	used := map[string]bool{}
	bundles := map[string]corpus.Bundle{}
	for _, retained := range original.Entries {
		if slices.ContainsFunc(retained.Bindings, func(b corpus.Binding) bool { return b.CaptureClass == "current-go-experiment" }) {
			if locations[retained.ID] != "" {
				return errors.New("current-Go experiment cannot enter independent capture publication")
			}
			ready.Corpus.Entries = append(ready.Corpus.Entries, retained)
			continue
		}
		location := locations[retained.ID]
		if location == "" {
			return fmt.Errorf("required native reference capture absent: %s", retained.ID)
		}
		used[retained.ID] = true
		parent := filepath.Dir(location)
		current, err := corpus.InspectCapture(ctx, parent, corpus.Definition{ID: retained.ID, Path: filepath.Base(location), Bindings: retained.Bindings})
		if err != nil {
			return err
		}
		var scope []publication.Requirement
		for _, requirement := range required {
			if requirement.ID == retained.ID {
				scope = append(scope, requirement)
			}
		}
		if err = publication.MatchCoverage(current, scope); err != nil {
			return err
		}
		resolver, err := corpus.New(current, corpus.Options{Repository: parent})
		if err != nil {
			return err
		}
		source, err := resolver.Resolve(ctx, retained.ID)
		if err != nil {
			return err
		}
		bundle, writeErr := corpus.WriteBundle(ctx, source, directory)
		closeErr := source.Close()
		if err = errors.Join(writeErr, closeErr); err != nil {
			return err
		}
		entry := current.Entries[0]
		entry.Location = corpus.Location{Kind: "bundle", Bundle: &bundle}
		ready.Corpus.Entries = append(ready.Corpus.Entries, entry)
		bundles[bundle.SHA256] = bundle
	}
	if len(used) != len(locations) {
		return errors.New("unregistered native capture locations supplied")
	}
	if err = publication.MatchCoverage(ready.Corpus, required); err != nil {
		return err
	}
	for _, bundle := range bundles {
		ready.Bundles = append(ready.Bundles, bundle)
	}
	slices.SortFunc(ready.Bundles, func(a, b corpus.Bundle) int { return strings.Compare(a.SHA256, b.SHA256) })
	after, err := captureContract(ctx, root, recipes)
	if err != nil {
		return err
	}
	if after != ready.CaptureContract {
		return errors.New("native collector contract changed during candidate preparation")
	}
	return newJSON(filepath.Join(directory, "candidate.json"), ready)
}

func readCandidateDocument(name string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, errors.New("candidate metadata is not an ordinary bounded file")
	}
	input, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(input, maximum+1))
	if err = errors.Join(readErr, input.Close()); err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum {
		return nil, errors.New("candidate metadata exceeds bound")
	}
	return data, nil
}

func readCaptureContract(ctx context.Context, root, registryPath string) (string, error) {
	data, err := regularFile(root, registryPath)
	if err != nil {
		return "", err
	}
	var r registry
	if err = corpus.StrictJSON(data, &r); err != nil {
		return "", err
	}
	recipes, err := readReplayContract(root, r)
	if err != nil {
		return "", err
	}
	return captureContract(ctx, root, recipes)
}
