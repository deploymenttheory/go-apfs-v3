package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/publication"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/replay"
)

type referenceEvidenceSummary struct {
	Schema          int                `json:"schema"`
	CaptureContract string             `json:"capture_contract_sha256"`
	Origin          publication.Origin `json:"origin"`
	Receipts        int                `json:"unique_receipts"`
	PortableCases   int                `json:"qualified_portable_cases"`
	NativeFiles     int                `json:"qualified_native_file_obligations"`
}

type referenceCoverage struct {
	portable map[string]map[string]receipt.File
	captured map[string]bool
	native   map[int]map[string]bool
	required map[string]referenceObligation
	single   map[int]map[string]map[string]bool
}

func referenceCaseKey(c receipt.Case, host string, race bool) (string, error) {
	return receipt.Digest(struct {
		Case receipt.Case `json:"case"`
		Host string       `json:"host"`
		Race bool         `json:"race"`
	}{c, host, race})
}

func capturedCaseKey(c receipt.Case, manifestSHA256 string) string {
	return strings.Join([]string{c.Corpus, c.Manifest, c.NativeCase, strconv.Itoa(c.Source), manifestSHA256}, "\x00")
}

func nativeFileKey(file receipt.File) string {
	return strconv.FormatInt(file.Bytes, 10) + ":" + file.SHA256
}

func nativeSourceContract(ctx context.Context, root string) (string, error) {
	var files []receipt.File
	err := filepath.WalkDir(filepath.Join(root, "acceptance/native"), func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !slices.Contains([]string{".py", ".c", ".h", ".entitlements"}, filepath.Ext(name)) {
			return nil
		}
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		file, err := digestFile(ctx, root, relative)
		if err == nil {
			files = append(files, file)
		}
		return err
	})
	if err != nil || len(files) == 0 {
		return "", errors.Join(err, errors.New("native execution source closure missing"))
	}
	slices.SortFunc(files, func(a, b receipt.File) int { return strings.Compare(a.Path, b.Path) })
	return receipt.Digest(files)
}

// checkReferenceEvidence verifies already executed original plans and streams.
// The caller separately authenticates the complete Actions campaign, its job
// inventory and successful required gates. Available records cannot reduce the
// independently planned portable/source/native-file obligation set.
func checkReferenceEvidence(ctx context.Context, root, registryPath, candidate, directory string, origin publication.Origin) (referenceEvidenceSummary, error) {
	result := referenceEvidenceSummary{Schema: 1, Origin: origin}
	if err := origin.Validate(); err != nil {
		return result, err
	}
	revision, err := commandText(ctx, root, "git", "rev-parse", "HEAD")
	if err != nil || revision != origin.Revision {
		return result, errors.Join(err, errors.New("candidate evidence requires the exact tested source checkout"))
	}
	want, err := planReferenceObligations(ctx, root, registryPath, candidate)
	if err != nil {
		return result, err
	}
	result.CaptureContract = want.CaptureContract
	production, contract, err := sourceIdentities(ctx, root)
	if err != nil {
		return result, err
	}
	nativeContract, err := nativeSourceContract(ctx, root)
	if err != nil {
		return result, err
	}
	data, err := regularFile(root, registryPath)
	if err != nil {
		return result, err
	}
	var r registry
	if err = corpus.StrictJSON(data, &r); err != nil {
		return result, err
	}
	optional := map[string]bool{}
	for _, exit := range r.Exits {
		optional[exit.Function] = true
	}
	coverage := referenceCoverage{portable: map[string]map[string]receipt.File{}, captured: map[string]bool{}, native: map[int]map[string]bool{}, required: map[string]referenceObligation{}, single: map[int]map[string]map[string]bool{}}
	individual := map[int]map[string]map[string]bool{}
	for _, obligation := range want.Cases {
		key, err := referenceCaseKey(obligation.Case, obligation.Host, obligation.Race)
		if err != nil {
			return result, err
		}
		if _, exists := coverage.required[key]; exists {
			return result, errors.New("duplicate required candidate execution obligation")
		}
		coverage.required[key] = obligation
	}
	seen := map[string]string{}
	var paths []string
	err = filepath.WalkDir(directory, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("aliased candidate execution evidence")
		}
		if !entry.IsDir() && (entry.Name() == "receipt.json" || strings.HasSuffix(entry.Name(), ".receipt.json")) {
			if len(paths) >= 10000 {
				return errors.New("candidate execution receipt inventory exceeds bound")
			}
			paths = append(paths, name)
		}
		return nil
	})
	if err != nil || len(paths) == 0 {
		return result, errors.Join(err, errors.New("candidate execution evidence missing"))
	}
	for _, path := range paths {
		data, err := readCandidateDocument(path, 32<<20)
		if err != nil {
			return result, err
		}
		var record receipt.Receipt
		if err = corpus.StrictJSON(data, &record); err != nil {
			return result, err
		}
		planPath := strings.TrimSuffix(path, "receipt.json") + "plan.json"
		data, err = readCandidateDocument(planPath, 32<<20)
		if err != nil {
			return result, err
		}
		var plan receipt.Plan
		if err = corpus.StrictJSON(data, &plan); err != nil {
			return result, err
		}
		expectedOrigin := receipt.Origin{Revision: origin.Revision, Run: origin.Run, Attempt: origin.Attempt, Job: record.Origin.Job}
		if err = receipt.VerifyStoredEvents(ctx, filepath.Dir(path), plan, expectedOrigin, record, optional); err != nil {
			return result, err
		}
		if plan.Stage == "replay" && (plan.Production != production || plan.Contract != contract) || plan.Stage != "replay" && (plan.Contract != nativeContract || plan.Production != "" && plan.Production != production) {
			return result, errors.New("candidate execution belongs to another implementation/assertion/native contract")
		}
		key := record.Fingerprint + "/" + record.Origin.Job
		identity, err := receipt.Digest(record)
		if err != nil {
			return result, err
		}
		if previous, exists := seen[key]; exists && previous != identity {
			return result, errors.New("conflicting copies of original candidate execution receipt")
		}
		seen[key] = identity
		if err = collectReferenceCoverage(ctx, filepath.Dir(path), record, &coverage); err != nil {
			return result, err
		}
	}
	for _, obligation := range want.Cases {
		key, err := referenceCaseKey(obligation.Case, obligation.Host, obligation.Race)
		if err != nil {
			return result, err
		}
		outputs, exists := coverage.portable[key]
		if !exists || !coverage.captured[capturedCaseKey(obligation.Case, obligation.ManifestSHA256)] {
			return result, fmt.Errorf("candidate source/portable case not qualified: %s (%s, race=%t)", obligation.Case.Test, obligation.Host, obligation.Race)
		}
		result.PortableCases++
		for _, name := range obligation.Case.Outputs {
			if !strings.HasSuffix(name, ".dmg") && !strings.HasSuffix(name, ".appledouble") && !strings.HasSuffix(name, "/metadata/manifest.json") {
				continue
			}
			file, exists := outputs[name]
			if !exists {
				return result, errors.New("required candidate output has no original portable byte identity")
			}
			for _, major := range obligation.NativeMajors {
				if !coverage.native[major][nativeFileKey(file)] {
					return result, fmt.Errorf("candidate output lacks Apple verification on macOS %d: %s", major, name)
				}
				result.NativeFiles++
				if strings.Contains(name, "/encrypted/") || strings.Contains(obligation.Case.Variant, "encrypted-aes") || strings.Contains(obligation.Case.Variant, "encrypted-input/rewrapped") {
					if individual[major] == nil {
						individual[major] = map[string]map[string]bool{}
					}
					fileKey := nativeFileKey(file)
					if individual[major][fileKey] == nil {
						individual[major][fileKey] = map[string]bool{}
					}
					individual[major][fileKey][key+"/"+name] = true
				}
			}
		}
	}
	for major, files := range individual {
		for file, outputs := range files {
			if len(coverage.single[major][file]) < len(outputs) {
				return result, errors.New("randomized candidate ciphertext lacks individual native execution evidence")
			}
		}
	}
	result.Receipts = len(seen)
	return result, nil
}

func collectReferenceCoverage(ctx context.Context, directory string, record receipt.Receipt, coverage *referenceCoverage) error {
	plan := record.Plan
	switch plan.Stage {
	case "capture":
		for _, file := range record.Outputs {
			actual, err := digestFile(ctx, directory, file.Path)
			if err != nil || actual != file {
				return errors.Join(err, errors.New("original native case observation bytes differ"))
			}
		}
		for _, c := range plan.Cases {
			if len(c.Outputs) != 1 {
				return errors.New("native capture case observation inventory differs")
			}
			data, err := readCandidateDocument(filepath.Join(directory, filepath.FromSlash(c.Outputs[0])), 32<<20)
			if err != nil {
				return err
			}
			var observation struct {
				Manifest       string         `json:"manifest"`
				ManifestSHA256 string         `json:"manifest_sha256"`
				NativeCase     string         `json:"native_case"`
				Observation    map[string]any `json:"observation"`
			}
			if err = corpus.StrictJSON(data, &observation); err != nil {
				return err
			}
			if observation.Manifest != c.Manifest || observation.NativeCase != c.NativeCase || len(observation.Observation) == 0 {
				return errors.New("captured case does not bind its original observation")
			}
			coverage.captured[capturedCaseKey(c, observation.ManifestSHA256)] = true
		}
	case "apple-verification":
		major, err := strconv.Atoi(strings.Split(plan.Environment.Version, ".")[0])
		if err != nil {
			return err
		}
		if coverage.native[major] == nil {
			coverage.native[major] = map[string]bool{}
			coverage.single[major] = map[string]map[string]bool{}
		}
		files := map[string]receipt.File{}
		for _, file := range plan.Outputs {
			coverage.native[major][nativeFileKey(file)] = true
			files[file.Path] = file
		}
		for _, c := range plan.Cases {
			if len(c.Outputs) != 1 {
				continue
			}
			file, exists := files[c.Outputs[0]]
			if !exists {
				return errors.New("native case is missing its declared portable output")
			}
			key := nativeFileKey(file)
			if coverage.single[major][key] == nil {
				coverage.single[major][key] = map[string]bool{}
			}
			coverage.single[major][key][record.Fingerprint+"/"+c.Test] = true
		}
	case "replay":
		metadataFile := "source-inputs.json"
		exported := strings.Contains(filepath.ToSlash(directory), "/.qualification/")
		if exported {
			metadataFile = "inputs.json"
		}
		data, err := readCandidateDocument(filepath.Join(directory, metadataFile), 32<<20)
		if err != nil {
			return err
		}
		var metadata replayEvidence
		if err = corpus.StrictJSON(data, &metadata); err != nil {
			return err
		}
		if metadata.Schema != 1 || exported && metadata.OutputEnvironment == "" {
			return errors.New("candidate replay source snapshot missing")
		}
		entries := map[string]corpus.Entry{}
		for _, entry := range metadata.Inputs {
			identity, err := entry.Identity()
			if err != nil || identity != entry.TreeSHA256 || entries[entry.ID].ID != "" || !slices.ContainsFunc(plan.Inputs, func(input receipt.Input) bool { return input.ID == entry.ID && input.TreeSHA256 == identity }) {
				return errors.New("candidate replay original input identity differs")
			}
			entries[entry.ID] = entry
		}
		controls := map[string]bool{}
		for _, flag := range plan.Environment.Flags {
			if value, ok := strings.CutPrefix(flag, "required-controls="); ok {
				controls, err = replay.RequiredControls(value)
				if err != nil {
					return err
				}
			}
		}
		outputs := map[string]receipt.File{}
		for _, file := range record.Outputs {
			outputs[file.Path] = file
		}
		sourceIdentities := map[string]map[int]string{}
		for _, c := range plan.Cases {
			key, err := referenceCaseKey(c, plan.Environment.OS, plan.Environment.Race)
			if err != nil {
				return err
			}
			obligation, required := coverage.required[key]
			if !required {
				continue
			}
			entry := entries[c.Corpus]
			if sourceIdentities[c.Corpus] == nil {
				sourceIdentities[c.Corpus] = map[int]string{}
			}
			if sourceIdentities[c.Corpus][c.Source] == "" {
				identity, err := referenceSourceIdentity(entry, c.Source)
				if err != nil {
					return err
				}
				sourceIdentities[c.Corpus][c.Source] = identity
			}
			if sourceIdentities[c.Corpus][c.Source] != obligation.InputSHA256 {
				continue
			}
			if !slices.ContainsFunc(entry.Captures, func(capture corpus.Capture) bool {
				return capture.Manifest == c.Manifest && capture.OriginalSHA256 == obligation.ManifestSHA256
			}) {
				continue
			}
			if !slices.ContainsFunc(obligation.Controls, func(control string) bool { return !controls[control] }) {
				coverage.portable[key] = outputs
			}
		}
	}
	return nil
}
