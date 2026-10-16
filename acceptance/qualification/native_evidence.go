package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

// The controller authenticates every upload and the original complete native
// gate. This admission additionally checks the original execution bytes; copied
// portable receipts in Apple readback archives cannot replace their executors.
func checkNativeEvidence(ctx context.Context, root, directory string, origin executionEvidenceOrigin) (executionEvidenceSummary, error) {
	summary := executionEvidenceSummary{Schema: 1, Origin: origin.Origin, Tree: origin.Tree, Receipts: []receipt.File{}}
	if origin.Schema != 1 || origin.Workflow != "native" || origin.Origin.Validate() != nil || len(origin.Artifacts) == 0 || len(origin.Artifacts) > 1000 {
		return summary, errors.New("authenticated complete native origin and artifact inventory required")
	}
	tree, err := commandText(ctx, root, "git", "rev-parse", "HEAD^{tree}")
	if err != nil || origin.Tree != tree {
		return summary, errors.Join(err, errors.New("native evidence tested different source contents"))
	}
	production, contract, err := sourceIdentities(ctx, root)
	if err != nil {
		return summary, err
	}
	nativeContract, err := nativeSourceContract(ctx, root)
	if err != nil {
		return summary, err
	}
	version, err := projectGoVersion(root)
	if err != nil {
		return summary, err
	}
	data, err := regularFile(root, "acceptance/qualification/registry.json")
	if err != nil {
		return summary, err
	}
	var registry registry
	if err = corpus.StrictJSON(data, &registry); err != nil {
		return summary, err
	}
	optional := map[string]bool{}
	for _, exit := range registry.Exits {
		optional[exit.Function] = true
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(origin.Artifacts) {
		return summary, errors.Join(err, errors.New("native artifact directories differ from authenticated inventory"))
	}
	seenArtifacts := map[string]bool{}
	for _, entry := range entries {
		if !entry.IsDir() || !slices.ContainsFunc(origin.Artifacts, func(a executionEvidenceArtifact) bool { return a.Name == entry.Name() }) {
			return summary, errors.New("unexpected native artifact directory")
		}
	}
	seen, owners := map[string]string{}, map[string]string{}
	records := map[string]receipt.Receipt{}
	coverage := referenceCoverage{captured: map[string]bool{}, native: map[int]map[string]bool{}, single: map[int]map[string]map[string]bool{}}
	for _, artifact := range origin.Artifacts {
		if !strings.HasPrefix(artifact.Name, "qualification-") || filepath.Base(artifact.Name) != artifact.Name || strings.ContainsAny(artifact.Name, `/\`) || seenArtifacts[artifact.Name] || artifact.Job == "" || !slices.Contains([]string{"linux", "darwin", "windows"}, artifact.Host) {
			return summary, errors.New("invalid or duplicate authenticated native artifact")
		}
		seenArtifacts[artifact.Name] = true
		base := filepath.Join(directory, artifact.Name)
		var paths []string
		err = filepath.WalkDir(base, func(name string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() && !entry.Type().IsRegular() {
				return errors.New("native execution evidence contains aliased or special members")
			}
			if !entry.IsDir() && (entry.Name() == "receipt.json" || strings.HasSuffix(entry.Name(), ".receipt.json")) {
				if len(paths) >= 10000 {
					return errors.New("native receipt inventory exceeds bound")
				}
				paths = append(paths, name)
			}
			return ctx.Err()
		})
		if err != nil {
			return summary, err
		}
		if artifact.Kind == "approved-inputs" {
			if len(paths) != 0 || artifact.Host != "linux" {
				return summary, errors.New("approved source restoration cannot claim executed assertions")
			}
			if err = checkRestoredInputEvidence(ctx, root, base); err != nil {
				return summary, err
			}
			continue
		}
		if artifact.Kind != "" || len(paths) == 0 {
			return summary, errors.New("required original native execution evidence missing")
		}
		owned := false
		for _, name := range paths {
			var record receipt.Receipt
			var plan receipt.Plan
			if err = readEvidenceDocument(name, &record); err != nil {
				return summary, err
			}
			if err = readEvidenceDocument(strings.TrimSuffix(name, "receipt.json")+"plan.json", &plan); err != nil {
				return summary, err
			}
			expected := receipt.Origin{Revision: origin.Origin.Revision, Run: origin.Origin.Run, Attempt: origin.Origin.Attempt, Job: record.Origin.Job}
			if err = receipt.VerifyStoredEvents(ctx, filepath.Dir(name), plan, expected, record, optional); err != nil {
				return summary, err
			}
			owner := record.Origin.Job == artifact.Job && plan.Environment.OS == artifact.Host
			if owner {
				owned = true
			}
			if plan.Stage == "replay" {
				if plan.Production != production || plan.Contract != contract || len(plan.Environment.Tools) < 5 || !strings.HasPrefix(plan.Environment.Toolchain, "go version go"+version+" ") {
					return summary, errors.New("portable source, assertions or actual tools differ")
				}
				if err = checkReplaySourceEvidence(filepath.Dir(name), plan); err != nil {
					return summary, err
				}
			} else {
				major, parseErr := strconv.Atoi(strings.Split(plan.Environment.Version, ".")[0])
				if parseErr != nil || plan.Contract != nativeContract || len(plan.Environment.Tools) < 7 || plan.Production != "" && plan.Production != production || owner && major != artifact.Major {
					return summary, errors.New("native source, assertions, version or actual tools differ")
				}
				if err = collectReferenceCoverage(ctx, filepath.Dir(name), record, &coverage); err != nil {
					return summary, err
				}
			}
			relative, err := filepath.Rel(directory, name)
			if err != nil {
				return summary, err
			}
			file, err := digestFile(ctx, directory, filepath.ToSlash(relative))
			if err != nil {
				return summary, err
			}
			key := record.Origin.Job + "/" + record.Fingerprint
			if previous, exists := seen[key]; exists && previous != file.SHA256 {
				return summary, errors.New("conflicting copies of original native execution evidence")
			}
			if owner {
				if previous, exists := owners[key]; exists && previous != artifact.Name {
					return summary, errors.New("one execution replaced a different required native artifact")
				}
				owners[key] = artifact.Name
			}
			if _, exists := seen[key]; !exists {
				summary.Receipts = append(summary.Receipts, file)
				summary.CaseCount += len(plan.Cases)
			}
			seen[key], records[key] = file.SHA256, record
		}
		if !owned {
			return summary, errors.New("original native artifact contains no evidence from its own executor")
		}
	}
	for key := range seen {
		if owners[key] == "" {
			return summary, errors.New("copied execution lacks its original producer evidence")
		}
	}
	if err = checkNativeOutputEvidence(root, registry, records, &coverage); err != nil {
		return summary, err
	}
	return summary, nil
}

func readEvidenceDocument(path string, result any) error {
	data, err := readCandidateDocument(path, 32<<20)
	if err != nil {
		return err
	}
	return corpus.StrictJSON(data, result)
}

func checkReplaySourceEvidence(directory string, plan receipt.Plan) error {
	name := "source-inputs.json"
	if strings.Contains(filepath.ToSlash(directory), "/.qualification/") {
		name = "inputs.json"
	}
	var metadata replayEvidence
	if err := readEvidenceDocument(filepath.Join(directory, name), &metadata); err != nil {
		return err
	}
	identities := map[string]string{}
	for _, input := range metadata.Inputs {
		identity, err := input.Identity()
		if err != nil || identity != input.TreeSHA256 || identities[input.ID] != "" {
			return errors.New("original portable source snapshot differs")
		}
		identities[input.ID] = identity
	}
	for _, continuation := range metadata.Continuations {
		identity, err := receipt.Digest(continuation.Files)
		if err != nil || identity != continuation.Input.TreeSHA256 || identities[continuation.Input.ID] != "" {
			return errors.New("original continuation source snapshot differs")
		}
		identities[continuation.Input.ID] = identity
	}
	if metadata.Schema != 1 || len(identities) != len(plan.Inputs) {
		return errors.New("original portable source snapshot incomplete")
	}
	for _, input := range plan.Inputs {
		if identities[input.ID] != input.TreeSHA256 {
			return errors.New("original portable input binding differs")
		}
	}
	return nil
}

func checkRestoredInputEvidence(ctx context.Context, root, directory string) error {
	pin, err := regularFile(root, "acceptance/qualification/references.json")
	if err != nil {
		return err
	}
	sum := sha256.Sum256(pin)
	var document struct {
		Catalog struct {
			SHA256 string `json:"sha256"`
		} `json:"catalog"`
	}
	// The reviewed pin has other publication fields; its exact bytes are bound.
	if err = json.Unmarshal(pin, &document); err != nil {
		return err
	}
	for _, major := range []int{15, 26, 27} {
		if err := ctx.Err(); err != nil {
			return err
		}
		var report map[string]any
		if err = readEvidenceDocument(filepath.Join(directory, "capture-approved-"+strconv.Itoa(major), "admission.json"), &report); err != nil {
			return err
		}
		if report["schema"] != float64(1) || report["kind"] != "approved-native-input-admission" || report["assertions_executed"] != false || report["source_major"] != float64(major) || report["pin_sha256"] != hex.EncodeToString(sum[:]) || report["catalog_sha256"] != document.Catalog.SHA256 || !corpus.ValidDigest(document.Catalog.SHA256) {
			return errors.New("original approved input admission differs from the reviewed pin")
		}
	}
	return nil
}

func checkNativeOutputEvidence(root string, registry registry, records map[string]receipt.Receipt, coverage *referenceCoverage) error {
	data, err := regularFile(root, "acceptance/qualification/replay.json")
	if err != nil {
		return err
	}
	var recipes replayContract
	if err = corpus.StrictJSON(data, &recipes); err != nil {
		return err
	}
	matching := map[string]bool{}
	for _, recipe := range recipes.Tests {
		matching[recipe.Test] = recipe.NativeScope == "matching-source"
	}
	individual := map[int]map[string]map[string]bool{}
	for key, record := range records {
		if record.Plan.Stage != "replay" {
			continue
		}
		for _, c := range record.Plan.Cases {
			index := slices.IndexFunc(registry.Families, func(f family) bool { return f.ID == c.Family })
			if index < 0 {
				return errors.New("original portable case has no reviewed native scope")
			}
			majors := registry.Families[index].NativeMajors
			if matching[strings.Split(c.Test, "/")[0]] && len(majors) != 0 {
				majors = []int{c.Source}
			}
			for _, name := range c.Outputs {
				if !strings.HasSuffix(name, ".dmg") && !strings.HasSuffix(name, ".appledouble") && !strings.HasSuffix(name, "/metadata/manifest.json") {
					continue
				}
				index := slices.IndexFunc(record.Outputs, func(f receipt.File) bool { return f.Path == name })
				if index < 0 {
					return errors.New("required portable output identity missing")
				}
				file := nativeFileKey(record.Outputs[index])
				for _, major := range majors {
					if !coverage.native[major][file] {
						return fmt.Errorf("portable output lacks original Apple verification on macOS %d: %s", major, name)
					}
					if strings.Contains(name, "/encrypted/") || strings.Contains(c.Variant, "encrypted-aes") || strings.Contains(c.Variant, "encrypted-input/rewrapped") {
						if individual[major] == nil {
							individual[major] = map[string]map[string]bool{}
						}
						if individual[major][file] == nil {
							individual[major][file] = map[string]bool{}
						}
						individual[major][file][key+"/"+c.Test+"/"+name] = true
					}
				}
			}
		}
	}
	for major, files := range individual {
		for file, scopes := range files {
			if len(coverage.single[major][file]) < len(scopes) {
				return errors.New("randomized ciphertext lacks individual original Apple checks")
			}
		}
	}
	return nil
}
