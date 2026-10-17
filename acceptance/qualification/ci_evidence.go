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
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

func checkCIEvidence(ctx context.Context, root, directory string, origin executionEvidenceOrigin, reviewed *corpus.Catalog) (executionEvidenceSummary, error) {
	summary := executionEvidenceSummary{Schema: 1, Origin: origin.Origin, Tree: origin.Tree, Receipts: []receipt.File{}}
	if origin.Schema != 1 || origin.Workflow != "ci" || origin.Origin.Validate() != nil || len(origin.Artifacts) == 0 || len(origin.Artifacts) > 1000 {
		return summary, errors.New("authenticated complete CI origin and artifact inventory required")
	}
	projection, err := checkExecutionSource(ctx, root, origin)
	if err != nil {
		return summary, err
	}
	summary.Projection = projection
	production, contract, err := sourceIdentities(ctx, root)
	if err != nil {
		return summary, err
	}
	data, err := regularFile(root, "acceptance/qualification/corpus.json")
	if err != nil {
		return summary, err
	}
	catalog, err := corpus.Read(strings.NewReader(string(data)))
	if err != nil {
		return summary, err
	}
	if reviewed != nil {
		catalog = *reviewed
	}
	inputs := map[string]string{}
	for _, entry := range catalog.Entries {
		inputs[entry.ID] = entry.TreeSHA256
	}
	data, err = regularFile(root, "acceptance/qualification/registry.json")
	if err != nil {
		return summary, err
	}
	var r registry
	if err = corpus.StrictJSON(data, &r); err != nil {
		return summary, err
	}
	optional := map[string]bool{}
	for _, exit := range r.Exits {
		optional[exit.Function] = true
	}
	version, err := projectGoVersion(root)
	if err != nil {
		return summary, err
	}
	seenArtifacts, seenReceipts, receiptArtifacts := map[string]bool{}, map[string]string{}, map[string]string{}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(origin.Artifacts) {
		return summary, errors.Join(err, errors.New("CI artifact directories differ from authenticated inventory"))
	}
	for _, entry := range entries {
		if !entry.IsDir() || !slices.ContainsFunc(origin.Artifacts, func(a executionEvidenceArtifact) bool { return a.Name == entry.Name() }) {
			return summary, errors.New("unexpected or aliased CI artifact directory")
		}
	}
	for _, artifact := range origin.Artifacts {
		index, ok := strings.CutPrefix(artifact.Name, "qualification-ci-"+artifact.Job+"-")
		n, parseErr := strconv.Atoi(index)
		if !ok || parseErr != nil || n < 0 || strconv.Itoa(n) != index || filepath.Base(artifact.Name) != artifact.Name || strings.ContainsAny(artifact.Name, `/\`) || seenArtifacts[artifact.Name] || !slices.Contains([]string{"linux", "darwin", "windows"}, artifact.Host) {
			return summary, errors.New("invalid or duplicate authenticated CI artifact")
		}
		seenArtifacts[artifact.Name] = true
		base := filepath.Join(directory, artifact.Name)
		var receipts []string
		err = filepath.WalkDir(base, func(name string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.Type()&os.ModeSymlink != 0 || !entry.IsDir() && !entry.Type().IsRegular() {
				return errors.New("CI execution evidence contains aliased or special members")
			}
			if !entry.IsDir() && entry.Name() == "receipt.json" {
				if len(receipts) >= 10000 {
					return errors.New("CI receipt inventory exceeds bound")
				}
				receipts = append(receipts, name)
			}
			return ctx.Err()
		})
		if err != nil || len(receipts) == 0 {
			return summary, errors.Join(err, fmt.Errorf("required CI execution evidence missing: %s", artifact.Name))
		}
		for _, name := range receipts {
			data, err = readCandidateDocument(name, 32<<20)
			if err != nil {
				return summary, err
			}
			var record receipt.Receipt
			if err = corpus.StrictJSON(data, &record); err != nil {
				return summary, err
			}
			data, err = readCandidateDocument(filepath.Join(filepath.Dir(name), "plan.json"), 32<<20)
			if err != nil {
				return summary, err
			}
			var plan receipt.Plan
			if err = corpus.StrictJSON(data, &plan); err != nil {
				return summary, err
			}
			expected := receipt.Origin{Revision: origin.Origin.Revision, Run: origin.Origin.Run, Attempt: origin.Origin.Attempt, Job: artifact.Job}
			if err = receipt.VerifyStoredEvents(ctx, filepath.Dir(name), plan, expected, record, optional); err != nil {
				return summary, err
			}
			if plan.Stage != "replay" || plan.Production != production || plan.Contract != contract || plan.Environment.OS != artifact.Host || len(plan.Environment.Tools) < 5 || !strings.HasPrefix(plan.Environment.Toolchain, "go version go"+version+" ") {
				return summary, errors.New("CI execution source, assertion, host or actual toolchain identity differs")
			}
			for _, input := range plan.Inputs {
				if input.Use != "retained" || inputs[input.ID] != input.TreeSHA256 {
					return summary, errors.New("CI execution input differs from its admitted catalog")
				}
			}
			if err = checkReplaySourceEvidence(filepath.Dir(name), plan); err != nil {
				return summary, err
			}
			relative, err := filepath.Rel(directory, name)
			if err != nil {
				return summary, err
			}
			file, err := digestFile(ctx, directory, filepath.ToSlash(relative))
			if err != nil {
				return summary, err
			}
			key := artifact.Job + "/" + record.Fingerprint
			if previous, exists := seenReceipts[key]; exists {
				if previous != file.SHA256 || receiptArtifacts[key] != artifact.Name {
					return summary, errors.New("conflicting copies of original CI execution evidence")
				}
				continue
			}
			seenReceipts[key] = file.SHA256
			receiptArtifacts[key] = artifact.Name
			summary.Receipts = append(summary.Receipts, file)
			summary.CaseCount += len(plan.Cases)
		}
	}
	return summary, nil
}

// Only the pin in the authenticated source checkout can replace its historical
// catalog. An arbitrary caller-selected release is not the original CI input.
func checkedCIEvidenceReferences(ctx context.Context, root, registryPath, pinPath, bundles string) (corpus.Catalog, error) {
	const member = "acceptance/qualification/references.json"
	expected, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(member)))
	if err != nil {
		return corpus.Catalog{}, err
	}
	if !filepath.IsAbs(pinPath) {
		pinPath = filepath.Join(root, filepath.FromSlash(pinPath))
	}
	actual, err := filepath.Abs(pinPath)
	if err != nil || actual != expected {
		return corpus.Catalog{}, errors.Join(err, errors.New("CI evidence requires the reviewed pin in its authenticated source checkout"))
	}
	if _, err = regularFile(root, member); err != nil {
		return corpus.Catalog{}, err
	}
	return checkedReferenceCatalog(ctx, root, registryPath, member, bundles)
}
