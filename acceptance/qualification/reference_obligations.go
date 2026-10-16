package main

import (
	"context"
	"errors"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/publication"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

type referenceObligation struct {
	Case           receipt.Case `json:"case"`
	ManifestSHA256 string       `json:"manifest_sha256"`
	InputSHA256    string       `json:"source_input_sha256"`
	Host           string       `json:"host"`
	Race           bool         `json:"race"`
	Controls       []string     `json:"required_controls"`
	NativeMajors   []int        `json:"native_majors"`
}

type referenceProjection struct {
	Corpus  string `json:"corpus"`
	Capture string `json:"capture"`
}

type referenceObligations struct {
	Schema          int                   `json:"schema"`
	CaptureContract string                `json:"capture_contract_sha256"`
	Cases           []referenceObligation `json:"cases"`
	Projections     []referenceProjection `json:"projections"`
}

// These are input projections, not execution aliases or inherited verdicts.
// The complete canonical capture includes every required operation. Existing
// retained entrypoints still execute; removing an execution requires separate
// old/new equivalence proof.
var referenceProjections = []referenceProjection{
	{Corpus: "copy-setid-permissions", Capture: "copy-permissions"},
	{Corpus: "copy-truncation-permissions", Capture: "copy-permissions"},
	{Corpus: "hfs-metadata-lifecycle", Capture: "hfs-fragmented-metadata"},
}

// planReferenceObligations derives the complete candidate's required portable
// assertions before observing its returned receipts. Available execution data
// cannot choose this inventory. No native filesystem operation occurs here.
func planReferenceObligations(ctx context.Context, root, registryPath, directory string) (referenceObligations, error) {
	want := referenceObligations{Schema: 1, Cases: []referenceObligation{}, Projections: []referenceProjection{}}
	data, err := regularFile(root, registryPath)
	if err != nil {
		return want, err
	}
	var r registry
	if err = corpus.StrictJSON(data, &r); err != nil {
		return want, err
	}
	recipes, err := readReplayContract(root, r)
	if err != nil {
		return want, err
	}
	data, err = readCandidateDocument(filepath.Join(directory, "candidate.json"), corpus.MaxCatalogBytes)
	if err != nil {
		return want, err
	}
	var ready preparedReferences
	if err = corpus.StrictJSON(data, &ready); err != nil {
		return want, err
	}
	current, err := captureContract(ctx, root, recipes)
	if err != nil {
		return want, err
	}
	if ready.Schema != 1 || ready.CaptureContract != current {
		return want, errors.New("candidate collector/helper/recipe contract differs")
	}
	want.CaptureContract = current
	data, err = regularFile(root, "acceptance/qualification/corpus.json")
	if err != nil {
		return want, err
	}
	original, err := corpus.Read(strings.NewReader(string(data)))
	if err != nil {
		return want, err
	}
	if err = publication.MatchBindings(ready.Corpus, original); err != nil {
		return want, err
	}
	required, err := referenceRequirements(original, recipes)
	if err != nil {
		return want, err
	}
	if err = publication.MatchCoverage(ready.Corpus, required); err != nil {
		return want, err
	}
	for _, projection := range referenceProjections {
		index := slices.IndexFunc(ready.Corpus.Entries, func(e corpus.Entry) bool { return e.ID == projection.Corpus })
		if index < 0 {
			continue
		}
		canonical := slices.IndexFunc(ready.Corpus.Entries, func(e corpus.Entry) bool { return e.ID == projection.Capture })
		if canonical < 0 || !publication.SameFiles(ready.Corpus.Entries[index], ready.Corpus.Entries[canonical]) {
			return want, errors.New("reference projection is not the identical complete original capture")
		}
		want.Projections = append(want.Projections, projection)
	}
	resolver, err := corpus.New(ready.Corpus, corpus.Options{Repository: root, Bundles: directory})
	if err != nil {
		return want, err
	}
	families := map[string]family{}
	for _, family := range r.Families {
		for _, test := range family.Tests {
			families[test.Name] = family
		}
	}
	inputs := map[string]corpus.Entry{}
	for _, entry := range ready.Corpus.Entries {
		inputs[entry.ID] = entry
	}
	// Release each admitted tree before resolving the next one. Planning never
	// needs all candidate archives extracted at once.
	for _, entry := range ready.Corpus.Entries {
		dependent := slices.ContainsFunc(entry.Bindings, func(b corpus.Binding) bool { return b.CaptureClass == "current-go-experiment" })
		if dependent || slices.ContainsFunc(referenceProjections, func(p referenceProjection) bool { return p.Corpus == entry.ID }) {
			continue
		}
		source, err := resolver.Resolve(ctx, entry.ID)
		if err != nil {
			return want, err
		}
		caseErr := appendReferenceCases(&want, entry, source, recipes, families, inputs)
		verifyErr := source.Verify(ctx)
		closeErr := source.Close()
		if err = errors.Join(caseErr, verifyErr, closeErr); err != nil {
			return want, err
		}
	}
	if len(want.Cases) == 0 {
		return want, errors.New("candidate has no required portable assertions")
	}
	after, err := captureContract(ctx, root, recipes)
	if err != nil {
		return want, err
	}
	if after != current {
		return want, errors.New("candidate qualification contract changed during planning")
	}
	// The key includes actual host and instrumentation; equal logical contents
	// do not merge normal/race obligations or cross-platform executions.
	slices.SortFunc(want.Cases, func(a, b referenceObligation) int {
		return strings.Compare(path.Join(a.Case.Test, a.Host), path.Join(b.Case.Test, b.Host))
	})
	return want, nil
}

func appendReferenceCases(want *referenceObligations, entry corpus.Entry, source *corpus.Resolved, recipes replayContract, families map[string]family, inputs map[string]corpus.Entry) error {
	admitted := admittedInputs{entries: map[string]corpus.Entry{entry.ID: entry}, resolved: map[string]*corpus.Resolved{entry.ID: source}}
	sourceIdentities := map[string]map[int]string{}
	for _, spec := range recipes.Tests {
		if spec.Input != entry.ID {
			continue
		}
		cases, _, err := replayCases(spec, families[spec.Test].ID, &admitted)
		if err != nil {
			return err
		}
		for _, c := range cases {
			input, exists := inputs[c.Corpus]
			if !exists {
				return errors.New("required case has no original primary or auxiliary input")
			}
			if sourceIdentities[c.Corpus] == nil {
				sourceIdentities[c.Corpus] = map[int]string{}
			}
			if sourceIdentities[c.Corpus][c.Source] == "" {
				identity, err := referenceSourceIdentity(input, c.Source)
				if err != nil {
					return err
				}
				sourceIdentities[c.Corpus][c.Source] = identity
			}
			index := slices.IndexFunc(input.Captures, func(capture corpus.Capture) bool {
				return strings.TrimSuffix(capture.Manifest, ".gz") == strings.TrimSuffix(c.Manifest, ".gz")
			})
			if index < 0 {
				return errors.New("required replay case has no original native manifest")
			}
			c.Outputs = expectedCaseOutputs(spec, c)
			nativeMajors := slices.Clone(families[spec.Test].NativeMajors)
			if spec.NativeScope == "matching-source" && len(nativeMajors) != 0 {
				if !slices.Contains(nativeMajors, c.Source) {
					return errors.New("native source scope has no required matching verifier version")
				}
				nativeMajors = []int{c.Source}
			}
			for _, host := range families[spec.Test].PortableHosts {
				want.Cases = append(want.Cases, referenceObligation{Case: c, ManifestSHA256: input.Captures[index].OriginalSHA256, InputSHA256: sourceIdentities[c.Corpus][c.Source], Host: host, Race: slices.Contains(spec.FreshRaceHosts, host), Controls: slices.Clone(spec.Controls), NativeMajors: nativeMajors})
			}
		}
	}
	return nil
}

// Current jobs may hold one source version or additional sibling capabilities.
// Compare the exact original files and capture documents within this logical
// source directory. A matching manifest alone cannot approve changed disk bytes.
// This projection changes no captured file or original whole-tree identity.
func referenceSourceIdentity(entry corpus.Entry, major int) (string, error) {
	if !slices.Contains([]int{15, 26, 27}, major) {
		return "", errors.New("native source identity requires a supported macOS version")
	}
	prefix := "macos-" + strconv.Itoa(major) + "/"
	projected := corpus.Entry{ID: entry.ID, Bindings: entry.Bindings}
	for _, file := range entry.Files {
		if strings.HasPrefix(file.Path, prefix) {
			projected.Files = append(projected.Files, file)
		}
	}
	for _, capture := range entry.Captures {
		if strings.HasPrefix(capture.Manifest, prefix) {
			projected.Captures = append(projected.Captures, capture)
		}
	}
	if len(projected.Files) == 0 || len(projected.Captures) == 0 {
		return "", errors.New("native source projection is missing original files or capture documents")
	}
	return projected.Identity()
}
