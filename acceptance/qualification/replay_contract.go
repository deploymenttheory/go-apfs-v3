package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/replay"
)

type replayInput struct {
	ID          string `json:"id"`
	Environment string `json:"environment"`
}

type replayTest struct {
	Test            string   `json:"test"`
	Input           string   `json:"input,omitempty"`
	Environment     string   `json:"environment,omitempty"`
	Manifest        string   `json:"manifest,omitempty"`
	CaptureContract string   `json:"capture_contract,omitempty"`
	Layout          string   `json:"layout"`
	Variants        []string `json:"variants,omitempty"`
	Auxiliary       []string `json:"auxiliary,omitempty"`
	Output          string   `json:"output,omitempty"`
	Kind            string   `json:"kind,omitempty"`
	KindEnvironment string   `json:"kind_environment,omitempty"`
	Seeds           int      `json:"seeds,omitempty"`
	Controls        []string `json:"controls,omitempty"`
	FreshRaceHosts  []string `json:"fresh_race_hosts,omitempty"`
	NativeScope     string   `json:"native_scope,omitempty"`
}

type replayContract struct {
	Schema int           `json:"schema"`
	Inputs []replayInput `json:"inputs"`
	Tests  []replayTest  `json:"tests"`
}

func readReplayContract(root string, r registry) (replayContract, error) {
	var contract replayContract
	data, err := regularFile(root, "acceptance/qualification/replay.json")
	if err != nil {
		return contract, err
	}
	if len(data) > 1<<20 {
		return contract, errors.New("replay contract exceeds bound")
	}
	if err = corpus.StrictJSON(data, &contract); err != nil {
		return contract, err
	}
	known := map[string][]string{}
	for _, family := range r.Families {
		for _, test := range family.Tests {
			known[test.Name] = family.Corpora
		}
	}
	inputs := map[string]bool{}
	last := ""
	for _, input := range contract.Inputs {
		if input.ID <= last || !strings.HasPrefix(input.Environment, "APFS_NATIVE_") {
			return contract, errors.New("invalid/duplicate replay input binding")
		}
		last, inputs[input.ID] = input.ID, true
	}
	if contract.Schema != 1 || len(contract.Tests) != len(known) {
		return contract, errors.New("replay entrypoint coverage differs from registry")
	}
	last = ""
	writers := map[string]string{}
	for _, test := range contract.Tests {
		paths, exists := known[test.Test]
		if !exists || test.Test <= last || !slices.Contains([]string{"control", "fuzz", "continuation", "source-case", "combined-case", "construction", "containers", "repacking", "growth", "lifecycle", "checkpoint-recovery", "statistics-transitions"}, test.Layout) {
			return contract, fmt.Errorf("invalid/unregistered replay test: %s", test.Test)
		}
		last = test.Test
		if test.NativeScope != "" && test.NativeScope != "matching-source" {
			return contract, errors.New("unknown native verification source scope")
		}
		if !slices.IsSorted(test.FreshRaceHosts) {
			return contract, errors.New("fresh race host inventory is not sorted")
		}
		for index, host := range test.FreshRaceHosts {
			if !slices.Contains([]string{"linux", "windows", "darwin"}, host) || slices.Contains(test.FreshRaceHosts[:index], host) || test.Input == "" {
				return contract, errors.New("invalid/duplicate fresh race host")
			}
		}
		if test.Output != "" {
			owner := test.Input
			if owner == "" {
				owner = test.Test
			}
			if previous, exists := writers[test.Output]; exists && previous != owner {
				return contract, errors.New("independent corpus writers require distinct output locations")
			}
			writers[test.Output] = owner
		}
		if test.Input != "" && (!inputs[test.Input] || !slices.Contains(paths, "acceptance/testdata/"+test.Input)) {
			return contract, errors.New("replay input differs from capability registry")
		}
		if len(paths) != 0 && test.Input == "" || strings.HasSuffix(test.Test, "Continuation") != (test.Layout == "continuation") {
			return contract, errors.New("native case obligations cannot become inputless controls")
		}
		for _, input := range test.Auxiliary {
			if !inputs[input] || !slices.Contains(paths, "acceptance/testdata/"+input) {
				return contract, errors.New("auxiliary replay input differs from registry")
			}
		}
		if test.Layout == "continuation" && (test.Environment == "" || test.Output == "" || test.Kind == "" && test.KindEnvironment == "") || test.Layout != "continuation" && test.Layout != "control" && (test.Input == "" || test.Manifest == "") {
			return contract, errors.New("incomplete replay case contract")
		}
	}
	return contract, nil
}

type admittedInputs struct {
	bindings   replay.Inputs
	entries    map[string]corpus.Entry
	resolved   map[string]*corpus.Resolved
	identities []receipt.Input
}

func (a *admittedInputs) close() error {
	var err error
	for _, source := range a.resolved {
		err = errors.Join(err, source.Close())
	}
	return err
}

func admitReplayInputs(ctx context.Context, root, catalogPath, bundles, referencePin string, r registry, contract replayContract, selected []replayTest) (_ *admittedInputs, err error) {
	if !filepath.IsAbs(catalogPath) {
		catalogPath = filepath.Join(root, filepath.FromSlash(catalogPath))
	}
	file, err := os.Open(catalogPath)
	if err != nil {
		return nil, err
	}
	catalog, err := corpus.Read(file)
	closeErr := file.Close()
	if err != nil {
		return nil, err
	}
	if closeErr != nil {
		return nil, closeErr
	}
	definitions, err := corpusDefinitions(r)
	if err != nil {
		return nil, err
	}
	if err = corpus.MatchRetainedDefinitions(catalog, definitions); err != nil {
		return nil, err
	}
	if referencePin != "" {
		catalog, err = approvedReferences(ctx, root, referencePin, bundles, catalog, contract)
		if err != nil {
			return nil, err
		}
	}
	retained, err := corpus.New(catalog, corpus.Options{Repository: root, Bundles: bundles})
	if err != nil {
		return nil, err
	}
	a := &admittedInputs{bindings: replay.Inputs{Schema: 1}, entries: map[string]corpus.Entry{}, resolved: map[string]*corpus.Resolved{}}
	defer func() {
		if err != nil {
			_ = a.close()
		}
	}()
	needed := map[string]bool{}
	for _, test := range selected {
		if test.Input != "" {
			needed[test.Input] = true
		}
		for _, id := range test.Auxiliary {
			needed[id] = true
		}
	}
	for _, binding := range contract.Inputs {
		if !needed[binding.ID] {
			continue
		}
		index := slices.IndexFunc(catalog.Entries, func(e corpus.Entry) bool { return e.ID == binding.ID })
		if index < 0 {
			return nil, fmt.Errorf("required retained corpus missing: %s", binding.ID)
		}
		entry, resolver := catalog.Entries[index], retained
		reference := entry
		use := "retained"
		if override := os.Getenv(binding.Environment); override != "" {
			if !filepath.IsAbs(override) {
				override = filepath.Join(root, "acceptance", override)
			}
			override, err = filepath.Abs(override)
			if err != nil {
				return nil, err
			}
			parent := filepath.Dir(override)
			candidate, captureErr := corpus.InspectCapture(ctx, parent, corpus.Definition{ID: binding.ID, Path: filepath.Base(override), Bindings: entry.Bindings})
			if captureErr != nil {
				return nil, fmt.Errorf("current native input %s: %w", binding.ID, captureErr)
			}
			entry = candidate.Entries[0]
			if referencePin != "" && entry.TreeSHA256 != reference.TreeSHA256 {
				return nil, errors.New("native input override differs from the reviewed reference pin")
			}
			use = "native-capture"
			if entry.TreeSHA256 == reference.TreeSHA256 {
				use = "retained"
			}
			resolver, err = corpus.New(candidate, corpus.Options{Repository: parent})
			if err != nil {
				return nil, err
			}
		}
		source, resolveErr := resolver.Resolve(ctx, binding.ID)
		if resolveErr != nil {
			return nil, resolveErr
		}
		a.entries[binding.ID], a.resolved[binding.ID] = entry, source
		if use != "retained" {
			for _, test := range selected {
				if test.Input == binding.ID {
					if err = matchCaptureCases(test, entry, reference); err != nil {
						return nil, err
					}
				}
			}
			if slices.ContainsFunc(entry.Bindings, func(b corpus.Binding) bool { return b.CaptureClass == "current-go-experiment" }) {
				use = "current-go"
				revision, revisionErr := commandText(ctx, root, "git", "rev-parse", "HEAD")
				if revisionErr != nil {
					return nil, revisionErr
				}
				for _, capture := range entry.Captures {
					data, readErr := source.Manifest(capture.Manifest)
					if readErr != nil {
						return nil, readErr
					}
					var document struct{ Producer struct{ Revision string } }
					if json.Unmarshal(data, &document) != nil || document.Producer.Revision != revision {
						return nil, errors.New("matched native experiment belongs to a different Go revision")
					}
				}
			}
		}
		a.bindings.Bindings = append(a.bindings.Bindings, replay.Binding{ID: binding.ID, Environment: binding.Environment, Path: source.Path(), TreeSHA256: source.TreeSHA256()})
		a.identities = append(a.identities, receipt.Input{ID: binding.ID, TreeSHA256: source.TreeSHA256(), Use: use})
	}
	return a, nil
}

func matchCaptureCases(spec replayTest, actual, reference corpus.Entry) error {
	matched := false
	for _, capture := range actual.Captures {
		matches, err := path.Match(spec.Manifest, capture.Manifest)
		if err != nil {
			return err
		}
		if !matches {
			continue
		}
		matched = true
		index := slices.IndexFunc(reference.Captures, func(c corpus.Capture) bool {
			ok, _ := path.Match(spec.Manifest, c.Manifest)
			return ok && c.Major == capture.Major
		})
		if index < 0 {
			index = slices.IndexFunc(reference.Captures, func(c corpus.Capture) bool { ok, _ := path.Match(spec.Manifest, c.Manifest); return ok })
		}
		if index < 0 {
			return errors.New("capture has no reviewed case contract")
		}
		expected := reference.Captures[index]
		contract := expected.Contract
		if spec.CaptureContract != "" && expected.Role == "retained-index" && capture.Role == "native-capture" {
			// Readable retained indexes have their own scenario. The reviewed
			// recipe names the original capture contract, without changing
			// either document or weakening the required case inventory.
			contract = spec.CaptureContract
		}
		want, got := slices.Clone(expected.Cases), slices.Clone(capture.Cases)
		slices.Sort(want)
		slices.Sort(got)
		if capture.Contract != contract || !slices.Equal(want, got) {
			return fmt.Errorf("capture case/contract inventory differs from reviewed inputs: %s", capture.Manifest)
		}
	}
	if !matched {
		return errors.New("required native capture manifest missing")
	}
	return nil
}

func replayCases(spec replayTest, family string, admitted *admittedInputs) ([]receipt.Case, []string, error) {
	parents := []string{spec.Test}
	if spec.Layout == "control" {
		return []receipt.Case{{Family: family, Test: spec.Test, NativeCase: spec.Test}}, parents, nil
	}
	entry, exists := admitted.entries[spec.Input]
	if !exists {
		return nil, nil, fmt.Errorf("input not admitted: %s", spec.Input)
	}
	source := admitted.resolved[spec.Input]
	var cases []receipt.Case
	if spec.Layout == "fuzz" {
		if spec.Seeds != 5 {
			return nil, nil, errors.New("native codec seed inventory differs")
		}
		for n := 0; n < spec.Seeds; n++ {
			cases = append(cases, receipt.Case{Family: family, Test: fmt.Sprintf("%s/seed#%d", spec.Test, n), Corpus: spec.Input, Manifest: "macos-27/manifest.json", NativeCase: "cases/file-compression/apfs", Source: 27, Variant: []string{"type-03", "type-07", "type-12", "type-14", "type-16"}[n]})
		}
		return cases, parents, nil
	}
	matched := 0
	for _, capture := range entry.Captures {
		match, err := path.Match(spec.Manifest, capture.Manifest)
		if err != nil {
			return nil, nil, err
		}
		if !match {
			continue
		}
		matched++
		data, err := source.Manifest(capture.Manifest)
		if err != nil {
			return nil, nil, err
		}
		var document struct{ SectorProbes []struct{ Capacity int64 } }
		// Most cases do not have state arrays. HFS catalog states are maps and
		// are deliberately parsed only by the lifecycle layout that needs labels.
		var raw map[string]json.RawMessage
		if err = json.Unmarshal(data, &raw); err != nil {
			return nil, nil, err
		}
		var records []map[string]json.RawMessage
		if err = json.Unmarshal(raw["cases"], &records); err != nil {
			return nil, nil, err
		}
		prefix := spec.Test + "/macos-" + strconv.Itoa(capture.Major)
		if spec.Layout != "combined-case" {
			parents = append(parents, prefix)
		}
		for _, record := range records {
			var id string
			if err = json.Unmarshal(record["id"], &id); err != nil {
				return nil, nil, err
			}
			name := id
			if spec.Layout == "repacking" {
				name = strings.TrimPrefix(id, "image-repacking/")
			}
			base := receipt.Case{Family: family, Test: prefix + "/" + name, Corpus: spec.Input, Manifest: capture.Manifest, NativeCase: "cases/" + id, Source: capture.Major}
			cases = append(cases, base)
			parents = append(parents, base.Test)
			add := func(variant string) {
				child := base
				child.Test += "/" + variant
				child.Variant = variant
				cases = append(cases, child)
			}
			for _, variant := range spec.Variants {
				add(variant)
				parents = append(parents, base.Test+"/"+variant)
			}
			if spec.Layout == "construction" || spec.Layout == "containers" || spec.Layout == "repacking" {
				for _, encoding := range []string{"UDRO", "UDZO"} {
					add(encoding)
					parents = append(parents, base.Test+"/"+encoding)
					profile := path.Base(id)
					bits := expectedOutputCipher(spec.Layout, profile, encoding)
					if bits != 0 {
						add(fmt.Sprintf("%s/encrypted-aes%d", encoding, bits))
					}
				}
			}
			if spec.Layout == "construction" {
				add("file-compression/zlib")
				add("file-compression/none")
				if id == "image-building/apfs" {
					add("empty/UDZO")
				}
			}
			if spec.Layout == "repacking" && name == "hfsplus-gpt" {
				parents = append(parents, base.Test+"/encrypted-input")
				add("encrypted-input/rewrapped/UDZO")
				add("encrypted-input/decrypted/UDZO")
			}
			if spec.Layout == "lifecycle" {
				var states []struct{ Label string }
				if err = json.Unmarshal(record["states"], &states); err != nil {
					return nil, nil, err
				}
				for _, state := range states {
					if state.Label == "" {
						return nil, nil, errors.New("native lifecycle label missing")
					}
					add(state.Label)
				}
			}
			if spec.Layout == "statistics-transitions" && os.Getenv(spec.Output) != "" {
				for _, segment := range []string{"before-compression", "final"} {
					for _, encoding := range []string{"UDRO", "UDZO"} {
						add(segment + "/" + encoding)
					}
				}
			}
			if len(record["collapsed"]) > 0 && string(record["collapsed"]) != "null" && len(record["reused"]) > 0 && string(record["reused"]) != "null" {
				for _, encoding := range spec.Variants {
					add(encoding + "/collapsed")
					add(encoding + "/reused")
				}
			}
		}
		if spec.Layout == "growth" {
			if err = json.Unmarshal(raw["sectorProbes"], &document.SectorProbes); err != nil {
				return nil, nil, err
			}
			for _, probe := range document.SectorProbes {
				cases = append(cases, receipt.Case{Family: family, Test: fmt.Sprintf("%s/unmounted-sectors-%d", prefix, probe.Capacity), Corpus: spec.Input, Manifest: capture.Manifest, NativeCase: fmt.Sprintf("sectorProbes/%d", probe.Capacity), Source: capture.Major})
			}
		}
		if spec.Layout == "checkpoint-recovery" {
			parent := prefix + "/interrupted-Go-commits"
			parents = append(parents, parent)
			for _, stage := range []string{"data", "metadata", "ephemeral", "mapping", "superblock", "block-zero"} {
				cases = append(cases, receipt.Case{Family: family, Test: parent + "/" + stage, Corpus: spec.Input, Manifest: capture.Manifest, NativeCase: "cases/apfs-committed", Variant: "interrupted-" + stage, Source: capture.Major})
			}
		}
		if spec.Layout == "repacking" {
			var rejections []struct{ ID string }
			if err = json.Unmarshal(raw["rejections"], &rejections); err != nil {
				return nil, nil, err
			}
			for _, item := range rejections {
				cases = append(cases, receipt.Case{Family: family, Test: prefix + "/rejected/" + item.ID, Corpus: spec.Input, Manifest: capture.Manifest, NativeCase: "rejections/" + item.ID, Source: capture.Major, Variant: "refused"})
			}
			base := prefix + "/hfsplus-encrypted-raw/UDZO"
			parents = append(parents, base)
			for _, suffix := range []string{"", "/encrypted-aes128"} {
				cases = append(cases, receipt.Case{Family: family, Test: base + suffix, Corpus: "encrypted-dmg", Manifest: fmt.Sprintf("macos-%d/manifest.json", capture.Major), NativeCase: "cases/disk-image-encryption/hfsplus-raw-aes256", Source: capture.Major, Variant: "raw-encrypted" + suffix})
			}
		}
	}
	if matched == 0 {
		return nil, nil, fmt.Errorf("required capture manifests missing: %s", spec.Test)
	}
	return cases, parents, nil
}

// This reviewed obligation table is separate from the writer's implementation.
// Randomized ciphertext remains a separate output, even when plaintext matches.
func expectedOutputCipher(layout, profile, encoding string) int {
	if layout == "repacking" {
		if profile == "hfsx-apm-raw" {
			if encoding == "UDRO" {
				return 128
			}
			return 0
		}
		if encoding == "UDZO" {
			return 256
		}
		return 0
	}
	for _, item := range []struct {
		profile, encoding string
		bits              int
	}{{"apfs", "UDRO", 128}, {"apfs-case-sensitive", "UDZO", 256}, {"hfsplus", "UDZO", 128}, {"hfsx", "UDRO", 256}, {"group", "UDZO", 256}} {
		if item.profile == profile && item.encoding == encoding {
			return item.bits
		}
	}
	return 0
}
