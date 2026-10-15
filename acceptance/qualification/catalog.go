package main

import (
	"context"
	"encoding/json"
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
)

type corpusAction struct {
	catalog, bootstrap, verify, bundle, bundles string
	describe                                    bool
}

func corpusDefinitions(r registry) ([]corpus.Definition, error) {
	definitions := map[string]*corpus.Definition{}
	for _, family := range r.Families {
		for _, directory := range family.Corpora {
			def := definitions[directory]
			if def == nil {
				def = &corpus.Definition{ID: path.Base(directory), Path: directory}
				definitions[directory] = def
				for _, manifest := range r.Manifests {
					if relative, ok := strings.CutPrefix(manifest.Path, directory+"/"); ok {
						def.Manifests = append(def.Manifests, corpus.ManifestReference{Path: relative, SHA256: manifest.SHA256, Cases: manifest.Cases})
					}
				}
				if len(def.Manifests) == 0 {
					return nil, fmt.Errorf("corpus has no registered native manifests: %s", directory)
				}
			}
			def.Bindings = append(def.Bindings, corpus.Binding{Family: family.ID, CaptureClass: family.CaptureClass})
		}
	}
	var result []corpus.Definition
	for _, def := range definitions {
		result = append(result, *def)
	}
	slices.SortFunc(result, func(a, b corpus.Definition) int { return strings.Compare(a.ID, b.ID) })
	return result, nil
}

func corpusWork(ctx context.Context, root, registryPath string, action corpusAction, out io.Writer) error {
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(registryPath)))
	if err != nil {
		return err
	}
	var r registry
	if err = corpus.StrictJSON(data, &r); err != nil {
		return err
	}
	definitions, err := corpusDefinitions(r)
	if err != nil {
		return err
	}
	if action.bootstrap != "" && (action.verify != "" || action.bundle != "" || action.describe) {
		return errors.New("bootstrap prepares a candidate; it cannot be combined with catalog execution")
	}
	if action.bootstrap != "" {
		if err := cleanNativeCheckout(ctx, root); err != nil {
			return err
		}
		catalog, err := corpus.Build(ctx, root, definitions)
		if err != nil {
			return err
		}
		if err = writeNewCatalog(action.bootstrap, catalog); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "Prepared unapproved catalog: %d corpus trees. Review before committing or promoting it.\n", len(catalog.Entries))
		return err
	}
	catalogPath := action.catalog
	if !filepath.IsAbs(catalogPath) {
		catalogPath = filepath.Join(root, filepath.FromSlash(catalogPath))
	}
	input, err := os.Open(catalogPath)
	if err != nil {
		return err
	}
	catalog, err := corpus.Read(input)
	closeErr := input.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = corpus.MatchRetainedDefinitions(catalog, definitions); err != nil {
		return err
	}
	if action.describe {
		for _, entry := range catalog.Entries {
			majors := []int{}
			for _, capture := range entry.Captures {
				if !slices.Contains(majors, capture.Major) {
					majors = append(majors, capture.Major)
				}
			}
			slices.Sort(majors)
			if _, err = fmt.Fprintf(out, "%s: %d files, %d retained bytes, macOS %v, input %s\n", entry.ID, len(entry.Files), entry.TotalBytes(), majors, entry.TreeSHA256); err != nil {
				return err
			}
		}
	}
	if action.verify != "" && action.bundle != "" {
		return errors.New("choose verification or bundle construction")
	}
	if action.describe && action.bundle != "" {
		return errors.New("bundle records cannot be combined with human-readable catalog descriptions")
	}
	resolver, err := corpus.New(catalog, corpus.Options{Repository: root, Bundles: action.bundles})
	if err != nil {
		return err
	}
	if action.bundle != "" {
		if action.bundles == "" {
			return errors.New("bundle construction requires an existing --bundle-dir outside the corpus")
		}
		ids := []string{action.bundle}
		if action.bundle == "all" {
			ids = nil
			for _, entry := range catalog.Entries {
				ids = append(ids, entry.ID)
			}
		}
		for _, id := range ids {
			source, err := resolver.Resolve(ctx, id)
			if err != nil {
				return err
			}
			bundle, err := corpus.WriteBundle(ctx, source, action.bundles)
			closeErr := source.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
			if err = json.NewEncoder(out).Encode(struct {
				ID         string        `json:"id"`
				TreeSHA256 string        `json:"tree_sha256"`
				Bundle     corpus.Bundle `json:"bundle"`
			}{id, source.TreeSHA256(), bundle}); err != nil {
				return err
			}
		}
		return nil
	}
	if action.verify != "" {
		ids := []string{action.verify}
		if action.verify == "all" {
			ids = nil
			for _, entry := range catalog.Entries {
				ids = append(ids, entry.ID)
			}
		}
		for _, id := range ids {
			resolved, err := resolver.Resolve(ctx, id)
			if err != nil {
				return err
			}
			if err = resolved.Close(); err != nil {
				return err
			}
		}
		_, err = fmt.Fprintf(out, "Verified exact retained files and original capture documents for %d corpus trees. Native filesystem assertions remain required.\n", len(ids))
		return err
	}
	_, err = fmt.Fprintf(out, "Catalog coverage audited: %d corpus trees; no execution verdicts inherited.\n", len(catalog.Entries))
	return err
}

func cleanNativeCheckout(ctx context.Context, root string) error {
	command := exec.CommandContext(ctx, "git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching", "--", "acceptance/testdata")
	command.Dir = root
	status, err := command.Output()
	if err != nil {
		return fmt.Errorf("check original evidence checkout: %w", err)
	}
	if len(status) != 0 {
		return errors.New("bootstrap requires a clean native-evidence checkout, including ignored files; use an isolated checkout without changing existing evidence")
	}
	return nil
}

func writeNewCatalog(name string, catalog corpus.Catalog) error {
	output, err := os.CreateTemp(filepath.Dir(name), ".corpus-catalog-")
	if err != nil {
		return err
	}
	temporary := output.Name()
	defer func() { _ = output.Close(); _ = os.Remove(temporary) }()
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	if err = encoder.Encode(catalog); err != nil {
		return err
	}
	if err = output.Sync(); err != nil {
		return err
	}
	if err = output.Close(); err != nil {
		return err
	}
	return os.Link(temporary, name)
}
