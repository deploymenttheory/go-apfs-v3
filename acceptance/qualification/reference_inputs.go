package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
)

// materializeReferences retains original input bytes for native programs that
// accept directory paths. These are managed ordinary files, never mounted disk
// images. Current-Go experiments cannot be supplied by a historical release.
func materializeReferences(ctx context.Context, root, registryPath, pin, bundles, selected, destination string) (err error) {
	data, err := regularFile(root, registryPath)
	if err != nil {
		return err
	}
	var r registry
	if err = corpus.StrictJSON(data, &r); err != nil {
		return err
	}
	recipes, err := readReplayContract(root, r)
	if err != nil {
		return err
	}
	data, err = regularFile(root, "acceptance/qualification/corpus.json")
	if err != nil {
		return err
	}
	original, err := corpus.Read(strings.NewReader(string(data)))
	if err != nil {
		return err
	}
	approved, err := approvedReferences(ctx, root, pin, bundles, original, recipes)
	if err != nil {
		return err
	}
	ids := strings.Split(selected, ",")
	seen := map[string]bool{}
	for _, id := range ids {
		if id == "" || seen[id] {
			return errors.New("selected reference inputs are empty/duplicated")
		}
		seen[id] = true
		index := slices.IndexFunc(approved.Entries, func(e corpus.Entry) bool { return e.ID == id })
		if index < 0 || approved.Entries[index].Location.Kind != "bundle" {
			return fmt.Errorf("independent input unavailable; current-Go experiments require fresh execution: %s", id)
		}
	}
	if !filepath.IsAbs(destination) {
		return errors.New("reference scratch location must be absolute")
	}
	if _, err = os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return errors.New("reference materialization requires absent managed scratch")
	}
	if err = separatePaths(bundles, destination); err != nil {
		return err
	}
	if err = separatePaths(root, destination); err != nil {
		return errors.New("materialized reference scratch must be outside the source checkout")
	}
	if err = os.MkdirAll(destination, 0700); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(destination)
		}
	}()
	resolver, err := corpus.New(approved, corpus.Options{Repository: root, Bundles: bundles})
	if err != nil {
		return err
	}
	inputs := candidateInputs{Schema: 1, Inputs: []candidateInput{}}
	slices.Sort(ids)
	for _, id := range ids {
		source, err := resolver.Resolve(ctx, id)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, id)
		copyErr := os.CopyFS(target, os.DirFS(source.Path()))
		verifyErr := source.Verify(ctx)
		closeErr := source.Close()
		if err = errors.Join(copyErr, verifyErr, closeErr); err != nil {
			return err
		}
		entry := approved.Entries[slices.IndexFunc(approved.Entries, func(e corpus.Entry) bool { return e.ID == id })]
		entry.Location = corpus.Location{Kind: "committed", Path: id}
		copied, err := corpus.New(corpus.Catalog{Schema: 1, Entries: []corpus.Entry{entry}}, corpus.Options{Repository: destination})
		if err != nil {
			return err
		}
		checked, err := copied.Resolve(ctx, id)
		if err != nil {
			return err
		}
		if err = checked.Close(); err != nil {
			return err
		}
		inputs.Inputs = append(inputs.Inputs, candidateInput{ID: id, Path: target})
	}
	return newJSON(filepath.Join(destination, "inputs.json"), inputs)
}
