package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

type continuationInput struct {
	path     string
	identity receipt.Input
	files    []receipt.File
}

func snapshotFiles(ctx context.Context, root string) ([]receipt.File, error) {
	files := []receipt.File{}
	var bytes int64
	err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if name == filepath.Join(root, ".qualification") {
				return filepath.SkipDir
			}
			return nil
		}
		relative, err := filepath.Rel(root, name)
		if err != nil {
			return err
		}
		file, err := digestFile(ctx, root, relative)
		if err != nil {
			return err
		}
		if file.Bytes > (64<<30)-bytes || len(files) >= 1000000 {
			return errors.New("execution artifact tree exceeds bounds")
		}
		bytes += file.Bytes
		files = append(files, file)
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(files, func(a, b receipt.File) int { return strings.Compare(a.Path, b.Path) })
	return files, nil
}

func continuationCases(ctx context.Context, root string, spec replayTest, family string) ([]receipt.Case, []string, continuationInput, error) {
	var input continuationInput
	kind := spec.Kind
	if spec.KindEnvironment != "" {
		kind = os.Getenv(spec.KindEnvironment)
	}
	if kind != "apfs" && kind != "hfs" {
		return nil, nil, input, errors.New("explicit native continuation filesystem missing")
	}
	location := os.Getenv(spec.Environment)
	if location == "" {
		return nil, nil, input, errors.New("required native continuation absent")
	}
	if !filepath.IsAbs(location) {
		location = filepath.Join(root, "acceptance", location)
	}
	location, err := filepath.Abs(location)
	if err != nil {
		return nil, nil, input, err
	}
	files, err := snapshotFiles(ctx, location)
	if err != nil {
		return nil, nil, input, err
	}
	profiles := []string{"apfs", "apfs-case-sensitive"}
	if kind == "hfs" {
		profiles = []string{"hfsplus", "hfsx"}
		if spec.Test == "TestNativeImageMetadataEditingContinuation" {
			profiles = append(profiles, "hfsplus-empty-attributes", "hfsx-empty-attributes")
		}
	}
	input.path = location
	input.identity.ID = "continuation-" + strings.ToLower(strings.ReplaceAll(spec.Environment, "_", "-"))
	input.identity.Use = "native-continuation"
	var cases []receipt.Case
	expected := map[string]bool{}
	for _, major := range []int{15, 26, 27} {
		for _, profile := range profiles {
			name := fmt.Sprintf("macos-%d-%s.raw", major, profile)
			expected[name] = true
			if spec.KindEnvironment != "" {
				expected[strings.TrimSuffix(name, ".raw")+".json"] = true
			}
			output := strings.TrimSuffix(name, ".raw") + ".dmg"
			if spec.Test == "TestNativeHFSImageEditingContinuation" {
				output = name + ".dmg"
			}
			cases = append(cases, receipt.Case{Family: family, Test: spec.Test + "/" + name, Corpus: input.identity.ID, NativeCase: "continuations/" + name, Source: major, Variant: "go-after-apple/" + kind, Continuation: true, Outputs: []string{spec.Output + "/" + output}})
		}
	}
	if len(files) != len(expected) {
		return nil, nil, input, errors.New("native continuation input inventory incomplete/extra")
	}
	for _, file := range files {
		if !expected[file.Path] {
			return nil, nil, input, fmt.Errorf("unexpected native continuation input: %s", file.Path)
		}
	}
	input.identity.TreeSHA256, err = receipt.Digest(files)
	input.files = files
	return cases, []string{spec.Test}, input, err
}

func (c continuationInput) verify(ctx context.Context) error {
	files, err := snapshotFiles(ctx, c.path)
	if err != nil {
		return err
	}
	digest, err := receipt.Digest(files)
	if err != nil {
		return err
	}
	if digest != c.identity.TreeSHA256 {
		return errors.New("native continuation source changed during Go replay")
	}
	return nil
}
