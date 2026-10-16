package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/publication"
)

// approvedReferences admits a reviewed release without changing the original
// retained catalog. Result evidence is permanent provenance, never a verdict
// for this implementation: replay and Apple verification still run afresh.
func approvedReferences(ctx context.Context, root, pinPath, bundles string, original corpus.Catalog, recipes replayContract) (corpus.Catalog, error) {
	if bundles == "" {
		return corpus.Catalog{}, errors.New("reviewed native reference assets require an explicit bundle directory")
	}
	if !filepath.IsAbs(pinPath) {
		pinPath = filepath.Join(root, filepath.FromSlash(pinPath))
	}
	input, err := os.Open(pinPath)
	if err != nil {
		return corpus.Catalog{}, err
	}
	pin, readErr := publication.ReadPin(input)
	if err = errors.Join(readErr, input.Close()); err != nil {
		return corpus.Catalog{}, err
	}
	input, err = os.Open(filepath.Join(bundles, pin.Catalog.Name))
	if err != nil {
		return corpus.Catalog{}, err
	}
	required, err := referenceRequirements(original, recipes)
	if err != nil {
		_ = input.Close()
		return corpus.Catalog{}, err
	}
	published, readErr := publication.ReadManifest(input, pin, original, required)
	if err = errors.Join(readErr, input.Close()); err != nil {
		return corpus.Catalog{}, err
	}
	current, err := captureContract(ctx, root, recipes)
	if err != nil {
		return corpus.Catalog{}, err
	}
	if published.CaptureContract != current {
		return corpus.Catalog{}, errors.New("approved native references have a different collector/helper/recipe contract; fresh capture is required")
	}
	if err = verifyReferenceAsset(ctx, bundles, published.Evidence); err != nil {
		return corpus.Catalog{}, err
	}
	return published.Corpus, nil
}

func verifyReferenceAsset(ctx context.Context, directory string, asset publication.Asset) error {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	info, err := root.Lstat(asset.Name)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() != asset.Bytes {
		return errors.New("permanent candidate qualification evidence size/type differs")
	}
	input, err := root.Open(asset.Name)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	digest := sha256.New()
	reader := io.LimitReader(input, asset.Bytes+1)
	buffer := make([]byte, 64<<10)
	var count int64
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		n, readErr := reader.Read(buffer)
		count += int64(n)
		_, _ = digest.Write(buffer[:n])
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if count != asset.Bytes || hex.EncodeToString(digest.Sum(nil)) != asset.SHA256 {
		return errors.New("permanent candidate qualification evidence bytes differ")
	}
	return nil
}

func checkReferenceAssets(ctx context.Context, root, registryPath, pinPath, bundles string) error {
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
	definitions, err := corpusDefinitions(r)
	if err != nil {
		return err
	}
	if err = corpus.MatchRetainedDefinitions(original, definitions); err != nil {
		return err
	}
	approved, err := approvedReferences(ctx, root, pinPath, bundles, original, recipes)
	if err != nil {
		return err
	}
	resolver, err := corpus.New(approved, corpus.Options{Repository: root, Bundles: bundles})
	if err != nil {
		return err
	}
	for _, entry := range approved.Entries {
		source, err := resolver.Resolve(ctx, entry.ID)
		if err != nil {
			return err
		}
		if err = source.Close(); err != nil {
			return err
		}
	}
	return nil
}
