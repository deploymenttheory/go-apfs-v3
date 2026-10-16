// Package replay supplies verified input locations to existing acceptance
// entrypoints. Location is independent of the required native capture controls.
package replay

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
)

type Binding struct {
	ID          string `json:"id"`
	Environment string `json:"environment"`
	Path        string `json:"path"`
	TreeSHA256  string `json:"tree_sha256"`
}

type Inputs struct {
	Schema   int       `json:"schema"`
	Bindings []Binding `json:"bindings"`
}

// InputPath dispatches by corpus identity, rather than environment variable.
// Existing HFS file/catalog tests share one override variable but intentionally
// have different retained corpora; exporting one resolved path would conflate
// those independent observations. Ordinary direct go test remains supported.
func InputPath(environment, fallback string) (string, error) {
	name := os.Getenv("APFS_REPLAY_INPUTS")
	if name == "" {
		if override := os.Getenv(environment); override != "" {
			return override, nil
		}
		return fallback, nil
	}
	input, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer func() { _ = input.Close() }()
	data, err := io.ReadAll(io.LimitReader(input, (1<<20)+1))
	if err != nil || len(data) > 1<<20 {
		return "", errors.New("invalid replay input binding document")
	}
	var inputs Inputs
	if err = corpus.StrictJSON(data, &inputs); err != nil {
		return "", err
	}
	if inputs.Schema != 1 || len(inputs.Bindings) == 0 || len(inputs.Bindings) > 1000 {
		return "", errors.New("missing replay input bindings")
	}
	seen := map[string]bool{}
	var selected string
	for _, binding := range inputs.Bindings {
		if binding.ID == "" || seen[binding.ID] || !filepath.IsAbs(binding.Path) || binding.Environment == "" || !corpus.ValidDigest(binding.TreeSHA256) {
			return "", errors.New("incomplete/duplicate replay input binding")
		}
		seen[binding.ID] = true
		if binding.ID == path.Base(fallback) {
			if binding.Environment != environment {
				return "", errors.New("replay input override contract differs")
			}
			selected = binding.Path
		}
	}
	if selected == "" {
		return "", fmt.Errorf("required corpus was not admitted by replay: %s", path.Base(fallback))
	}
	return selected, nil
}
