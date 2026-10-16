package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

type replayEvidence struct {
	Schema            int                    `json:"schema"`
	OutputEnvironment string                 `json:"output_environment"`
	Inputs            []corpus.Entry         `json:"inputs"`
	Continuations     []continuationEvidence `json:"continuations"`
}

type continuationEvidence struct {
	Input receipt.Input  `json:"input"`
	Files []receipt.File `json:"files"`
}

// Publish proof with the existing output archives. Ledger bytes are excluded
// from output identities: adding a proof cannot change the bytes it describes.
func publishReplayEvidence(ctx context.Context, scratch string, result receipt.Receipt, roots map[string]string, admitted *admittedInputs, continuations map[string]continuationInput) error {
	metadata := replayEvidence{Schema: 1, Inputs: []corpus.Entry{}, Continuations: []continuationEvidence{}}
	for _, entry := range admitted.entries {
		metadata.Inputs = append(metadata.Inputs, entry)
	}
	slices.SortFunc(metadata.Inputs, func(a, b corpus.Entry) int { return strings.Compare(a.ID, b.ID) })
	for _, input := range continuations {
		metadata.Continuations = append(metadata.Continuations, continuationEvidence{Input: input.identity, Files: input.files})
	}
	slices.SortFunc(metadata.Continuations, func(a, b continuationEvidence) int { return strings.Compare(a.Input.ID, b.Input.ID) })
	// Readers also need their complete original source snapshot even when no
	// writer output directory exists to carry a .qualification copy.
	if err := newJSON(filepath.Join(scratch, "source-inputs.json"), metadata); err != nil {
		return err
	}
	for variable, root := range roots {
		metadata.OutputEnvironment = variable
		directory := filepath.Join(root, ".qualification", result.Fingerprint)
		if err := os.MkdirAll(directory, 0700); err != nil {
			return err
		}
		if err := newJSON(filepath.Join(directory, "inputs.json"), metadata); err != nil {
			return err
		}
		for _, name := range []string{"plan.json", "events.jsonl"} {
			if err := copyEvidence(ctx, filepath.Join(scratch, name), filepath.Join(directory, name)); err != nil {
				return err
			}
		}
		if err := newJSON(filepath.Join(directory, "receipt.json"), result); err != nil {
			return err
		}
	}
	return nil
}

func copyEvidence(ctx context.Context, source, destination string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	output, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	buffer := make([]byte, 64<<10)
	for {
		if err = ctx.Err(); err != nil {
			break
		}
		n, readErr := input.Read(buffer)
		if n > 0 {
			if _, err = output.Write(buffer[:n]); err != nil {
				break
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			err = readErr
			break
		}
	}
	return errors.Join(err, output.Close())
}
