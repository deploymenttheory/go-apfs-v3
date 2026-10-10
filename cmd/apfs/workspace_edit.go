package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

type editInput struct {
	workspace.Change
	Contents          string `json:"contents,omitempty"`
	InitialAttributes []struct {
		Name     string `json:"name"`
		Contents string `json:"contents"`
	} `json:"attributes,omitempty"`
}

// The CLI only resolves explicitly supplied input files. Tree operations and
// metadata rules belong to workspace.Edit, shared by library consumers.
func editWorkspace(ctx context.Context, w *workspace.Workspace, plan, destination string) (report workspace.Report, err error) {
	f, err := os.Open(plan)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, f.Close()) }()
	const maxPlan = 16 << 20
	info, err := f.Stat()
	if err != nil {
		return report, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxPlan {
		return report, filesystem.ErrLimit
	}
	var document struct {
		Schema  int         `json:"schema"`
		Changes []editInput `json:"changes"`
	}
	decoder := json.NewDecoder(io.LimitReader(f, maxPlan+1))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&document); err != nil {
		return report, err
	}
	var extra any
	if e := decoder.Decode(&extra); e != io.EOF {
		return report, fmt.Errorf("edit plan trailing data: %w", filesystem.ErrCorrupt)
	}
	if document.Schema != 1 {
		return report, filesystem.ErrUnsupported
	}
	if len(document.Changes) > workspace.DefaultLimits().Entries {
		return report, filesystem.ErrLimit
	}
	var sources []*block.File
	defer func() {
		for _, source := range sources {
			err = errors.Join(err, source.Close())
		}
	}()
	open := func(name string) (block.Source, error) {
		if name == "" {
			return nil, fmt.Errorf("missing contents path: %w", filesystem.ErrConflict)
		}
		if !filepath.IsAbs(name) {
			name = filepath.Join(filepath.Dir(plan), name)
		}
		source, e := block.Open(name)
		if e != nil {
			return nil, e
		}
		sources = append(sources, source)
		return source, nil
	}
	changes := make([]workspace.Change, len(document.Changes))
	for i, input := range document.Changes {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		c := input.Change
		if input.Contents != "" {
			c.Data, err = open(input.Contents)
			if err != nil {
				return report, err
			}
		}
		if input.InitialAttributes != nil {
			c.Attributes = map[string]block.Source{}
		}
		for _, a := range input.InitialAttributes {
			if _, ok := c.Attributes[a.Name]; ok {
				return report, fmt.Errorf("duplicate initial attribute: %w", filesystem.ErrConflict)
			}
			value, e := open(a.Contents)
			if e != nil {
				return report, e
			}
			c.Attributes[a.Name] = value
		}
		changes[i] = c
	}
	return w.Edit(ctx, changes, destination, workspace.Limits{})
}
