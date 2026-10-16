package main

import (
	"errors"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/publication"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

type executionEvidenceArtifact struct {
	Kind  string `json:"kind,omitempty"`
	Major int    `json:"native_major,omitempty"`
	Name  string `json:"name"`
	Job   string `json:"job"`
	Host  string `json:"host"`
}

// The controller authenticates the original successful workflow and upload jobs
// before constructing this document. A caller-supplied origin is not authority.
type executionEvidenceOrigin struct {
	Schema     int                         `json:"schema"`
	Workflow   string                      `json:"workflow"`
	Origin     publication.Origin          `json:"origin"`
	Tree       string                      `json:"tree_sha"`
	Projection string                      `json:"source_projection,omitempty"`
	Artifacts  []executionEvidenceArtifact `json:"artifacts"`
}

type executionEvidenceSummary struct {
	Schema     int                `json:"schema"`
	Origin     publication.Origin `json:"origin"`
	Tree       string             `json:"tree_sha"`
	Receipts   []receipt.File     `json:"original_receipts"`
	CaseCount  int                `json:"qualified_cases"`
	Projection *executionChanges  `json:"source_projection,omitempty"`
}

func projectGoVersion(root string) (string, error) {
	data, err := regularFile(root, "go.mod")
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 && fields[0] == "go" {
			return fields[1], nil
		}
	}
	return "", errors.New("project Go toolchain version missing")
}
