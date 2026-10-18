package schema

import (
	"fmt"
	"os"
)

// DriftSchema is the current known-drift.json schema version.
const DriftSchema = 1

// KnownDrift lists every difference between macOS versions that the
// cross-version parity check accepts. Any other difference fails the native
// gate. Entries are written by people after a capture has shown the
// difference and the Apple behaviour has been understood.
type KnownDrift struct {
	Schema  int          `json:"schema"`
	Entries []DriftEntry `json:"entries"`
}

// DriftEntry names one observed field that legitimately differs.
type DriftEntry struct {
	Recipe  string `json:"recipe"`
	Profile string `json:"profile,omitempty"` // empty means every profile
	Path    string `json:"path,omitempty"`    // entry path; empty for image/volume fields
	Field   string `json:"field"`             // JSON pointer-like name, e.g. "compression.kernelRead"
	// Producers maps "macos-<major>" to the value each producer records.
	Producers map[string]string `json:"producers"`
	Reason    string            `json:"reason"`
}

// ReadKnownDrift decodes and validates the allow-list.
func ReadKnownDrift(path string) (*KnownDrift, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var drift KnownDrift
	if err := DecodeStrict(data, &drift); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if drift.Schema != DriftSchema {
		return nil, fmt.Errorf("%s: schema %d, want %d", path, drift.Schema, DriftSchema)
	}
	for i, entry := range drift.Entries {
		if entry.Recipe == "" || entry.Field == "" || entry.Reason == "" || len(entry.Producers) < 2 {
			return nil, fmt.Errorf("%s: entry %d must name a recipe, a field, a reason and at least two producers", path, i)
		}
	}
	return &drift, nil
}
