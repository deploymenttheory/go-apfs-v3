package schema

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
)

// LockSchema is the current fixtures.lock.json schema version.
const LockSchema = 1

// Lock pins the fixture corpus a checkout tests against. Changing a recipe
// changes RecipesSHA256; CI fails until a new corpus is captured and this file
// is updated in a reviewed pull request.
type Lock struct {
	Schema        int               `json:"schema"`
	Release       string            `json:"release"`
	RecipesSHA256 string            `json:"recipesSHA256"`
	Bundles       map[string]Bundle `json:"bundles"`
}

// Bundle pins one producer's bundle. The map key is "macos-<major>".
type Bundle struct {
	Asset      string `json:"asset"`
	SHA256     string `json:"sha256"`
	Bytes      int64  `json:"bytes"`
	Build      string `json:"build"`
	CaptureRun string `json:"captureRun"`
}

var digestPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ValidDigest reports whether s is a lowercase hex SHA-256.
func ValidDigest(s string) bool { return digestPattern.MatchString(s) }

// ReadLock decodes and validates a lock file. A lock with no bundles is
// valid: it pins recipes before any corpus has been published.
func ReadLock(path string) (*Lock, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var lock Lock
	if err := DecodeStrict(data, &lock); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if lock.Schema != LockSchema {
		return nil, fmt.Errorf("%s: schema %d, want %d", path, lock.Schema, LockSchema)
	}
	if !ValidDigest(lock.RecipesSHA256) {
		return nil, fmt.Errorf("%s: recipesSHA256 is not a SHA-256", path)
	}
	for key, bundle := range lock.Bundles {
		if bundle.Asset == "" || !ValidDigest(bundle.SHA256) || bundle.Bytes <= 0 {
			return nil, fmt.Errorf("%s: bundle %s is incomplete", path, key)
		}
	}
	if len(lock.Bundles) > 0 && lock.Release == "" {
		return nil, fmt.Errorf("%s: bundles are pinned without a release", path)
	}
	return &lock, nil
}

// DecodeStrict decodes JSON rejecting unknown fields and trailing data, so a
// misspelled key cannot silently weaken a recipe, manifest or lock.
func DecodeStrict(data []byte, v any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(v); err != nil {
		return err
	}
	if decoder.More() {
		return fmt.Errorf("trailing data after JSON value")
	}
	return nil
}
