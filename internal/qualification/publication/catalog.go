// Package publication binds reviewed native reference releases to immutable
// corpus bytes. It never grants filesystem or execution verdicts from a tag.
package publication

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
)

const Schema = 1

// Asset pins both GitHub's numeric object and the complete returned bytes.
// Replacing a release asset under the same filename cannot preserve this pin.
type Asset struct {
	ID     int64  `json:"id"`
	Name   string `json:"name"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`
}

type Pin struct {
	Schema     int    `json:"schema"`
	Repository string `json:"repository"`
	ReleaseID  int64  `json:"release_id"`
	Catalog    Asset  `json:"catalog"`
}

type Origin struct {
	Repository string    `json:"repository"`
	Revision   string    `json:"revision"`
	Run        string    `json:"run"`
	Attempt    string    `json:"attempt"`
	Completed  time.Time `json:"completed_at"`
}

// Manifest is prepared only after candidate qualification. The nested corpus
// identities exclude release IDs and result receipts. Its evidence asset keeps
// original plans/events/receipts available after Actions artifacts expire.
type Manifest struct {
	Schema          int            `json:"schema"`
	CaptureContract string         `json:"capture_contract_sha256"`
	Origin          Origin         `json:"origin"`
	Corpus          corpus.Catalog `json:"corpus"`
	Assets          []Asset        `json:"assets"`
	Evidence        Asset          `json:"qualification_evidence"`
}

var repository = regexp.MustCompile(`^[A-Za-z0-9_-][A-Za-z0-9_.-]*/[A-Za-z0-9_-][A-Za-z0-9_.-]*$`)
var revision = regexp.MustCompile(`^(?:[a-f0-9]{40}|[a-f0-9]{64})$`)
var run = regexp.MustCompile(`^[1-9][0-9]*$`)

func (o Origin) Validate() error {
	if !repository.MatchString(o.Repository) || !revision.MatchString(o.Revision) || !run.MatchString(o.Run) || !run.MatchString(o.Attempt) || o.Completed.IsZero() || o.Completed.Format("-0700") != "+0000" {
		return errors.New("native reference provenance missing/invalid")
	}
	return nil
}

func validAsset(a Asset, prefix, suffix string, maximum int64) bool {
	return a.ID > 0 && corpus.ValidDigest(a.SHA256) && a.Bytes > 0 && a.Bytes <= maximum && a.Name == prefix+a.SHA256+suffix
}

func (p Pin) Validate() error {
	if p.Schema != Schema || !repository.MatchString(p.Repository) || p.ReleaseID <= 0 || !validAsset(p.Catalog, "catalog-sha256-", ".json", corpus.MaxCatalogBytes) {
		return errors.New("invalid reviewed native reference release pin")
	}
	return nil
}

func (m Manifest) Validate(original corpus.Catalog, required []Requirement) error {
	if m.Schema != Schema || !corpus.ValidDigest(m.CaptureContract) || m.Origin.Validate() != nil {
		return errors.New("native reference provenance/contract missing")
	}
	if err := original.Validate(); err != nil {
		return err
	}
	if err := m.Corpus.Validate(); err != nil {
		return err
	}
	if !validAsset(m.Evidence, "qualification-sha256-", ".tar.gz", corpus.MaxBundleBytes) {
		return errors.New("permanent candidate qualification evidence missing")
	}
	if err := MatchBindings(m.Corpus, original); err != nil {
		return err
	}
	assets := map[string]Asset{}
	ids := map[int64]bool{m.Evidence.ID: true}
	previous := ""
	for _, asset := range m.Assets {
		if !validAsset(asset, "sha256-", ".tar.gz", corpus.MaxBundleBytes) || asset.Name <= previous || ids[asset.ID] {
			return errors.New("invalid/duplicate native reference asset")
		}
		previous = asset.Name
		assets[asset.Name] = asset
		ids[asset.ID] = true
	}
	used := map[string]bool{}
	for _, entry := range m.Corpus.Entries {
		dependent := slices.ContainsFunc(entry.Bindings, func(b corpus.Binding) bool { return b.CaptureClass == "current-go-experiment" })
		if dependent {
			// Historical controls stay historical. Every implementation still needs
			// the separate current-revision native experiment; publication cannot
			// convert it into an independently captured reference.
			continue
		}
		if entry.Location.Kind != "bundle" {
			return fmt.Errorf("independent references require permanent pinned transport: %s", entry.ID)
		}
		bundle := entry.Location.Bundle
		asset, ok := assets[bundle.Filename()]
		if !ok || asset.SHA256 != bundle.SHA256 || asset.Bytes != bundle.Bytes {
			return fmt.Errorf("missing/mismatched corpus asset: %s", entry.ID)
		}
		used[asset.Name] = true
	}
	if len(used) != len(assets) {
		return errors.New("unreferenced native corpus assets")
	}
	return MatchCoverage(m.Corpus, required)
}

// MatchBindings applies before qualification as well as publication. Available
// candidate files cannot remove a capability or relabel a current-Go experiment
// as independently captured input.
func MatchBindings(candidate, original corpus.Catalog) error {
	if len(candidate.Entries) != len(original.Entries) {
		return errors.New("candidate corpus coverage differs from the reviewed inventory")
	}
	for i, entry := range candidate.Entries {
		retained := original.Entries[i]
		if entry.ID != retained.ID || !reflect.DeepEqual(entry.Bindings, retained.Bindings) {
			return fmt.Errorf("candidate capability binding changed: %s", entry.ID)
		}
		if slices.ContainsFunc(entry.Bindings, func(b corpus.Binding) bool { return b.CaptureClass == "current-go-experiment" }) && !reflect.DeepEqual(entry, retained) {
			return fmt.Errorf("current-Go experiment cannot be promoted as independent evidence: %s", entry.ID)
		}
	}
	return nil
}

// ReadManifest verifies the approved bytes before decoding any release content.
// A correct GitHub object ID alone is insufficient evidence of identity.
func ReadManifest(input io.Reader, pin Pin, original corpus.Catalog, required []Requirement) (Manifest, error) {
	var m Manifest
	if err := pin.Validate(); err != nil {
		return m, err
	}
	data, err := io.ReadAll(io.LimitReader(input, pin.Catalog.Bytes+1))
	if err != nil {
		return m, err
	}
	if int64(len(data)) != pin.Catalog.Bytes {
		return m, errors.New("native catalog asset size differs")
	}
	if err = corpus.StrictJSON(data, &m); err != nil {
		return m, err
	}
	// File hashing shares the repository's canonical digest convention.
	sum := digestBytes(data)
	if sum != pin.Catalog.SHA256 {
		return m, errors.New("native catalog asset digest differs")
	}
	if m.Origin.Repository != pin.Repository {
		return m, errors.New("native catalog belongs to another repository")
	}
	return m, m.Validate(original, required)
}

func ReadPin(input io.Reader) (Pin, error) {
	var p Pin
	data, err := io.ReadAll(io.LimitReader(input, (64<<10)+1))
	if err != nil {
		return p, err
	}
	if len(data) > 64<<10 {
		return p, errors.New("native release pin exceeds bound")
	}
	if err = corpus.StrictJSON(data, &p); err != nil {
		return p, err
	}
	return p, p.Validate()
}

func Encode(m Manifest) ([]byte, error) {
	var output bytes.Buffer
	encoder := json.NewEncoder(&output)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(m); err != nil {
		return nil, err
	}
	if output.Len() > corpus.MaxCatalogBytes {
		return nil, errors.New("native catalog exceeds size bound")
	}
	return output.Bytes(), nil
}

func SameFiles(a, b corpus.Entry) bool {
	return reflect.DeepEqual(a.Files, b.Files) && reflect.DeepEqual(a.Captures, b.Captures)
}

func AssetOrder(assets []Asset) {
	slices.SortFunc(assets, func(a, b Asset) int { return strings.Compare(a.Name, b.Name) })
}
