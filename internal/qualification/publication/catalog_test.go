package publication

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
)

func publicationControl(t *testing.T) (Manifest, Pin, corpus.Catalog, []byte) {
	t.Helper()
	root := t.TempDir()
	document := []byte(`{"schema":1,"scenario":"plain-harness-control","producer":{"system":"macOS","version":"27.0","build":"synthetic","architecture":"synthetic"},"cases":[{"id":"plain-control"}]}`)
	write := func(name string) {
		t.Helper()
		target := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, document, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("references/files/manifest.json")
	write("references/current-go/manifest.json")
	definitions := []corpus.Definition{}
	for _, id := range []string{"current-go", "files"} {
		class := "apple-independent"
		if id == "current-go" {
			class = "current-go-experiment"
		}
		definitions = append(definitions, corpus.Definition{ID: id, Path: "references/" + id, Bindings: []corpus.Binding{{Family: id, CaptureClass: class}}, Manifests: []corpus.ManifestReference{{Path: "manifest.json", SHA256: digestBytes(document), Cases: []string{"cases/plain-control"}}}})
	}
	original, err := corpus.Build(context.Background(), root, definitions)
	if err != nil {
		t.Fatal(err)
	}
	candidate := original
	candidate.Entries = append([]corpus.Entry(nil), original.Entries...)
	bundle := corpus.Bundle{SHA256: strings.Repeat("a", 64), Bytes: 128}
	candidate.Entries[1].Location = corpus.Location{Kind: "bundle", Bundle: &bundle}
	manifest := Manifest{Schema: Schema, CaptureContract: strings.Repeat("b", 64), Origin: Origin{Repository: "owner/filesystems", Revision: strings.Repeat("c", 40), Run: "123", Attempt: "1", Completed: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)}, Corpus: candidate, Assets: []Asset{{ID: 10, Name: bundle.Filename(), Bytes: bundle.Bytes, SHA256: bundle.SHA256}}, Evidence: Asset{ID: 20, Name: "qualification-sha256-" + strings.Repeat("d", 64) + ".tar.gz", Bytes: 256, SHA256: strings.Repeat("d", 64)}}
	data, err := Encode(manifest)
	if err != nil {
		t.Fatal(err)
	}
	sum := digestBytes(data)
	pin := Pin{Schema: 1, Repository: manifest.Origin.Repository, ReleaseID: 30, Catalog: Asset{ID: 40, Name: "catalog-sha256-" + sum + ".json", Bytes: int64(len(data)), SHA256: sum}}
	return manifest, pin, original, data
}

func TestReviewedReleasePinBindsCatalogBytesAndHistoricalCurrentGoControls(t *testing.T) {
	manifest, pin, original, data := publicationControl(t)
	if err := manifest.Validate(original, publicationRequirements()); err != nil {
		t.Fatal(err)
	}
	decoded, err := ReadManifest(bytes.NewReader(data), pin, original, publicationRequirements())
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Corpus.Entries[0].TreeSHA256 != original.Entries[0].TreeSHA256 {
		t.Fatal("historical matched experiment changed identity")
	}
	if decoded.Corpus.Entries[1].TreeSHA256 != original.Entries[1].TreeSHA256 {
		t.Fatal("transport changed independent input identity")
	}
	raw, err := json.Marshal(pin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = ReadPin(bytes.NewReader(raw)); err != nil {
		t.Fatal(err)
	}
	for _, altered := range [][]byte{append(append([]byte{}, data...), byte(' ')), bytes.Replace(data, []byte("plain-control"), []byte("other-control"), 1)} {
		if _, err := ReadManifest(bytes.NewReader(altered), pin, original, publicationRequirements()); err == nil {
			t.Fatal("unreviewed catalog bytes admitted")
		}
	}
}

func TestNativePublicationRejectsChangedBindingsMissingAssetsAndPromotedGoExperiments(t *testing.T) {
	originalManifest, _, original, _ := publicationControl(t)
	mutations := []struct {
		name   string
		change func(*Manifest)
	}{
		{"missing-corpus", func(m *Manifest) { m.Corpus.Entries = m.Corpus.Entries[:1] }},
		{"missing-asset", func(m *Manifest) { m.Assets = nil }},
		{"wrong-asset-size", func(m *Manifest) { m.Assets[0].Bytes++ }},
		{"duplicate-asset", func(m *Manifest) { m.Assets = append(m.Assets, m.Assets[0]) }},
		{"missing-evidence", func(m *Manifest) { m.Evidence = Asset{} }},
		{"go-experiment", func(m *Manifest) { m.Corpus.Entries[0].Location = m.Corpus.Entries[1].Location }},
		{"wrong-origin", func(m *Manifest) { m.Origin.Run = "unknown" }},
		{"bad-contract", func(m *Manifest) { m.CaptureContract = "missing" }},
	}
	for _, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			data, err := json.Marshal(originalManifest)
			if err != nil {
				t.Fatal(err)
			}
			var m Manifest
			if err = json.Unmarshal(data, &m); err != nil {
				t.Fatal(err)
			}
			mutation.change(&m)
			if err = m.Validate(original, publicationRequirements()); err == nil {
				t.Fatal("unsafe native reference publication admitted")
			}
		})
	}
}

func TestNativeReferencePinsRejectAmbiguousOrUnboundedTransport(t *testing.T) {
	_, pin, _, _ := publicationControl(t)
	for _, mutation := range []func(*Pin){func(p *Pin) { p.Repository = "../other" }, func(p *Pin) { p.ReleaseID = 0 }, func(p *Pin) { p.Catalog.ID = 0 }, func(p *Pin) { p.Catalog.Name = "latest.json" }, func(p *Pin) { p.Catalog.Bytes = corpus.MaxCatalogBytes + 1 }, func(p *Pin) { p.Catalog.SHA256 = "wrong" }} {
		changed := pin
		mutation(&changed)
		if err := changed.Validate(); err == nil {
			t.Fatal("invalid release pin accepted")
		}
	}
	if _, err := ReadPin(strings.NewReader(`{"schema":1,"schema":1}`)); err == nil {
		t.Fatal("duplicate pin field accepted")
	}
}

func publicationRequirements() []Requirement {
	return []Requirement{{ID: "files", Manifest: "manifest.json", Contract: "plain-harness-control", Cases: map[int][]string{27: {"cases/plain-control"}}}}
}

func TestNativePublicationCannotLoseSourceVersionsCasesOrContractMeaning(t *testing.T) {
	manifest, _, _, _ := publicationControl(t)
	required := publicationRequirements()
	required[0].Cases[15] = []string{"cases/plain-control"}
	if err := MatchCoverage(manifest.Corpus, required); err == nil {
		t.Fatal("missing native source version admitted")
	}
	required = publicationRequirements()
	required[0].Cases[27] = append(required[0].Cases[27], "cases/missing-control")
	if err := MatchCoverage(manifest.Corpus, required); err == nil {
		t.Fatal("missing native source case admitted")
	}
	required = publicationRequirements()
	required[0].Contract = "different-native-contract"
	if err := MatchCoverage(manifest.Corpus, required); err == nil {
		t.Fatal("native semantic contract substituted")
	}
	if err := MatchCoverage(manifest.Corpus, nil); err == nil {
		t.Fatal("available inputs chose their own coverage")
	}
}
