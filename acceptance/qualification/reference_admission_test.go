package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/publication"
)

func TestReviewedReferencesAdmitNewSourcesWithoutRewritingRetainedEvidence(t *testing.T) {
	ctx := context.Background()
	root := replayControlModule(t, "valid")
	writeControl(t, root, "internal/qualification/control.go", "package control\n")
	writeControl(t, root, ".github/workflows/native.yml", "name: native control\n")
	writeControl(t, root, ".gitignore", "fresh/\nartifacts/\n")
	input, err := os.Open(filepath.Join(root, "acceptance/qualification/corpus.json"))
	if err != nil {
		t.Fatal(err)
	}
	original, err := corpus.Read(input)
	if closeErr := input.Close(); err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	var r registry
	data, err := os.ReadFile(filepath.Join(root, "acceptance/qualification/registry.json"))
	if err != nil || json.Unmarshal(data, &r) != nil {
		t.Fatal("read synthetic registry", err)
	}
	r.Families[0].PortableHosts = []string{"darwin", "linux", "windows"}
	r.Families[0].NativeMajors = []int{15, 26, 27}
	registryData, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	writeControl(t, root, "acceptance/qualification/registry.json", string(registryData))
	recipes, err := readReplayContract(root, r)
	if err != nil {
		t.Fatal(err)
	}
	recipes.Tests[0].FreshRaceHosts = []string{"linux"}
	recipes.Tests[0].NativeScope = "matching-source"
	recipeData, err := json.Marshal(recipes)
	if err != nil {
		t.Fatal(err)
	}
	writeControl(t, root, "acceptance/qualification/replay.json", string(recipeData))
	contract, err := captureContract(ctx, root, recipes)
	if err != nil {
		t.Fatal(err)
	}
	// The historical reference has only source 15. Publication must add both
	// other source versions with the same independently reviewed case recipe.
	for _, major := range []string{"15", "26", "27"} {
		writeControl(t, root, "fresh/macos-"+major+"/manifest.json", `{"schema":1,"scenario":"unit-control","producer":{"system":"macOS","version":"`+major+`.0","build":"fresh-control","architecture":"synthetic"},"cases":[{"id":"apfs"}]}`)
	}
	candidate, err := corpus.InspectCapture(ctx, root, corpus.Definition{ID: "apfs-geometry", Path: "fresh", Bindings: original.Entries[0].Bindings})
	if err != nil {
		t.Fatal(err)
	}
	bundles := t.TempDir()
	resolver, err := corpus.New(candidate, corpus.Options{Repository: root})
	if err != nil {
		t.Fatal(err)
	}
	source, err := resolver.Resolve(ctx, "apfs-geometry")
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := corpus.WriteBundle(ctx, source, bundles)
	if closeErr := source.Close(); err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	candidate.Entries[0].Location = corpus.Location{Kind: "bundle", Bundle: &bundle}
	evidence := "original qualification evidence control"
	manifest := publication.Manifest{Schema: 1, CaptureContract: contract,
		Origin: publication.Origin{Repository: "owner/filesystems", Revision: strings.Repeat("a", 40), Run: "123", Attempt: "1", Completed: time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)},
		Corpus: candidate, Assets: []publication.Asset{{ID: 10, Name: bundle.Filename(), Bytes: bundle.Bytes, SHA256: bundle.SHA256}},
		Evidence: publication.Asset{ID: 20, Name: "qualification-sha256-" + digest(evidence) + ".tar.gz", Bytes: int64(len(evidence)), SHA256: digest(evidence)}}
	writeControl(t, bundles, manifest.Evidence.Name, evidence)
	if err = newJSON(filepath.Join(bundles, "candidate.json"), preparedReferences{Schema: 1, CaptureContract: contract, Corpus: candidate, Bundles: []corpus.Bundle{bundle}}); err != nil {
		t.Fatal(err)
	}
	want, err := planReferenceObligations(ctx, root, "acceptance/qualification/registry.json", bundles)
	if err != nil || len(want.Cases) != 27 || len(want.Projections) != 0 {
		t.Fatal("complete source/host/format obligation set missing", len(want.Cases), err)
	}
	for _, obligation := range want.Cases {
		if obligation.Race != (obligation.Host == "linux") || obligation.ManifestSHA256 == "" || len(obligation.NativeMajors) != 1 || obligation.NativeMajors[0] != obligation.Case.Source {
			t.Fatal("original input or instrumentation obligation lost", obligation)
		}
	}
	data, err = publication.Encode(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pin := publication.Pin{Schema: 1, Repository: "owner/filesystems", ReleaseID: 30, Catalog: publication.Asset{ID: 40, Name: "catalog-sha256-" + digest(string(data)) + ".json", Bytes: int64(len(data)), SHA256: digest(string(data))}}
	writeControl(t, bundles, pin.Catalog.Name, string(data))
	pinData, err := json.Marshal(pin)
	if err != nil {
		t.Fatal(err)
	}
	writeControl(t, root, "acceptance/qualification/references.json", string(pinData))
	checked, err := checkedReferenceCatalog(ctx, root, "acceptance/qualification/registry.json", "acceptance/qualification/references.json", bundles)
	if err != nil {
		t.Fatal("complete pinned asset admission failed", err)
	}
	sources, err := referenceSourceIdentities(checked)
	if err != nil || len(sources) != 3 {
		t.Fatal("verified reference source versions are incomplete", err)
	}
	for position, major := range []int{15, 26, 27} {
		expected, err := referenceSourceIdentity(candidate.Entries[0], major)
		if err != nil || sources[position].ID != "apfs-geometry" || sources[position].Major != major || sources[position].Class != "apple-independent" || sources[position].Identity != expected {
			t.Fatal("reference identities differ from the actual verified source files", major, err)
		}
	}
	admitted, err := admitReplayInputs(ctx, root, "acceptance/qualification/corpus.json", bundles, "acceptance/qualification/references.json", r, recipes, recipes.Tests)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = admitted.close() }()
	if admitted.entries["apfs-geometry"].TreeSHA256 == original.Entries[0].TreeSHA256 || len(admitted.entries["apfs-geometry"].Captures) != 3 {
		t.Fatal("reviewed fresh references were replaced by old retained inputs")
	}
	if err = admitted.resolved["apfs-geometry"].Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if original.Entries[0].Location.Kind != "committed" || len(original.Entries[0].Captures) != 1 {
		t.Fatal("original retained evidence changed")
	}
	materialized := filepath.Join(t.TempDir(), "native-inputs")
	if err = materializeReferences(ctx, root, "acceptance/qualification/registry.json", "acceptance/qualification/references.json", bundles, "apfs-geometry", materialized); err != nil {
		t.Fatal("ordinary reference materialization", err)
	}
	materializedBytes, err := os.ReadFile(filepath.Join(materialized, "apfs-geometry/macos-15/manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	originalBytes, err := os.ReadFile(filepath.Join(root, "fresh/macos-15/manifest.json"))
	if err != nil || string(materializedBytes) != string(originalBytes) {
		t.Fatal("reference materialization changed original bytes", err)
	}
	if err = materializeReferences(ctx, root, "acceptance/qualification/registry.json", "acceptance/qualification/references.json", bundles, "apfs-geometry", filepath.Join(root, "new-scratch")); err == nil {
		t.Fatal("reference materialization wrote into source checkout")
	}
	t.Setenv("APFS_NATIVE_APFS_GEOMETRY", filepath.Join(root, "fresh"))
	matching, err := admitReplayInputs(ctx, root, "acceptance/qualification/corpus.json", bundles, "acceptance/qualification/references.json", r, recipes, recipes.Tests)
	if err != nil {
		t.Fatal("byte-identical materialized reference refused", err)
	}
	if err = matching.close(); err != nil {
		t.Fatal(err)
	}
	writeControl(t, root, "fresh/unreviewed-control.txt", "another input tree with the same primary cases\n")
	if unexpected, err := admitReplayInputs(ctx, root, "acceptance/qualification/corpus.json", bundles, "acceptance/qualification/references.json", r, recipes, recipes.Tests); err == nil {
		_ = unexpected.close()
		t.Fatal("environment override silently replaced reviewed reference bytes")
	}
	t.Setenv("APFS_NATIVE_APFS_GEOMETRY", "")
	writeControl(t, bundles, manifest.Evidence.Name, "X"+evidence[1:])
	if _, err = approvedReferences(ctx, root, "acceptance/qualification/references.json", bundles, original, recipes); err == nil {
		t.Fatal("corrupt permanent qualification evidence admitted")
	}
	if err = os.Remove(filepath.Join(bundles, manifest.Evidence.Name)); err != nil {
		t.Fatal(err)
	}
	if _, err = approvedReferences(ctx, root, "acceptance/qualification/references.json", bundles, original, recipes); err == nil {
		t.Fatal("missing permanent qualification evidence admitted")
	}
	writeControl(t, bundles, manifest.Evidence.Name, evidence)
	// Collector drift and corrupt pinned transport must refuse admission,
	// including when a valid historical corpus would otherwise be available.
	writeControl(t, root, "acceptance/native/control.py", "# changed native collector\n")
	if _, err = approvedReferences(ctx, root, "acceptance/qualification/references.json", bundles, original, recipes); err == nil || !strings.Contains(err.Error(), "fresh capture") {
		t.Fatal("collector drift inherited independent capture", err)
	}
	writeControl(t, bundles, pin.Catalog.Name, string(data)+" ")
	if _, err = approvedReferences(ctx, root, "acceptance/qualification/references.json", bundles, original, recipes); err == nil {
		t.Fatal("corrupt pinned catalog silently fell back to retained evidence")
	}
}

func TestReferenceTransportPinsDoNotEnterProductionOrReplayIdentity(t *testing.T) {
	root := replayControlModule(t, "valid")
	p, c, err := sourceIdentities(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	writeControl(t, root, "acceptance/qualification/references.json", `{"transport":"changed"}`)
	newP, newC, err := sourceIdentities(context.Background(), root)
	if err != nil || p != newP || c != newC {
		t.Fatal("release transport entered production/replay contract instead of input identities", err)
	}
}
