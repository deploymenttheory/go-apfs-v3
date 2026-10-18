package fixture

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestManifestAndBundleRoundTrip(t *testing.T) {
	dir := t.TempDir()
	caseDir := filepath.Join(dir, "file-corpus")
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	obs := schema.Observation{Schema: 1, Recipe: "file-corpus", Profile: "apfs", Stage: "final"}
	data, _ := json.Marshal(obs)
	if err := os.WriteFile(filepath.Join(caseDir, "apfs.final.observation.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "apfs.final.dmg"), []byte("image"), 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, err := WriteManifest(dir, schema.Producer{Major: 27}, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Cases) != 1 || len(manifest.Cases[0].Files) != 2 {
		t.Fatalf("unexpected manifest %+v", manifest)
	}
	out := t.TempDir()
	path, sum, size, err := WriteBundle(dir, 27, out)
	if err != nil {
		t.Fatal(err)
	}
	if size == 0 || len(sum) != 64 || filepath.Base(path) != "fixtures-macos-27-"+sum[:16]+".tar.gz" {
		t.Fatalf("bundle %s %s %d", path, sum, size)
	}
	again, sum2, _, err := WriteBundle(dir, 27, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if sum2 != sum {
		t.Fatalf("bundle is not deterministic: %s vs %s (%s)", sum, sum2, again)
	}
	extracted := t.TempDir()
	if err := ExtractBundle(path, extracted, 1<<20); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(extracted, "manifest.json")); err != nil {
		t.Fatal(err)
	}
	if err := ExtractBundle(path, t.TempDir(), 10); err == nil {
		t.Fatal("size bound not enforced")
	}
}
