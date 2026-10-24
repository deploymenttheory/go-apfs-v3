package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func bundleFor(t *testing.T, major int, recipesDigest string, dir string) {
	t.Helper()
	tree := t.TempDir()
	caseDir := filepath.Join(tree, "file-corpus")
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	obs := schema.Observation{Schema: 1, Recipe: "file-corpus", Profile: "apfs", Stage: "final", Image: schema.Image{File: "apfs.final.dmg"}}
	data, _ := json.Marshal(obs)
	if err := os.WriteFile(filepath.Join(caseDir, "apfs.final.observation.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "apfs.final.dmg"), []byte("image"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.WriteManifest(tree, schema.Producer{Major: major, Build: "build" + string(rune('0'+major%10))}, recipesDigest); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := fixture.WriteBundle(tree, major, dir); err != nil {
		t.Fatal(err)
	}
}

func TestLockRecordsEveryProducerAndRefusesForeignRecipes(t *testing.T) {
	recipes := filepath.Join("..", "..", "acceptance", "recipes")
	digest, err := schema.TreeDigest(recipes)
	if err != nil {
		t.Fatal(err)
	}
	bundles := t.TempDir()
	for _, major := range schema.Producers {
		bundleFor(t, major, digest, bundles)
	}
	// Archived or malformed unsupported bundles cannot enter active locking.
	if err := os.WriteFile(filepath.Join(bundles, "fixtures-macos-15-0000000000000000.tar.gz"), []byte("not an active bundle"), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "fixtures.lock.json")
	if err := lock([]string{"--recipes", recipes, "--release", "fixtures/2026.10.18-1", "--run", "https://example/run", "--bundles", bundles, "--out", out}); err != nil {
		t.Fatal(err)
	}
	l, err := schema.ReadLock(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.Bundles) != len(schema.Producers) || l.RecipesSHA256 != digest || l.Release != "fixtures/2026.10.18-1" || l.Bundles["macos-27"].Build != "build7" {
		t.Fatalf("lock %+v", l)
	}
	if _, present := l.Bundles["macos-15"]; present {
		t.Fatal("unsupported archive entered the active lock")
	}
	foreign := t.TempDir()
	bundleFor(t, 15, digest, foreign)
	bundleFor(t, 26, digest, foreign)
	bundleFor(t, 27, strings.Repeat("00", 32), foreign)
	if err := lock([]string{"--recipes", recipes, "--release", "r", "--bundles", foreign, "--out", out}); err == nil || !strings.Contains(err.Error(), "captured from recipes") {
		t.Fatalf("foreign recipes accepted: %v", err)
	}
	partial := t.TempDir()
	bundleFor(t, 27, digest, partial)
	if err := lock([]string{"--recipes", recipes, "--release", "r", "--bundles", partial, "--out", out}); err == nil || !strings.Contains(err.Error(), "no bundle for macos-26") {
		t.Fatalf("partial producer set accepted: %v", err)
	}
}
