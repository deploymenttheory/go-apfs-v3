package main

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
)

func TestRepositoryCorpusContract(t *testing.T) {
	if err := corpusWork(context.Background(), "../..", "acceptance/qualification/registry.json", corpusAction{catalog: "acceptance/qualification/corpus.json"}, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapRefusesIgnoredLocalEvidence(t *testing.T) {
	root := t.TempDir()
	command := exec.Command("git", "init", "--quiet", root)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %s: %v", output, err)
	}
	if err := cleanNativeCheckout(context.Background(), root); err != nil {
		t.Fatal(err)
	}
	writeControl(t, root, ".gitignore", "*.diagnostics.json\n")
	writeControl(t, root, "acceptance/testdata/native/macos-27.diagnostics.json", "local observation, not approved evidence")
	if err := cleanNativeCheckout(context.Background(), root); err == nil {
		t.Fatal("ignored local evidence admitted to bootstrap")
	}
	if _, err := os.Stat(filepath.Join(root, "acceptance/testdata/native/macos-27.diagnostics.json")); err != nil {
		t.Fatal("bootstrap changed local evidence", err)
	}
}

func TestCatalogPreparationCannotReplaceAnApprovedFile(t *testing.T) {
	file := filepath.Join(t.TempDir(), "catalog.json")
	if err := os.WriteFile(file, []byte("approved original bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeNewCatalog(file, corpus.Catalog{Schema: 1}); !errors.Is(err, os.ErrExist) {
		t.Fatal("candidate replaced approved catalog", err)
	}
	actual, err := os.ReadFile(file)
	if err != nil || string(actual) != "approved original bytes" {
		t.Fatal(string(actual), err)
	}
}
