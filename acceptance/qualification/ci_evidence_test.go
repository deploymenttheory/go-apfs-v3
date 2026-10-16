package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/publication"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

func ciEvidenceControl(t *testing.T) (string, string, executionEvidenceOrigin) {
	t.Helper()
	root := replayControlModule(t, "valid")
	version, err := commandText(context.Background(), root, "go", "env", "GOVERSION")
	if err != nil {
		t.Fatal(err)
	}
	writeControl(t, root, "go.mod", "module github.com/deploymenttheory/go-apfs-v3\n\ngo "+strings.TrimPrefix(version, "go")+"\n")
	if _, err = commandText(context.Background(), root, "git", "add", "go.mod"); err != nil {
		t.Fatal(err)
	}
	if _, err = commandText(context.Background(), root, "git", "-c", "user.name=Qualification control", "-c", "user.email=control@example.invalid", "commit", "--allow-empty", "-m", "actual control toolchain"); err != nil {
		t.Fatal(err)
	}
	revision, err := commandText(context.Background(), root, "git", "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	tree, err := commandText(context.Background(), root, "git", "rev-parse", "HEAD^{tree}")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_RUN_ID", "123")
	t.Setenv("GITHUB_RUN_ATTEMPT", "1")
	t.Setenv("GITHUB_JOB", "portable")
	t.Setenv("GITHUB_SHA", revision)
	var output bytes.Buffer
	err = runReplay(context.Background(), replayOptions{root: root, registry: "acceptance/qualification/registry.json", catalog: "acceptance/qualification/corpus.json", directory: "artifacts/qualification", args: []string{"-timeout", "1m", "./acceptance", "-run", "^TestReference$"}}, &output)
	if err != nil {
		t.Fatalf("original CI control failed: %v\n%s", err, output.String())
	}
	directory := t.TempDir()
	if err = os.CopyFS(filepath.Join(directory, "qualification-ci-portable-0"), os.DirFS(filepath.Join(root, "artifacts/qualification"))); err != nil {
		t.Fatal(err)
	}
	origin := executionEvidenceOrigin{Schema: 1, Workflow: "ci", Origin: publication.Origin{Repository: "owner/filesystems", Revision: revision, Run: "123", Attempt: "1", Completed: time.Now().UTC()}, Tree: tree, Artifacts: []executionEvidenceArtifact{{Name: "qualification-ci-portable-0", Job: "portable", Host: runtime.GOOS}}}
	return root, directory, origin
}

func TestCIInheritanceChecksOriginalExecutionAndRetainsReceiptDigests(t *testing.T) {
	root, directory, origin := ciEvidenceControl(t)
	proof, err := checkCIEvidence(context.Background(), root, directory, origin)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof.Receipts) != 1 || proof.CaseCount != 3 || proof.Origin != origin.Origin {
		t.Fatal("complete original execution evidence lost", proof)
	}
	data, err := os.ReadFile(filepath.Join(directory, filepath.FromSlash(proof.Receipts[0].Path)))
	if err != nil {
		t.Fatal(err)
	}
	var record receipt.Receipt
	if err = json.Unmarshal(data, &record); err != nil || record.Origin.Revision != origin.Origin.Revision {
		t.Fatal("inheritance rewrote the actual original receipt", err)
	}
	for _, kind := range []string{"tree", "attempt", "host", "missing", "duplicate"} {
		t.Run(kind, func(t *testing.T) {
			changed := origin
			changed.Artifacts = append([]executionEvidenceArtifact(nil), origin.Artifacts...)
			switch kind {
			case "tree":
				changed.Tree = strings.Repeat("a", 40)
			case "attempt":
				changed.Origin.Attempt = "2"
			case "host":
				changed.Artifacts[0].Host = "windows"
				if runtime.GOOS == "windows" {
					changed.Artifacts[0].Host = "linux"
				}
			case "missing":
				changed.Artifacts[0].Name = "qualification-ci-portable-1"
			case "duplicate":
				changed.Artifacts = append(changed.Artifacts, changed.Artifacts[0])
			}
			if _, err := checkCIEvidence(context.Background(), root, directory, changed); err == nil {
				t.Fatal("incompatible or incomplete original CI was admitted")
			}
		})
	}
	duplicate := filepath.Join(directory, "qualification-ci-portable-1")
	if err = os.CopyFS(duplicate, os.DirFS(filepath.Join(directory, "qualification-ci-portable-0"))); err != nil {
		t.Fatal(err)
	}
	duplicatedOrigin := origin
	duplicatedOrigin.Artifacts = append(append([]executionEvidenceArtifact(nil), origin.Artifacts...), executionEvidenceArtifact{Name: "qualification-ci-portable-1", Job: "portable", Host: runtime.GOOS})
	if _, err = checkCIEvidence(context.Background(), root, directory, duplicatedOrigin); err == nil {
		t.Fatal("one execution replaced a different required CI artifact")
	}
	if err = os.RemoveAll(duplicate); err != nil {
		t.Fatal(err)
	}
	eventPath := filepath.Join(directory, filepath.Dir(filepath.FromSlash(proof.Receipts[0].Path)), record.Events.Path)
	events, err := os.ReadFile(eventPath)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(eventPath, append(append([]byte(nil), events...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = checkCIEvidence(context.Background(), root, directory, origin); err == nil {
		t.Fatal("changed original event bytes inherited CI")
	}
	if err = os.WriteFile(eventPath, events, 0600); err != nil {
		t.Fatal(err)
	}
	writeControl(t, root, "library_test.go", "package control\n// Changed assertions.\n")
	if _, err = checkCIEvidence(context.Background(), root, directory, origin); err == nil {
		t.Fatal("changed library assertions inherited old CI")
	}
}
