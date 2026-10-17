package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func commitExecutionChanges(t *testing.T, root string) string {
	t.Helper()
	for _, args := range [][]string{{"add", "-A", "--", ".", ":(exclude)artifacts"}, {"-c", "user.name=Qualification control", "-c", "user.email=control@example.invalid", "commit", "--quiet", "--allow-empty", "-m", "ordinary source control"}} {
		if _, err := commandText(context.Background(), root, append([]string{"git"}, args...)...); err != nil {
			t.Fatal(err)
		}
	}
	revision, err := commandText(context.Background(), root, "git", "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	return revision
}

func TestExecutionChangeClassifierPreservesDeletedAndRenamedDependencies(t *testing.T) {
	root := replayControlModule(t, "valid")
	writeControl(t, root, "README.md", "Original documentation\n")
	writeControl(t, root, "collector.py", "original collector\n")
	before := commitExecutionChanges(t, root)
	writeControl(t, root, "README.md", "Updated documentation\n")
	commitExecutionChanges(t, root)
	changes, err := classifyExecutionChanges(context.Background(), root, before)
	if err != nil || changes.Classification != documentationChanges || len(changes.Paths) != 1 || changes.Paths[0] != "README.md" {
		t.Fatal("ordinary documentation did not classify", changes, err)
	}
	if err := os.Mkdir(filepath.Join(root, "docs"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "collector.py"), filepath.Join(root, "docs/collector.md")); err != nil {
		t.Fatal(err)
	}
	commitExecutionChanges(t, root)
	changes, err = classifyExecutionChanges(context.Background(), root, before)
	if err != nil || changes.Classification != "full" || !strings.Contains(strings.Join(changes.ExecutionReasons, "\n"), "collector.py") {
		t.Fatal("a documentation rename hid a deleted execution dependency", changes, err)
	}
	if _, err := classifyExecutionChanges(context.Background(), root, "main"); err == nil {
		t.Fatal("an ambiguous moving ref certified source classification")
	}
}

func TestExecutionChangeClassifierRequiresFullWorkForUnknownAndCapturedFiles(t *testing.T) {
	for _, path := range []string{"apfs/new.go", "go.mod", "go.sum", "new-helper.sh", "AGENTS.md", "docs/AGENTS.md", "docs/SKILL.md", "docs/qualification-evidence/README.md", "docs/captured-disk.gz", "acceptance/testdata/reference.md", "acceptance/qualification/references.json", ".github/workflows/native.yml", "release-please-config.json"} {
		t.Run(path, func(t *testing.T) {
			root := replayControlModule(t, "valid")
			before := commitExecutionChanges(t, root)
			writeControl(t, root, path, "changed input\n")
			commitExecutionChanges(t, root)
			changes, err := classifyExecutionChanges(context.Background(), root, before)
			if err != nil || changes.Classification != "full" || len(changes.ExecutionReasons) != 1 {
				t.Fatal("unknown execution dependency avoided full work", changes, err)
			}
		})
	}
}

func TestExecutionReleaseClassificationAcceptsOnlyExistingVersionLabels(t *testing.T) {
	for _, value := range []string{`{".":"1.2.3"}`, `{".":"1.2.3-rc.1+build.01"}`} {
		if !releaseLabel([]byte(value)) {
			t.Fatal("valid release version label rejected", value)
		}
	}
	for _, value := range []string{`[]`, `{".":"1.2.3",".":"2.0.0"}`, `{".":"1.2.3","other":"1.0.0"}`, `{".":null}`, `{".":"01.2.3"}`, `{".":"1.2.3-01"}`, `{".":"1.2.3-.."}`, `{".":"1.2"}`, strings.Repeat(" ", 4097)} {
		if releaseLabel([]byte(value)) {
			t.Fatal("unrecognised release input inherited execution", value)
		}
	}
	root := replayControlModule(t, "valid")
	writeControl(t, root, ".release-please-manifest.json", `{".":"1.0.0"}`)
	before := commitExecutionChanges(t, root)
	writeControl(t, root, ".release-please-manifest.json", `{".":"1.1.0"}`)
	commitExecutionChanges(t, root)
	changes, err := classifyExecutionChanges(context.Background(), root, before)
	if err != nil || changes.Classification != documentationChanges {
		t.Fatal("recognised release label did not classify", changes, err)
	}
	if err = os.Remove(filepath.Join(root, ".release-please-manifest.json")); err != nil {
		t.Fatal(err)
	}
	commitExecutionChanges(t, root)
	changes, err = classifyExecutionChanges(context.Background(), root, before)
	if err != nil || changes.Classification != "full" {
		t.Fatal("release label deletion avoided execution", changes, err)
	}
}

func TestDocumentationGitAliasesCannotInheritOrdinaryFileEvidence(t *testing.T) {
	root := replayControlModule(t, "valid")
	writeControl(t, root, "README.md", "Ordinary documentation\n")
	before := commitExecutionChanges(t, root)
	blob, err := commandText(context.Background(), root, "git", "rev-parse", "HEAD:source.go")
	if err != nil {
		t.Fatal(err)
	}
	// Write an index entry directly, so this test does not need Windows
	// privileges for creating filesystem symlinks.
	if _, err = commandText(context.Background(), root, "git", "update-index", "--cacheinfo", "120000,"+blob+",README.md"); err != nil {
		t.Fatal(err)
	}
	if _, err = commandText(context.Background(), root, "git", "-c", "user.name=Qualification control", "-c", "user.email=control@example.invalid", "commit", "--quiet", "-m", "aliased documentation control"); err != nil {
		t.Fatal(err)
	}
	changes, err := classifyExecutionChanges(context.Background(), root, before)
	if err != nil || changes.Classification != "full" || len(changes.ExecutionReasons) != 1 || !strings.Contains(changes.ExecutionReasons[0], "aliased") {
		t.Fatal("a Git symlink was classified as an ordinary documentation edit", changes, err)
	}
}

func TestDocumentationInheritanceStillRequiresOriginalCaseExecution(t *testing.T) {
	root, directory, origin := ciEvidenceControl(t)
	writeControl(t, root, "README.md", "Only documentation changed\n")
	commitExecutionChanges(t, root)
	if _, err := checkCIEvidence(context.Background(), root, directory, origin, nil); err == nil {
		t.Fatal("non-identical source inherited without an explicit projection")
	}
	origin.Projection = documentationChanges
	proof, err := checkCIEvidence(context.Background(), root, directory, origin, nil)
	if err != nil || proof.Projection == nil || proof.Projection.Classification != documentationChanges || proof.Origin != origin.Origin || len(proof.Receipts) != 1 {
		t.Fatal("documentation inheritance lost original proof or source distinction", proof, err)
	}
	// These unknown files are excluded from the Go source digest. Independent
	// Git change classification must still prevent stale execution inheritance.
	writeControl(t, root, "new-helper.sh", "unknown execution input\n")
	commitExecutionChanges(t, root)
	if _, err := checkCIEvidence(context.Background(), root, directory, origin, nil); err == nil {
		t.Fatal("an unclassified dependency inherited prior verdicts")
	}
}

func TestDocumentationNativeInheritancePreservesOriginalAppleAndGoProof(t *testing.T) {
	root, directory, origin := nativeEvidenceControl(t)
	writeControl(t, root, "docs/example.md", "Filesystem usage documentation\n")
	commitExecutionChanges(t, root)
	origin.Projection = documentationChanges
	proof, err := checkNativeEvidence(context.Background(), root, directory, origin)
	if err != nil || proof.Projection == nil || proof.Origin != origin.Origin || proof.CaseCount != 5 {
		t.Fatal("documentation inheritance lost original native evidence", proof, err)
	}
}
