package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeControl(t *testing.T, root, path, value string) {
	t.Helper()
	path = filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
}

func digest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func controlRegistry(t *testing.T) (string, registry) {
	t.Helper()
	root := t.TempDir()
	testPath := "acceptance/control_test.go"
	source := "package control\nimport \"testing\"\nfunc TestEvidence(t *testing.T) {}\n"
	writeControl(t, root, testPath, source)
	wfPath := ".github/workflows/check.yml"
	wf := "name: Checks\njobs:\n  checks:\n    runs-on: ubuntu-24.04\n"
	writeControl(t, root, wfPath, wf)
	mp := "acceptance/testdata/control/macos-27/manifest.json"
	m := `{"cases":[{"id":"native"}]}`
	writeControl(t, root, mp, m)
	r := registry{
		Schema:      1,
		TestSources: []sourceFile{{testPath, digest(source)}},
		Families: []family{{
			ID: "evidence", Purpose: "Reject lost evidence", Expectation: "Original observations",
			Tests:        []entrypoint{{"TestEvidence", testPath}},
			CaptureClass: "harness-control", CaptureReason: "Ordinary file control",
			PortableHosts: []string{"linux", "windows", "darwin"}, Race: "Linux retained controls",
			Corpora: []string{"acceptance/testdata/control"}, Checks: []string{"Original bytes"},
			RetainedSources: []int{27},
			Execution:       []execution{{wfPath, []string{"checks"}, "All retained controls"}},
		}},
		Workflows: []workflow{{wfPath, digest(wf), []string{"checks"}}},
		Manifests: []manifest{{mp, digest(m), []string{"cases/native"}}},
	}
	return root, r
}

func TestAuditRejectsCoverageLoss(t *testing.T) {
	for _, kind := range []string{"valid", "new-test", "missing-test", "duplicate-test", "new-skip", "early-return", "changed-workflow", "lost-job", "missing-manifest", "changed-case", "new-manifest", "new-corpus", "lost-source", "lost-host", "lost-explanation", "lost-case-index"} {
		t.Run(kind, func(t *testing.T) {
			root, r := controlRegistry(t)
			switch kind {
			case "new-test":
				writeControl(t, root, "acceptance/new_test.go", "package control\nimport \"testing\"\nfunc TestNew(t *testing.T) {}\n")
			case "missing-test":
				r.Families[0].Tests[0].Name = "TestAbsent"
			case "duplicate-test":
				r.Families[0].Tests = append(r.Families[0].Tests, r.Families[0].Tests[0])
			case "new-skip":
				writeControl(t, root, "acceptance/helper_test.go", "package control\nimport \"testing\"\nfunc helper(t *testing.T) { t.Run(\"nested\", func(t *testing.T) { t.Skip(\"missing\") }) }\n")
			case "early-return":
				writeControl(t, root, "acceptance/control_test.go", "package control\nimport \"testing\"\nfunc TestEvidence(t *testing.T) { if true { return } }\n")
			case "changed-workflow":
				writeControl(t, root, r.Workflows[0].Path, "name: Checks\njobs:\n  checks:\n    if: false\n")
			case "lost-job":
				r.Families[0].Execution[0].Jobs = []string{"absent"}
			case "missing-manifest":
				if err := os.Remove(filepath.Join(root, r.Manifests[0].Path)); err != nil {
					t.Fatal(err)
				}
			case "changed-case":
				writeControl(t, root, r.Manifests[0].Path, `{"cases":[{"id":"different"}]}`)
			case "new-manifest":
				writeControl(t, root, "acceptance/testdata/control/macos-15/manifest.json", `{"cases":[{"id":"new"}]}`)
			case "new-corpus":
				writeControl(t, root, "acceptance/testdata/new/macos-27/manifest.json", `{"cases":[{"id":"new"}]}`)
			case "lost-source":
				r.Families[0].RetainedSources = nil
			case "lost-host":
				r.Families[0].PortableHosts = []string{"linux"}
			case "lost-explanation":
				r.Families[0].Purpose = ""
			case "lost-case-index":
				r.Manifests[0].Cases = nil
			}
			actual, err := inspectTests(root)
			if err != nil {
				t.Fatal(err)
			}
			if kind == "new-skip" || kind == "early-return" {
				// Even a reviewed source-digest update cannot admit a new
				// skip/return without its separate explanation.
				paths, err := testPaths(root)
				if err != nil {
					t.Fatal(err)
				}
				r.TestSources = nil
				for _, path := range paths {
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					rel, err := filepath.Rel(root, path)
					if err != nil {
						t.Fatal(err)
					}
					r.TestSources = append(r.TestSources, sourceFile{filepath.ToSlash(rel), digest(string(data))})
				}
			}
			err = audit(root, r, actual)
			if (err == nil) != (kind == "valid") {
				t.Fatalf("coverage admission for %s: %v", kind, err)
			}
		})
	}
}

func TestSyntaxInventoryIgnoresCommentsAndTracksGuards(t *testing.T) {
	root := t.TempDir()
	writeControl(t, root, "acceptance/control_test.go", `package control
import "testing"
// func TestComment(t *testing.T) { t.Skip("comment") }
func TestEvidence(t *testing.T) {
 if missing { return }
 t.Run("real", func(t *testing.T) { t.Skip("real"); return })
}
`)
	i, err := inspectTests(root)
	if err != nil || len(i.Entrypoints) != 1 || len(i.Exits) != 2 {
		t.Fatal(i, err)
	}
	encoded, err := json.Marshal(i)
	if err != nil || !strings.Contains(string(encoded), "return when missing") || strings.Contains(string(encoded), "comment") {
		t.Fatal(string(encoded), err)
	}
}

func TestRepositoryCoverageContract(t *testing.T) {
	if err := run("../..", "acceptance/qualification/registry.json", false, os.Stdout); err != nil {
		t.Fatal(err)
	}
}
