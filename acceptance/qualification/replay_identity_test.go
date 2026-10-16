package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestNativeAndGoAssertionIdentitiesIncludeTheSameLibrarySources(t *testing.T) {
	root := replayControlModule(t, "valid")
	python, err := exec.LookPath("python3")
	if err != nil {
		python, err = exec.LookPath("python")
	}
	if err != nil {
		t.Fatal("native evidence compatibility requires Python", err)
	}
	repository, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"", "source_test.go", "block/reader_test.go"} {
		if name != "" {
			writeControl(t, root, name, "package control\n// Library assertions.\n")
		}
		production, assertions, err := sourceIdentities(context.Background(), root)
		if err != nil {
			t.Fatal(err)
		}
		command := exec.Command(python, "-c", "import json,sys; sys.path.insert(0,'acceptance/native'); import qualification; print(json.dumps(qualification.source_identities(sys.argv[1])))", root)
		command.Dir = repository
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("native source identity: %v\n%s", err, output)
		}
		var native []string
		if err = json.Unmarshal(output, &native); err != nil || len(native) != 2 || native[0] != production || native[1] != assertions {
			t.Fatalf("Go/native assertion identities diverged for %s: %v %v", name, native, err)
		}
	}
}

func TestLibraryUnitChangesInvalidateAssertionIdentity(t *testing.T) {
	for _, name := range []string{"source_test.go", "block/reader_test.go"} {
		t.Run(name, func(t *testing.T) {
			root := replayControlModule(t, "valid")
			beforeProduction, beforeAssertions, err := sourceIdentities(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			writeControl(t, root, name, "package control\n// New library assertion.\n")
			afterProduction, afterAssertions, err := sourceIdentities(context.Background(), root)
			if err != nil {
				t.Fatal(err)
			}
			if beforeProduction != afterProduction || beforeAssertions == afterAssertions {
				t.Fatal("library assertion did not invalidate test evidence independently of production")
			}
		})
	}
}

func TestChangingLibraryAssertionsDuringReplayCannotPublishEvidence(t *testing.T) {
	root := replayControlModule(t, "mutated-code")
	name := filepath.Join(root, "source_test.go")
	writeControl(t, root, "source_test.go", "package control\n")
	// The synthetic acceptance command changes this ordinary library test file
	// after its assertions pass. The production package remains unchanged.
	t.Setenv("UNIT_CODE", name)
	production, _, err := sourceIdentities(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	err = runReplay(context.Background(), replayOptions{root: root, registry: "acceptance/qualification/registry.json", catalog: "acceptance/qualification/corpus.json", directory: "artifacts/qualification", args: []string{"-timeout", "1m", "./acceptance", "-run", "^TestReference$"}}, &output)
	if err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("changed library assertion published execution evidence: %v\n%s", err, output.String())
	}
	after, _, err := sourceIdentities(context.Background(), root)
	if err != nil || production != after {
		t.Fatal("control unexpectedly changed production", err)
	}
	paths, err := filepath.Glob(filepath.Join(root, "artifacts/qualification/replay-*/receipt.json"))
	if err != nil || len(paths) != 0 {
		t.Fatal("a changed assertion source received a successful receipt", err)
	}
	changed, err := os.ReadFile(name)
	if err != nil || !strings.Contains(string(changed), "const Value=2") {
		t.Fatal("control did not change the library assertion source", err)
	}
}
