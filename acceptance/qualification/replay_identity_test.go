package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

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
