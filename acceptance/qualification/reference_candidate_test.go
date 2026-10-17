package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCaptureDependencyIdentityIgnoresProductionButTracksNativeHelpersAndRecipes(t *testing.T) {
	root := replayControlModule(t, "valid")
	writeControl(t, root, "acceptance/native/control.py", "# bounded collector control\n")
	writeControl(t, root, "acceptance/qualification/control.go", "package main\n")
	writeControl(t, root, "internal/qualification/control.go", "package control\n")
	writeControl(t, root, ".github/workflows/native.yml", "name: capture control\n")
	writeControl(t, root, "filesystem.go", "package filesystem\nconst Value=1\n")
	recipes := replayContract{Schema: 1, Tests: []replayTest{{Test: "TestControl", Input: "files", Manifest: "macos-*/manifest.json", CaptureContract: "native-control"}}}
	initial, err := captureContract(context.Background(), root, recipes)
	if err != nil {
		t.Fatal(err)
	}
	writeControl(t, root, "filesystem.go", "package filesystem\nconst Value=2\n")
	unchanged, err := captureContract(context.Background(), root, recipes)
	if err != nil || unchanged != initial {
		t.Fatal("independent capture inherited a Go implementation dependency", err)
	}
	writeControl(t, root, "acceptance/native/control.py", "# changed collector control\n")
	changed, err := captureContract(context.Background(), root, recipes)
	if err != nil || changed == initial {
		t.Fatal("collector change did not invalidate native capture", err)
	}
	recipes.Tests[0].CaptureContract = "other-native-control"
	other, err := captureContract(context.Background(), root, recipes)
	if err != nil || other == changed {
		t.Fatal("capture recipe change did not invalidate native capture", err)
	}
	writeControl(t, root, "scripts/unknown-helper.sh", "# new unclassified collector dependency\n")
	unknown, err := captureContract(context.Background(), root, recipes)
	if err != nil || unknown == other {
		t.Fatal("unclassified dependency did not force full native recapture", err)
	}
}

func TestCandidatePreparationRejectsMissingUnknownAndCurrentGoInputsBeforeCreatingOutput(t *testing.T) {
	for _, entry := range []string{"", "unknown-input", "hfs-header-growth"} {
		t.Run(entry, func(t *testing.T) {
			root, err := filepath.Abs("../..")
			if err != nil {
				t.Fatal(err)
			}
			temporary := t.TempDir()
			input := `{"schema":1,"inputs":[]}`
			if entry != "" {
				input = `{"schema":1,"inputs":[{"id":"` + entry + `","path":"` + filepath.ToSlash(temporary) + `"}]}`
			}
			writeControl(t, temporary, "inputs.json", input)
			output := filepath.Join(temporary, "candidate")
			err = prepareReferences(context.Background(), root, "acceptance/qualification/registry.json", filepath.Join(temporary, "inputs.json"), output)
			if err == nil || !strings.Contains(err.Error(), "capture") {
				t.Fatal("invalid independent reference inventory admitted", err)
			}
			if _, err = os.Lstat(output); !os.IsNotExist(err) {
				t.Fatal("invalid reference inventory created partial output", err)
			}
		})
	}
}
