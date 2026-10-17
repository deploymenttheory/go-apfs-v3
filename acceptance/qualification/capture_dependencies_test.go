package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestCaptureRegistryIdentitySurvivesWorkflowDigestAndExecutionMetadataRefresh(t *testing.T) {
	root := t.TempDir()
	data, err := regularFile("../..", "acceptance/qualification/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	var r registry
	if err = json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	for _, workflow := range r.Workflows {
		body, err := regularFile("../..", workflow.Path)
		if err != nil {
			t.Fatal(err)
		}
		writeControl(t, root, workflow.Path, string(body))
	}
	original, err := captureRegistryProjection(root, data)
	if err != nil {
		t.Fatal(err)
	}
	const name = ".github/workflows/native.yml"
	body, err := regularFile(root, name)
	if err != nil {
		t.Fatal(err)
	}
	replay := workflowJobSection(t, string(body), "replay")
	changed := strings.Replace(string(body), replay, strings.ReplaceAll(replay, "-parallel 2", "-parallel 1"), 1)
	if changed == string(body) {
		t.Fatal("actual replay scheduling control missing")
	}
	writeControl(t, root, name, changed)
	for index := range r.Workflows {
		if r.Workflows[index].Path == name {
			r.Workflows[index].SHA256 = digest(changed)
		}
	}
	r.TestSources[0].SHA256 = strings.Repeat("b", 64)
	r.Families[0].Execution = nil
	r.Families[0].Tests[0].File = "acceptance/renamed_assertions_test.go"
	r.Exits = nil
	updated, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := captureRegistryProjection(root, updated)
	if err != nil || actual != original {
		t.Fatal("updated workflow digest or assertion/execution metadata invalidated original Apple inputs", err)
	}
	r.Families[0].Collectors = append(r.Families[0].Collectors, "acceptance/native/new_collector.py")
	updated, err = json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	actual, err = captureRegistryProjection(root, updated)
	if err != nil || actual == original {
		t.Fatal("changed collector definition did not require fresh Apple inputs", err)
	}
}

const captureWorkflowControl = `name: Independent Apple input control
env:
  CAPTURE_BYTES: 128m
jobs:
  produce:
    runs-on: macos-26
    steps:
      - run: python3 acceptance/native/capture.py --size 128m --scenario file-reading
  replay:
    runs-on: ubuntu-24.04
    steps:
      - run: go test -count=1 -parallel 2 ./acceptance
  readback:
    runs-on: macos-26
    steps:
      - run: python3 acceptance/native/verify_preservation.py --outputs artifacts/outputs
`

func TestCaptureWorkflowIdentitySeparatesReplaySchedulingFromCaptureParameters(t *testing.T) {
	const name = ".github/workflows/native.yml"
	original, known := captureWorkflowProjection(name, []byte(captureWorkflowControl))
	if !known {
		t.Fatal("known native workflow was not projected")
	}
	for _, control := range []struct {
		name, body string
		changed    bool
	}{
		{"replay-batching", strings.ReplaceAll(captureWorkflowControl, "-parallel 2", "-parallel 1"), false},
		{"collector-parameters", strings.ReplaceAll(captureWorkflowControl, "--size 128m", "--size 256m"), true},
		{"workflow-environment", strings.ReplaceAll(captureWorkflowControl, "CAPTURE_BYTES: 128m", "CAPTURE_BYTES: 256m"), true},
		{"native-source-version", strings.ReplaceAll(captureWorkflowControl, "macos-26", "macos-27"), true},
		{"new-unknown-job", captureWorkflowControl + "  unknown:\n    run: python3 scripts/collector.py --new-control\n", true},
		{"collector-in-execution-job", strings.ReplaceAll(captureWorkflowControl, "go test -count=1 -parallel 2 ./acceptance", "python3 acceptance/native/capture.py --size 256m"), true},
		{"native-command-in-execution-job", strings.ReplaceAll(captureWorkflowControl, "go test -count=1 -parallel 2 ./acceptance", "hdiutil create -size 256m control.dmg"), true},
	} {
		t.Run(control.name, func(t *testing.T) {
			actual, known := captureWorkflowProjection(name, []byte(control.body))
			if !known || (actual.SHA256 != original.SHA256) != control.changed {
				t.Fatal("capture dependency boundary differs", known, actual)
			}
		})
	}
	for _, body := range []string{
		"name: unclassified layout\n",
		strings.ReplaceAll(captureWorkflowControl, "  replay:", "  'replay-job':"),
		strings.ReplaceAll(captureWorkflowControl, "  replay:", "  replay: &execution"),
		captureWorkflowControl + "env:\n  SOURCE_POLICY: changed\n",
	} {
		if _, known := captureWorkflowProjection(name, []byte(body)); known {
			t.Fatal("unknown workflow syntax lost its conservative full-file binding")
		}
	}
	if _, known := captureWorkflowProjection(".github/workflows/new-native-work.yml", []byte(captureWorkflowControl)); known {
		t.Fatal("unknown workflow was treated as an execution-only dependency")
	}
}

func TestCaptureDependencyIdentityKeepsTransportAndUnknownHelpersBound(t *testing.T) {
	root := replayControlModule(t, "valid")
	writeControl(t, root, ".github/workflows/native.yml", captureWorkflowControl)
	recipes := replayContract{Schema: 1, Tests: []replayTest{{Test: "TestControl", Input: "files", Manifest: "macos-*/manifest.json", CaptureContract: "native-control"}}}
	identity := func() string {
		t.Helper()
		value, err := captureContract(context.Background(), root, recipes)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	original := identity()
	writeControl(t, root, "acceptance/qualification/execution_index.go", "package main\n// Evidence inspection only.\n")
	writeControl(t, root, ".github/workflows/native.yml", strings.ReplaceAll(captureWorkflowControl, "-parallel 2", "-parallel 1"))
	if identity() != original {
		t.Fatal("execution-only changes invalidated independent Apple input bytes")
	}
	for _, name := range []string{
		"acceptance/qualification/reference_admission.go",
		"acceptance/qualification/reference_reuse.py",
		"internal/qualification/corpus/reader.go",
		"acceptance/qualification/unknown-helper.go",
		"acceptance/native/new-collector.py",
	} {
		before := identity()
		writeControl(t, root, name, "unclassified or input-handling dependency\n")
		if identity() == before {
			t.Fatal("input transport, native or unknown dependency was silently omitted", name)
		}
	}
}

func TestActualNativeWorkflowKeepsCaptureIdentityWhenOnlyReplayBatchingChanges(t *testing.T) {
	const name = ".github/workflows/native.yml"
	data, err := regularFile("../..", name)
	if err != nil {
		t.Fatal(err)
	}
	original, known := captureWorkflowProjection(name, data)
	if !known {
		t.Fatal("actual native workflow uses an unclassified layout")
	}
	body := string(data)
	replay := workflowJobSection(t, body, "replay")
	batched := strings.Replace(replay, "-parallel 2", "-parallel 1", 1)
	if replay == batched {
		t.Fatal("actual replay command no longer has the reviewed batching control")
	}
	changed := strings.Replace(body, replay, batched, 1)
	actual, known := captureWorkflowProjection(name, []byte(changed))
	if !known || actual.SHA256 != original.SHA256 {
		t.Fatal("actual replay batching still invalidates independent Apple inputs")
	}
	capture := workflowJobSection(t, body, "produce")
	modified := strings.Replace(capture, "--scenario file-reading", "--scenario file-semantics", 1)
	if capture == modified {
		t.Fatal("actual native capture invocation no longer matches its reviewed recipe")
	}
	changed = strings.Replace(body, capture, modified, 1)
	actual, known = captureWorkflowProjection(name, []byte(changed))
	if !known || actual.SHA256 == original.SHA256 {
		t.Fatal("actual native capture parameter change inherited old inputs")
	}
}
