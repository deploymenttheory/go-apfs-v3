package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/receipt"
)

// These are ordinary tiny files in a synthetic Go module, never filesystem
// images or native observations. They exercise the execution gate itself.
func replayControlModule(t *testing.T, mode string) string {
	t.Helper()
	root := t.TempDir()
	writeControl(t, root, "go.mod", "module github.com/deploymenttheory/go-apfs-v3\n\ngo 1.27.0\n")
	writeControl(t, root, "source.go", "package control\nconst Value = 1\n")
	writeControl(t, root, "acceptance/native/control.py", "# ordinary file-only control\n")
	code := `package acceptance_test
import("os";"path/filepath";"testing")
func TestReference(t *testing.T){
 t.Run("macos-15/apfs",func(t *testing.T){
  for _,format:=range []string{"UDRO","UDZO"}{
   if "MODE"=="missing-case"&&format=="UDZO"{continue}
   t.Run(format,func(t *testing.T){
    if "MODE"=="failure"{t.Fatal("deliberate failed assertion")}
    if "MODE"=="exit"{os.Exit(3)}
    output:=filepath.Join(os.Getenv("APFS_GEOMETRY_OUTPUT"),"macos-15","apfs")
    if err:=os.MkdirAll(output,0700);err!=nil{t.Fatal(err)}
    if !("MODE"=="missing-output"&&format=="UDZO"){
     if err:=os.WriteFile(filepath.Join(output,"edited-"+format+".dmg"),[]byte("plain bytes "+format),0600);err!=nil{t.Fatal(err)}
    }
   })
  }
  if "MODE"=="mutated-input"{if err:=os.WriteFile(os.Getenv("UNIT_INPUT"),[]byte("changed source"),0600);err!=nil{t.Fatal(err)}}
  if "MODE"=="mutated-code"{if err:=os.WriteFile(os.Getenv("UNIT_CODE"),[]byte("package control\nconst Value=2\n"),0600);err!=nil{t.Fatal(err)}}
 })
}
`
	writeControl(t, root, "acceptance/control_test.go", strings.ReplaceAll(code, "MODE", mode))
	manifestPath := "acceptance/testdata/apfs-geometry/macos-15/manifest.json"
	manifestText := `{"schema":1,"scenario":"unit-control","producer":{"system":"macOS","version":"15.0","build":"unit-control","architecture":"synthetic"},"cases":[{"id":"apfs"}]}`
	if mode == "repacking" {
		manifestText = strings.TrimSuffix(manifestText, "}") + `,"rejections":[]}`
	}
	writeControl(t, root, manifestPath, manifestText)
	definition := corpus.Definition{ID: "apfs-geometry", Path: "acceptance/testdata/apfs-geometry", Bindings: []corpus.Binding{{Family: "geometry-control", CaptureClass: "apple-independent"}}, Manifests: []corpus.ManifestReference{{Path: "macos-15/manifest.json", SHA256: digest(manifestText), Cases: []string{"cases/apfs"}}}}
	catalog, err := corpus.Build(context.Background(), root, []corpus.Definition{definition})
	if err != nil {
		t.Fatal(err)
	}
	writeObject := func(name string, value any) {
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		writeControl(t, root, name, string(data))
	}
	writeObject("acceptance/qualification/corpus.json", catalog)
	r := registry{Schema: 1, Families: []family{{ID: "geometry-control", Tests: []entrypoint{{Name: "TestReference", File: "acceptance/control_test.go"}}, Corpora: []string{definition.Path}, CaptureClass: "apple-independent"}}, Manifests: []manifest{{Path: manifestPath, SHA256: digest(manifestText), Cases: []string{"cases/apfs"}}}}
	writeObject("acceptance/qualification/registry.json", r)
	writeObject("acceptance/qualification/replay.json", replayContract{Schema: 1, Inputs: []replayInput{{ID: "apfs-geometry", Environment: "APFS_NATIVE_APFS_GEOMETRY"}}, Tests: []replayTest{{Test: "TestReference", Input: "apfs-geometry", Manifest: "macos-*/manifest.json", Layout: "combined-case", Variants: []string{"UDRO", "UDZO"}, Output: "APFS_GEOMETRY_OUTPUT"}}})
	for _, args := range [][]string{{"init", "--quiet"}, {"add", "."}, {"-c", "user.name=Qualification control", "-c", "user.email=control@example.invalid", "commit", "--quiet", "-m", "ordinary-file control"}} {
		command := exec.Command("git", args...)
		command.Dir = root
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("temporary git control: %s: %v", output, err)
		}
	}
	t.Setenv("GITHUB_RUN_ID", "")
	t.Setenv("APFS_REQUIRED_CONTROLS", "")
	t.Setenv("READBACK_RUN", "")
	t.Setenv("APFS_NATIVE_APFS_GEOMETRY", "")
	t.Setenv("APFS_GEOMETRY_OUTPUT", "")
	t.Setenv("UNIT_INPUT", filepath.Join(root, filepath.FromSlash(manifestPath)))
	t.Setenv("UNIT_CODE", filepath.Join(root, "source.go"))
	return root
}

func TestReplayPublishesOnlyCompleteExecution(t *testing.T) {
	for _, mode := range []string{"valid", "missing-case", "missing-output", "failure", "exit", "mutated-input", "mutated-code"} {
		t.Run(mode, func(t *testing.T) {
			root := replayControlModule(t, mode)
			var output bytes.Buffer
			err := runReplay(context.Background(), replayOptions{root: root, registry: "acceptance/qualification/registry.json", catalog: "acceptance/qualification/corpus.json", directory: "artifacts/qualification", args: []string{"-timeout", "1m", "./acceptance", "-run", "^TestReference$"}}, &output)
			if (err == nil) != (mode == "valid") {
				t.Fatalf("%s: %v\n%s", mode, err, output.String())
			}
			paths, globErr := filepath.Glob(filepath.Join(root, "artifacts/qualification/replay-*/receipt.json"))
			if globErr != nil {
				t.Fatal(globErr)
			}
			if mode != "valid" && len(paths) != 0 {
				t.Fatal("failed/interrupted execution published a receipt")
			}
			if mode == "valid" {
				if len(paths) != 1 {
					t.Fatal("complete execution receipt absent")
				}
				data, err := os.ReadFile(paths[0])
				if err != nil {
					t.Fatal(err)
				}
				var record receipt.Receipt
				if err = corpus.StrictJSON(data, &record); err != nil {
					t.Fatal(err)
				}
				if len(record.Verdicts) != 3 || len(record.Outputs) != 2 {
					t.Fatal("case, format or actual output evidence lost", len(record.Verdicts), len(record.Outputs))
				}
				if len(record.Plan.Environment.Tools) < 5 {
					t.Fatal("actual compiler and linker evidence missing")
				}
				data, err = os.ReadFile(filepath.Join(filepath.Dir(paths[0]), "source-inputs.json"))
				if err != nil {
					t.Fatal("standalone execution lost its original input snapshot", err)
				}
				var snapshot replayEvidence
				if err = corpus.StrictJSON(data, &snapshot); err != nil || len(snapshot.Inputs) != 1 || snapshot.OutputEnvironment != "" {
					t.Fatal("standalone source evidence depends on a writer archive", err)
				}
				archivedPlan, err := os.ReadFile(filepath.Join(filepath.Dir(paths[0]), "outputs/APFS_GEOMETRY_OUTPUT/.qualification", record.Fingerprint, "plan.json"))
				if err != nil {
					t.Fatal("original pre-execution plan was not retained with output evidence", err)
				}
				originalPlan, err := os.ReadFile(filepath.Join(filepath.Dir(paths[0]), "plan.json"))
				if err != nil || !bytes.Equal(archivedPlan, originalPlan) {
					t.Fatal("archived plan was reconstructed or changed after execution", err)
				}
				python, err := exec.LookPath("python3")
				if err != nil {
					python, err = exec.LookPath("python")
				}
				if err != nil {
					t.Fatal("qualification wire checks require Python", err)
				}
				module, err := filepath.Abs("../native")
				if err != nil {
					t.Fatal(err)
				}
				program := `import os,sys
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,sys.argv[1])
from qualification import ReplayEvidence,NativeEvidence
e=ReplayEvidence(sys.argv[2],sys.argv[3])
e.file(sys.argv[4])
environment={'os':'darwin','architecture':'synthetic','version':'15.0','build':'unit-native','toolchain':'file-only-control','flags':[],'race':False,'tools':[{'path':'tools/control','bytes':1,'sha256':'a'*64}]}
os.environ.update(GITHUB_SHA='unit-native',GITHUB_RUN_ID='unit-native',GITHUB_RUN_ATTEMPT='1',GITHUB_JOB='control')
with patch('qualification.native_environment',return_value=environment):
    n=NativeEvidence(e,[Path(sys.argv[4])],sys.argv[3],Path(sys.argv[2]),'native-control',15)
    with n.case([Path(sys.argv[4])]):
        assert Path(sys.argv[4]).read_bytes()==b'plain bytes UDRO'
    n.finish()
`
				command := exec.Command(python, "-c", program, module, filepath.Join(filepath.Dir(paths[0]), "outputs"), root, filepath.Join(filepath.Dir(paths[0]), "outputs/APFS_GEOMETRY_OUTPUT/macos-15/apfs/edited-UDRO.dmg"))
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("native reader rejected actual Go evidence: %s: %v", output, err)
				}
				nativeRoot := filepath.Join(filepath.Dir(paths[0]), "outputs")
				data, err = os.ReadFile(filepath.Join(nativeRoot, "native-control-macos-15.receipt.json"))
				if err != nil {
					t.Fatal(err)
				}
				var native receipt.Receipt
				if err = corpus.StrictJSON(data, &native); err != nil {
					t.Fatal(err)
				}
				if err = receipt.Verify(native.Plan, native.Origin, native); err != nil {
					t.Fatal("Python native proof differs from Go wire contract", err)
				}
				data, err = os.ReadFile(filepath.Join(nativeRoot, native.Events.Path))
				if err != nil {
					t.Fatal(err)
				}
				if _, err = receipt.CheckEvents(bytes.NewReader(data), native.Plan, nil, io.Discard); err != nil {
					t.Fatal("Python native event stream differs from Go contract", err)
				}
			}
		})
	}
}

func TestReplayFlagAdmissionPreservesFreshBoundedAssertions(t *testing.T) {
	for _, args := range [][]string{{"-count=0", "./acceptance"}, {"-count=2", "./acceptance"}, {"-timeout=0", "./acceptance"}, {"-timeout=1h", "./acceptance"}, {"-parallel=0", "./acceptance"}, {"-exec=other", "./acceptance"}, {"./apfs"}, {"./acceptance", "./..."}, {"-run"}, {"-short", "./acceptance"}} {
		if _, err := parseTestCommand(args); err == nil {
			t.Fatal("unsafe or unbounded execution accepted", args)
		}
	}
	if _, err := parseTestCommand([]string{"-race", "-count=1", "-timeout", "5m", "-parallel", "2", "./acceptance", "-run", "^TestNativeGeometry$/macos-15/"}); err != nil {
		t.Fatal(err)
	}
}

func TestOutputIsolationFollowsPhysicalPaths(t *testing.T) {
	root := t.TempDir()
	input := filepath.Join(root, "inputs")
	if err := os.Mkdir(input, 0700); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{input, filepath.Join(input, "new-output"), root} {
		if err := separatePaths(input, output); err == nil {
			t.Fatal("overlap admitted", output)
		}
	}
	if err := separatePaths(input, filepath.Join(root, "outputs")); err != nil {
		t.Fatal(err)
	}
}

func TestReceiptPublicationCannotReplaceEvidence(t *testing.T) {
	name := filepath.Join(t.TempDir(), "receipt.json")
	if err := newJSON(name, map[string]string{"original": "record"}); err != nil {
		t.Fatal(err)
	}
	if err := newJSON(name, map[string]string{"replacement": "record"}); !os.IsExist(err) {
		t.Fatal("existing evidence replaced", err)
	}
	data, err := os.ReadFile(name)
	if err != nil || !strings.Contains(string(data), "original") {
		t.Fatal(string(data), err)
	}
}
