package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

var sessionCloneStages = []string{"before", "copied", "data-replaced", "fork-replaced", "attribute-replaced", "source-removed", "refused"}

// This journey crosses the process boundary after every command. It retains
// explicit clone declarations in private scratch, then asks the public pack
// command to materialize each independently captured Apple state.
func TestReopenedSessionCloneStreamsPackToAppleStates(t *testing.T) {
	cases, _ := loadCorpus(t)
	indexed := indexCases(cases)
	recipe, exists := recipesByName(t)["clone-copy"]
	if !exists || len(recipe.Stages) != len(sessionCloneStages) {
		t.Fatal("missing complete clone-copy recipe")
	}
	for i, stage := range recipe.Stages {
		if stage.Name != sessionCloneStages[i] {
			t.Fatal("unqualified clone-copy stage", stage.Name)
		}
	}
	for _, major := range []int{15, 26, 27} {
		for _, profile := range []string{"apfs", "apfsx", "hfsplus", "hfsx"} {
			states := make([]corpus.Case, len(sessionCloneStages))
			for i, stage := range sessionCloneStages {
				states[i] = indexed[stageKey(major, recipe.Name, profile, stage)]
				if states[i].Observation == nil {
					t.Fatalf("missing clone-copy control macOS %d/%s/%s", major, profile, stage)
				}
			}
			t.Run(fmt.Sprintf("macos-%d/%s", major, profile), func(t *testing.T) {
				t.Parallel()
				before := states[0]
				sourceDigest := packingFileDigest(t, before.Image())
				clock := commandClock(states)
				s := openCommandSession(t, before, clock)
				actor := s.actor
				var replay []schema.Step
				for index, stage := range recipe.Stages[1:] {
					replay = append(replay, stage.Steps...)
					for stepIndex, step := range stage.Steps {
						if len(step.Only) != 0 && !containsString(step.Only, profile) {
							continue
						}
						if step.Host != nil {
							if stepIndex+1 >= len(stage.Steps) || stage.Steps[stepIndex+1].Tool == nil {
								t.Fatal("clone session staging payload lacks its native write")
							}
							if _, err := native.CloneCopyWriteStep(*step.Host, *stage.Steps[stepIndex+1].Tool); err != nil {
								t.Fatal(err)
							}
						} else if step.Tool != nil && step.Tool.Program == "dd" {
							if stepIndex == 0 || stage.Steps[stepIndex-1].Host == nil {
								t.Fatal("clone session native write lacks its staging payload")
							}
							write, err := native.CloneCopyWriteStep(*stage.Steps[stepIndex-1].Host, *step.Tool)
							if err != nil {
								t.Fatal(err)
							}
							s.actorContext(t, 0)
							sessionCloneFS(t, s, &write)
						} else if step.Tool != nil {
							uid := actor
							if step.Tool.Sudo {
								uid = 0
							}
							s.actorContext(t, uid)
							sessionCloneTool(t, s, step.Tool, strings.HasPrefix(profile, "apfs"))
						} else if step.FS != nil {
							s.actorContext(t, actor)
							sessionCloneFS(t, s, step.FS)
						} else {
							t.Fatal("unhandled clone session recipe step")
						}
					}
					after := states[index+1]
					s.run(t, false, "session", "verify", "build")
					name := outputName(after, "build.session-clones.UDZO.dmg")
					current := filepath.Join(s.scratch, "build", "current")
					revision := packingFileDigest(t, current)
					output := produceTwice(t, name, true, func(destination string) error {
						argv := []string{"pack", "--scratch-dir", s.scratch, "--session", "build", "--volume-name", "Session Clones", "--format", "UDZO", "--time", clock.Format(time.RFC3339Nano), "--json", destination}
						data, err := exec.Command(portableCommandBinary(t), argv...).CombinedOutput()
						if err != nil {
							return fmt.Errorf("pack reopened clone session: %w: %s", err, data)
						}
						var report pack.Report
						if err := json.Unmarshal(data, &report); err != nil {
							return err
						}
						if strings.HasPrefix(profile, "apfs") {
							shared := false
							for _, result := range report.Clones {
								shared = shared || result.Action == "shared"
							}
							if !shared {
								return fmt.Errorf("APFS pack did not report any materialized explicit sharing")
							}
						}
						return nil
					})
					if packingFileDigest(t, current) != revision {
						t.Fatal("packing changed session state")
					}
					projected, err := native.CloneCopyReference(before.Observation.Views[0], after.Observation.Views[0], replay, profile, clock.UnixNano())
					if err != nil {
						t.Fatal(err)
					}
					checkSessionCloneImage(t, output, projected)
					recordOutput(t, schema.Output{Name: name, File: filepath.Base(output), Operation: "build", Format: "UDZO", Source: caseRef(before), Expect: schema.Expectation{View: stage.Name, Subtree: "Fixture", NewIdentities: true, CommandClockNS: clock.UnixNano(), Continuation: index == len(recipe.Stages)-2}})
				}
				if packingFileDigest(t, before.Image()) != sourceDigest {
					t.Fatal("session clone journey changed its captured source image")
				}
			})
		}
	}
}

func sessionCloneTool(t *testing.T, s *commandSession, tool *schema.ToolStep, apfs bool) {
	t.Helper()
	if tool.Program != "cp" {
		t.Fatal("unexpected clone-copy command", tool.Program)
	}
	current := filepath.Join(s.scratch, "build", "current")
	before := packingFileDigest(t, current)
	argv := []string{"cp", "--scratch-dir", s.scratch, "--session", "build", "--json"}
	for _, arg := range tool.Args {
		argv = append(argv, strings.ReplaceAll(arg, "$MOUNT/Fixture", ""))
	}
	data, err := exec.Command(portableCommandBinary(t), argv...).CombinedOutput()
	if tool.Expect != "0" {
		exit, ok := err.(*exec.ExitError)
		if !ok || exit.ExitCode() != 1 || packingFileDigest(t, current) != before {
			t.Fatalf("clone refusal changed state or status: %v: %s", err, data)
		}
		return
	}
	if err != nil {
		t.Fatalf("clone session command %v: %v: %s", argv, err, data)
	}
	var report session.Report
	if err := json.Unmarshal(data, &report); err != nil || len(report.Clones) == 0 {
		t.Fatal("missing actual clone/fallback outcomes", err, string(data))
	}
	for _, result := range report.Clones {
		if result.Cloned != apfs || apfs && result.Fallback != "" || !apfs && result.Fallback == "" {
			t.Fatal("wrong actual clone/fallback outcome", result)
		}
	}
}

func sessionCloneFS(t *testing.T, state *commandSession, step *schema.FSStep) {
	t.Helper()
	ctx := context.Background()
	directory := filepath.Join(state.scratch, "build")
	s, err := session.Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	path := "/" + workspacePath(step.Path)
	var data []byte
	if step.Op == "write" || step.Op == "setxattr" {
		data, err = stepBytes(step)
		if err != nil {
			t.Fatal(err)
		}
	}
	switch step.Op {
	case "link":
		_, err = s.Link(ctx, path, "/"+workspacePath(step.Target), session.LinkOptions{})
	case "write":
		if strings.HasSuffix(path, "/..namedfork/rsrc") {
			_, err = s.ReplaceResourceFork(ctx, strings.TrimSuffix(path, "/..namedfork/rsrc"), bytes.NewReader(data))
		} else {
			_, err = s.ReplaceData(ctx, path, bytes.NewReader(data))
		}
	case "setxattr":
		_, err = s.SetAttribute(ctx, []string{path}, step.Name, bytes.NewReader(data), session.AttributeOptions{})
	case "unlink":
		_, err = s.Remove(ctx, []string{path}, session.RemoveOptions{})
	case "clone":
		// Session copying exposes cp -c rather than clonefile. Its explicit
		// no-clobber variant must preserve the same occupied-target invariant.
		if step.Expect != "EEXIST" {
			t.Fatal("unqualified direct clone refusal")
		}
		before := s.Report().Revision
		_, err = s.Copy(ctx, []string{path}, "/"+workspacePath(step.Target), session.CopyOptions{Clone: true, NoClobber: true})
		if !errors.Is(err, fs.ErrExist) || s.Report().Revision != before {
			t.Fatal("occupied clone target was changed", err)
		}
		return
	default:
		t.Fatal("unhandled session clone operation", step.Op)
	}
	if err != nil {
		t.Fatal(step.Op, path, err)
	}
}

func checkSessionCloneImage(t *testing.T, image string, want schema.View) {
	t.Helper()
	ctx := context.Background()
	img, err := diskimage.Open(image)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	report, err := inspect.Image(ctx, img)
	if err != nil {
		t.Fatal(err)
	}
	var reader filesystem.Reader
	for _, partition := range report.Partitions {
		if partition.APFS != nil && len(partition.APFS.Volumes) == 1 {
			reader = &partition.APFS.Volumes[0]
		} else if partition.HFSPlus != nil {
			reader = partition.HFSPlus
		}
	}
	if reader == nil {
		t.Fatal("fresh session output has no admitted filesystem")
	}
	compareViewWith(t, ctx, "reopened session clone build", reader, want, compareOptions{subtree: "Fixture", ignoreIDFor: func(string) bool { return true }})
	root := false
	for _, entry := range want.Entries {
		if entry.Path == "Fixture" {
			root = true
			compareEntryWith(t, ctx, "clone session root metadata", reader, reader.Root(), entry, compareOptions{ignoreIDFor: func(string) bool { return true }})
		}
	}
	if !root {
		t.Fatal("native clone control lacks its captured subtree root metadata")
	}
}
