package acceptance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

var cloneCopyStages = []string{"before", "copied", "data-replaced", "fork-replaced", "attribute-replaced", "source-removed", "refused"}

func TestCloneCopyEditsMatchAppleStates(t *testing.T) {
	cases := storageCases(t, map[string]map[string][]string{"clone-copy": {
		"apfs": cloneCopyStages, "apfsx": cloneCopyStages, "hfsplus": cloneCopyStages, "hfsx": cloneCopyStages,
	}})
	indexed := indexCases(cases)
	recipe := recipesByName(t)["clone-copy"]
	if len(recipe.Stages) != len(cloneCopyStages) {
		t.Fatal("missing complete native clone-copy recipe")
	}
	for i, name := range cloneCopyStages {
		if recipe.Stages[i].Name != name {
			t.Fatal("unqualified clone-copy stage", recipe.Stages[i].Name)
		}
	}
	for _, before := range cases {
		index := slices.Index(cloneCopyStages, before.Stage)
		if index < 0 || index == len(cloneCopyStages)-1 {
			continue
		}
		after := indexed[stageKey(before.Producer, before.Recipe, before.Profile, cloneCopyStages[index+1])]
		var views []schema.View
		for _, stage := range cloneCopyStages {
			state := indexed[stageKey(before.Producer, before.Recipe, before.Profile, stage)]
			if state.Observation == nil || len(state.Observation.Views) != 1 || len(state.Observation.Volumes) != 1 {
				t.Fatal("clone-copy needs every independent single-volume native state", before.Profile, stage)
			}
			views = append(views, state.Observation.Views[0])
		}
		clockNS, err := native.CloneCopyCommandClock(views)
		if err != nil {
			t.Fatal(err)
		}
		t.Run(fmt.Sprintf("macos-%d/%s/%s", before.Producer, before.Profile, after.Stage), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			source := before.Image()
			sourceDigest := packingFileDigest(t, source)
			stage := recipe.Stages[index+1]
			if after.Stage == "refused" {
				checkCloneCopyRefusals(t, ctx, source, before.Profile, stage, time.Unix(0, clockNS))
			}
			for _, format := range []string{"UDRO", "UDZO"} {
				name := outputName(after, "edit.clone-copy."+format+".dmg")
				options := imageedit.Options{Time: time.Unix(0, clockNS).UTC(), Format: format, ActorUID: filesystem.Observed(uint32(0))}
				output := produceTwice(t, name, true, func(destination string) error {
					var report imageedit.Report
					var err error
					if after.Stage == "copied" && format == "UDZO" {
						report, err = cloneCopyStageCLI(t, ctx, source, destination, options, stage)
					} else {
						report, err = cloneCopyStage(ctx, source, destination, options, stage, before.Profile)
					}
					if err == nil && after.Stage == "copied" {
						if len(report.Clones) != 9 {
							return fmt.Errorf("clone copy omitted regular-file outcomes: %d, want nine", len(report.Clones))
						}
						for _, result := range report.Clones {
							apfs := strings.HasPrefix(before.Profile, "apfs")
							if result.Cloned != apfs || apfs && result.Fallback != "" || !apfs && result.Fallback == "" {
								return fmt.Errorf("wrong actual clone/fallback outcome: %+v", result)
							}
						}
					}
					return err
				})
				checkCloneCopiedImage(t, ctx, output, before, after, recipe, stage.Steps, clockNS)
				recordOutput(t, schema.Output{Name: name, File: filepath.Base(output), Operation: "edit", Format: format, Source: caseRef(before), Expect: schema.Expectation{View: after.Stage, NewIdentities: true, CommandClockNS: clockNS, Continuation: after.Stage == "refused" && format == "UDZO"}})
			}
			if packingFileDigest(t, source) != sourceDigest {
				t.Fatal("clone-copy replay changed original native image")
			}
		})
	}
}

func cloneCopyStage(ctx context.Context, source, destination string, options imageedit.Options, stage schema.Stage, profile string) (imageedit.Report, error) {
	return imageedit.Edit(ctx, source, destination, options, func(editor *imageedit.Editor) error {
		for _, step := range stage.Steps {
			if len(step.Only) != 0 && !slices.Contains(step.Only, profile) {
				continue
			}
			if step.Tool != nil {
				tool := step.Tool
				if tool.Program != "cp" || len(tool.Args) != 3 {
					return fmt.Errorf("unqualified clone-copy tool")
				}
				if tool.Expect != "0" {
					continue // Refusals are separately required before unchanged publication.
				}
				flags := tool.Args[0]
				_, err := editor.Copy([]imageedit.CopyCommand{{Sources: []string{cloneCopyPath(tool.Args[1])}, Destination: cloneCopyPath(tool.Args[2]), Options: imageedit.CopyOptions{Clone: true, Preserve: flags == "-cp", Recursive: flags == "-cR"}}})
				if err != nil {
					return err
				}
			} else if step.FS != nil {
				if step.FS.Expect != "" && step.FS.Expect != "0" {
					continue
				}
				touched := &touchedPaths{paths: map[string]bool{}, pinnedModify: map[string]bool{}}
				_, changes, err := translateFSStep(step.FS, touched)
				if err != nil {
					return err
				}
				if _, err := editor.Apply(changes); err != nil {
					return err
				}
			} else {
				return fmt.Errorf("unqualified clone-copy step")
			}
		}
		return nil
	})
}

func cloneCopyPath(value string) string { return strings.TrimPrefix(value, "$MOUNT") }

func cloneCopyStageCLI(t *testing.T, ctx context.Context, source, destination string, options imageedit.Options, stage schema.Stage) (imageedit.Report, error) {
	t.Helper()
	args := []string{"edit", "--json", "--image", source, "--output", destination, "--format", options.Format, "--uid", "0", "--time", options.Time.Format(time.RFC3339), "--"}
	for i, step := range stage.Steps {
		if i != 0 {
			args = append(args, "--next")
		}
		if step.Tool != nil && step.Tool.Program == "cp" && step.Tool.Expect == "0" {
			args = append(args, "cp")
			for _, arg := range step.Tool.Args {
				args = append(args, cloneCopyPath(arg))
			}
		} else if step.FS != nil && step.FS.Op == "link" {
			args = append(args, "ln", cloneCopyPath(step.FS.Path), cloneCopyPath(step.FS.Target))
		} else {
			return imageedit.Report{}, fmt.Errorf("unqualified clone-copy CLI command")
		}
	}
	data, err := exec.CommandContext(ctx, portableCommandBinary(t), args...).CombinedOutput()
	if err != nil {
		return imageedit.Report{}, fmt.Errorf("clone-copy CLI: %w: %s", err, data)
	}
	var report imageedit.Report
	err = json.Unmarshal(data, &report)
	return report, err
}

func checkCloneCopyRefusals(t *testing.T, ctx context.Context, source, profile string, stage schema.Stage, clock time.Time) {
	t.Helper()
	digest := packingFileDigest(t, source)
	for _, step := range stage.Steps {
		if len(step.Only) != 0 && !slices.Contains(step.Only, profile) {
			continue
		}
		destination := filepath.Join(t.TempDir(), "absent.dmg")
		options := imageedit.Options{Time: clock, ActorUID: filesystem.Observed(uint32(0))}
		var err, expected error
		if tool := step.Tool; tool != nil {
			flags := tool.Args[0]
			expected = map[string]error{"-cX": fs.ErrInvalid, "-c": filesystem.ErrConflict, "-cn": fs.ErrExist}[flags]
			_, err = imageedit.Copy(ctx, source, destination, options, []string{cloneCopyPath(tool.Args[1])}, cloneCopyPath(tool.Args[2]), imageedit.CopyOptions{Clone: true, NoClobber: flags == "-cn", NoAttributes: flags == "-cX"})
			argv := []string{"cp", "--image", source, "--output", destination, "--uid", "0", "--time", clock.Format(time.RFC3339)}
			for _, arg := range tool.Args {
				argv = append(argv, cloneCopyPath(arg))
			}
			data, cliErr := exec.CommandContext(ctx, portableCommandBinary(t), argv...).CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(cliErr, &exit) || exit.ExitCode() != 1 {
				t.Fatal("clone-copy CLI refusal status", cliErr, string(data))
			}
		} else if step.FS != nil && step.FS.Op == "clone" && step.FS.Expect == "EEXIST" {
			expected = fs.ErrExist
			_, err = imageedit.Apply(ctx, source, destination, options, []imageedit.Change{{Operation: "clone", Path: cloneCopyPath(step.FS.Path), Destination: cloneCopyPath(step.FS.Target)}})
		} else {
			t.Fatal("unqualified clone-copy refusal")
		}
		if expected == nil || !errors.Is(err, expected) {
			t.Fatal("clone-copy typed refusal", err, expected)
		}
		if _, err := os.Lstat(destination); !errors.Is(err, fs.ErrNotExist) || packingFileDigest(t, source) != digest {
			t.Fatal("clone-copy refusal changed source or published output", err)
		}
	}
}

func checkCloneCopiedImage(t *testing.T, ctx context.Context, output string, before, after corpus.Case, recipe schema.Recipe, steps []schema.Step, clockNS int64) {
	t.Helper()
	image, err := diskimage.Open(output)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	report, err := inspect.Image(ctx, image)
	if err != nil {
		t.Fatal(err)
	}
	reader, close := openVolume(t, ctx, report, after.Observation.Volumes[0], volumeName(after.Observation.Volumes[0]), recipe)
	if close != nil {
		defer close()
	}
	expected, err := native.CloneCopyReference(before.Observation.Views[0], after.Observation.Views[0], steps, before.Profile, clockNS)
	if err != nil {
		t.Fatal(err)
	}
	retained := map[string]uint64{}
	for _, entry := range before.Observation.Views[0].Entries {
		retained[entry.Path] = entry.ID
	}
	for _, entry := range expected.Entries {
		if retained[entry.Path] != entry.ID {
			delete(retained, entry.Path)
		}
	}
	compareViewWith(t, ctx, filepath.Base(output), reader, expected, compareOptions{ignoreIDFor: func(path string) bool { return retained[path] == 0 }})
	forward, reverse := map[uint64]uint64{}, map[uint64]uint64{}
	for _, entry := range expected.Entries {
		id, err := filesystem.LookupExact(ctx, reader, entry.Path)
		if err != nil {
			t.Fatal(err)
		}
		if forward[entry.ID] != 0 && forward[entry.ID] != id || reverse[id] != 0 && reverse[id] != entry.ID {
			t.Fatal("clone-copy changed hard-link classes", entry.Path)
		}
		forward[entry.ID], reverse[id] = id, entry.ID
	}
}
