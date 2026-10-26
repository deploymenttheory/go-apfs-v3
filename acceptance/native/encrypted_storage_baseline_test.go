//go:build native && darwin

package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestEncryptedAPFSEditAndPasswordNativeContinuation(t *testing.T) {
	v := newVerifier(t)
	ctx := context.Background()
	type verdict struct {
		Name  string `json:"name"`
		Error string `json:"error,omitempty"`
	}
	var results []verdict
	record := func(name string, err error) bool {
		row := verdict{Name: name}
		if err != nil {
			row.Error = err.Error()
			t.Error(name, err)
		}
		results = append(results, row)
		t.Log(name, err)
		return err == nil
	}
	defer func() {
		data, _ := json.MarshalIndent(results, "", "  ")
		if err := os.WriteFile(filepath.Join(v.Work, "result.json"), data, 0600); err != nil {
			t.Error(err)
		}
	}()
	other := 26
	if v.Major == 26 {
		other = 27
	}
	baseline := schema.CaseRef{Producer: other, Recipe: "encrypted-snapshot-history", Profile: "apfs", Stage: "retained"}
	k := v.Cases[CaseKey(baseline)]
	lease, baselineErr := v.Corpus.AcquireImage(ctx, k)
	if baselineErr == nil {
		finish := v.recordVerificationCommands(filepath.Join(v.Work, "cross-version-baseline"))
		baselineErr = v.checkEncryptedVolumes(ctx, lease.Path(), nil, k.Observation, v.Recipes[k.Recipe])
		finish(&baselineErr)
		baselineErr = errors.Join(baselineErr, lease.Release(baselineErr))
	}
	// Record the cross-version warning diagnostic; the actual file/password
	// verdicts below still fail this bounded run on any qualification error.
	row := verdict{Name: "cross-version checker diagnostic"}
	if baselineErr != nil {
		row.Error = baselineErr.Error()
	}
	results = append(results, row)
	for _, profile := range []string{"apfs", "apfsx"} {
		for _, stage := range []string{"retained", "final"} {
			name := profile + "-" + stage
			source := schema.CaseRef{Producer: v.Major, Recipe: "encrypted-snapshot-history", Profile: profile, Stage: stage}
			input := v.Cases[CaseKey(source)]
			recipe := v.Recipes[source.Recipe]
			lease, err := v.Corpus.AcquireImage(ctx, input)
			if !record(name+" original input", err) {
				continue
			}
			work := filepath.Join(v.Work, name)
			if err := os.MkdirAll(work, 0700); err != nil {
				t.Fatal(err)
			}
			var selected string
			for _, volume := range input.Observation.Volumes {
				if volumeName(volume) == "EncryptedHistory" {
					selected = volume.APFS.VolumeUUID
				}
			}
			credentials, err := continuationVolumeArguments(work, selected, input.Observation, recipe)
			if !record(name+" credentials", err) {
				continue
			}
			output := filepath.Join(work, "output.dmg")
			clock := time.Unix(0, replayCommandClock).UTC().Format(time.RFC3339)
			args := []string{"edit", "--image", lease.Path(), "--output", output, "--volume", selected, "--partition", "1", "--time", clock}
			operation := "edit"
			expect := schema.Expectation{View: "edited", Volume: "EncryptedHistory", NewIdentities: true, CommandClockNS: replayCommandClock, Continuation: true}
			if stage == "final" {
				operation = "change-password"
				expect = schema.Expectation{View: "password-changed", Volume: "EncryptedHistory", Continuation: true}
				password := filepath.Join(work, "new-password")
				if err := os.WriteFile(password, []byte(recipe.Passwords["replacement"]), 0600); err != nil {
					t.Fatal(err)
				}
				args[0] = "passwd"
				args = append(args, "--new-password-file", password)
			}
			args = append(args, credentials...)
			if stage == "retained" {
				args = append(args, "--")
				count := 0
				for _, target := range recipe.Stages {
					if target.Name == "edited" {
						for _, step := range target.Steps {
							if step.FS != nil {
								write := step.FS
								if write.Op != "write" || !strings.HasPrefix(write.Path, "$MOUNT:EncryptedHistory/") {
									t.Fatal("unexpected native edit")
								}
								file := filepath.Join(work, "payload-"+strconv.Itoa(count))
								if err := os.WriteFile(file, []byte(write.Content), 0644); err != nil {
									t.Fatal(err)
								}
								if count > 0 {
									args = append(args, "--next")
								}
								args = append(args, "cp", "-X", "--from-host", file, strings.TrimPrefix(write.Path, "$MOUNT:EncryptedHistory"))
								count++
							}
						}
					}
				}
				if count == 0 {
					t.Fatal("no native edit commands")
				}
			}
			log, err := exec.CommandContext(ctx, v.Product, args...).CombinedOutput()
			if err != nil {
				err = fmt.Errorf("%w: %s", err, log)
			}
			if !record(name+" product CLI", err) {
				continue
			}
			if !record(name+" source release", lease.Release(nil)) {
				continue
			}
			out := schema.Output{Name: name, File: filepath.Base(output), Operation: operation, Format: "UDZO", Source: source, Expect: expect}
			pair := Paired{Name: name, Output: out, Primary: "darwin", ByHost: map[string]schema.Output{"darwin": out}, Dirs: map[string]string{"darwin": work}, Passwords: recipe.Passwords}
			differences, err := v.VerifyOutput(ctx, pair)
			if err == nil && len(differences) > 0 {
				err = fmt.Errorf("native readback differences: %v", differences)
			}
			if !record(name+" native checks and complete readback", err) {
				continue
			}
			_, err = v.Continuation(ctx, pair, schemaCase{recipe: recipe})
			record(name+" native Go native continued allocation", err)
		}
	}
}
