package native

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func encryptedVolumeTarget(stage string) string {
	switch stage {
	case "retained":
		return "edited"
	case "retained-again", "aes128-nested", "aes256-nested":
		return "final"
	case "final":
		return "password-changed"
	}
	return ""
}

// Password changes carry new random keybag salts even in a plaintext DMG.
// Only this closed native journey can vary that way; Encrypted continues to
// describe the independent DMG envelope, never APFS volume encryption.
func validateEncryptedVolumeOutput(out schema.Output) error {
	target := encryptedVolumeTarget(out.Source.Stage)
	operation := "edit"
	expect := schema.Expectation{View: target, Volume: "EncryptedHistory", NewIdentities: true, CommandClockNS: replayCommandClock, Continuation: true}
	if out.Source.Stage == "final" {
		operation = "change-password"
		expect.NewIdentities = false
		expect.CommandClockNS = 0
	}
	encrypted := strings.HasPrefix(out.Source.Stage, "aes")
	password := ""
	if encrypted {
		password = "encrypted-snapshot-history.image"
	}
	if out.Source.Recipe != "encrypted-snapshot-history" || target == "" || (out.Source.Profile != "apfs" && out.Source.Profile != "apfsx") || out.Operation != operation || out.Format != "UDZO" || out.Encrypted != encrypted || out.Password != password || !expectationsEqual(out.Expect, expect) {
		return fmt.Errorf("encrypted volume output %s lacks its native edit/password contract", out.Name)
	}
	return nil
}

func (v *Verifier) encryptedVolumeClocks(out schema.Output, target *schema.Observation) (map[string]schema.View, error) {
	if err := validateEncryptedVolumeOutput(out); err != nil {
		return nil, err
	}
	source, ok := v.Cases[CaseKey(out.Source)]
	if !ok || source.Observation == nil || target == nil {
		return nil, fmt.Errorf("encrypted edit lacks original native observations")
	}
	beforeVol, err := namedVolume(source.Observation, "EncryptedHistory")
	if err != nil {
		return nil, err
	}
	afterVol, err := namedVolume(target, "EncryptedHistory")
	if err != nil {
		return nil, err
	}
	before, err := observedView(source.Observation, beforeVol.Index, "")
	if err != nil {
		return nil, err
	}
	after, err := observedView(target, afterVol.Index, "")
	if err != nil {
		return nil, err
	}
	recipe, ok := v.Recipes[out.Source.Recipe]
	if !ok {
		return nil, fmt.Errorf("encrypted edit lacks its native recipe")
	}
	var steps []schema.Step
	for _, stage := range recipe.Stages {
		if stage.Name != out.Expect.View {
			continue
		}
		for _, step := range stage.Steps {
			// These commands unlock/mount the private capture. They cannot affect
			// filesystem inode clocks. Every actual edit must be a declared FS write.
			if step.Tool != nil {
				tool := step.Tool
				if tool.Program != "diskutil" || tool.Expect != "0" || len(tool.Args) == 0 || (tool.Args[0] != "mount" && (len(tool.Args) < 2 || tool.Args[0] != "apfs" || tool.Args[1] != "unlockVolume")) {
					return nil, fmt.Errorf("unqualified encrypted edit setup command")
				}
				continue
			}
			if step.FS == nil || step.FS.Op != "write" || !strings.HasPrefix(step.FS.Path, "$MOUNT:EncryptedHistory/") {
				return nil, fmt.Errorf("unqualified encrypted edit clock operation")
			}
			command := *step.FS
			command.Path = strings.Replace(command.Path, "$MOUNT:EncryptedHistory/", "$MOUNT/", 1)
			steps = append(steps, schema.Step{FS: &command})
		}
	}
	if len(steps) == 0 {
		return nil, fmt.Errorf("encrypted edit lacks native writes")
	}
	projected, err := ProjectEditedViewClocks(before, after, steps, out.Source.Profile, out.Expect.CommandClockNS)
	if err != nil {
		return nil, err
	}
	return map[string]schema.View{"EncryptedHistory": projected}, nil
}

func requireEncryptedVolumeOutputs(pairs []Paired, cases map[string]corpus.Case, major int) error {
	counts := map[string]int{}
	for _, p := range pairs {
		out := p.Output
		if out.Source.Producer != major || out.Source.Recipe != "encrypted-snapshot-history" {
			continue
		}
		if out.Operation != "edit" && out.Operation != "change-password" {
			continue
		}
		if err := validateEncryptedVolumeOutput(out); err != nil {
			return err
		}
		counts[CaseKey(out.Source)]++
	}
	for _, profile := range []string{"apfs", "apfsx"} {
		for _, stage := range []string{"retained", "retained-again", "aes128-nested", "aes256-nested", "final"} {
			ref := schema.CaseRef{Producer: major, Recipe: "encrypted-snapshot-history", Profile: profile, Stage: stage}
			source, ok := cases[CaseKey(ref)]
			if !ok || source.Observation == nil || len(source.Observation.Volumes) != 3 || !hasHistoricalViews(source.Observation) || counts[CaseKey(ref)] != 1 {
				return fmt.Errorf("encrypted edit %s requires original encrypted history, both peers and one continued output", CaseKey(ref))
			}
		}
	}
	return nil
}

// The expected bytes are the explicit continuation command input. Apple's
// mounted observation must read every byte of both newly encrypted streams,
// through both hard-link aliases, before later native allocation can proceed.
func checkEncryptedContinuationStreams(observed *schema.Observation, selected string) error {
	volume, err := namedVolume(observed, selected)
	if err != nil {
		return err
	}
	view, err := observedView(observed, volume.Index, "")
	if err != nil {
		return err
	}
	data := []byte(strings.Repeat("continued by the product\n", 400))
	expected := fmt.Sprintf("%x", sha256.Sum256(data))
	count := 0
	for _, entry := range view.Entries {
		if entry.Path != "native-continuation/go/payload" && entry.Path != "native-continuation/go/alias" {
			continue
		}
		if len(entry.Xattrs) != 2 {
			return fmt.Errorf("encrypted continuation lost its resource fork or streamed attribute")
		}
		seen := map[string]bool{}
		for _, attribute := range entry.Xattrs {
			if seen[attribute.Name] {
				return fmt.Errorf("duplicate encrypted continuation attribute")
			}
			seen[attribute.Name] = true
			if attribute.Name != "com.apple.ResourceFork" && attribute.Name != "org.go-apfs.encrypted" || attribute.Bytes != int64(len(data)) || attribute.SHA256 != expected {
				return fmt.Errorf("encrypted continuation stream %s:%s differs from the declared input", entry.Path, attribute.Name)
			}
		}
		count++
	}
	if count != 2 {
		return fmt.Errorf("encrypted continuation lost a stream's hard-link alias")
	}
	return nil
}
