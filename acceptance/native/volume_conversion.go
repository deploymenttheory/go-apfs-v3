package native

import (
	"fmt"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// VolumeConversionTarget is the closed set of independent native conversion
// journeys. Encrypted describes the APFS target, not the separate DMG envelope.
func VolumeConversionTarget(source schema.CaseRef) (volume, target string, encrypted bool, err error) {
	if !schema.IsSupportedProducer(source.Producer) || source.Profile != "apfs" && source.Profile != "apfsx" {
		return "", "", false, fmt.Errorf("unsupported native volume conversion source")
	}
	switch source.Recipe {
	case "encrypted-volumes":
		switch source.Stage {
		case "password-changed":
			return "Peer", "converted", true, nil
		case "converted":
			return "Peer", "decrypted", false, nil
		}
	case "encrypted-snapshot-history":
		switch source.Stage {
		case "retained-again", "aes128-nested", "aes256-nested":
			return "EncryptedHistory", "decrypted", false, nil
		case "decrypted":
			return "EncryptedHistory", "converted", true, nil
		}
	}
	return "", "", false, fmt.Errorf("unqualified native volume conversion journey")
}

func validateVolumeConversionOutput(out schema.Output) (bool, error) {
	volume, target, encrypted, err := VolumeConversionTarget(out.Source)
	if err != nil {
		return false, err
	}
	outer := strings.HasPrefix(out.Source.Stage, "aes")
	password := ""
	if outer {
		password = "encrypted-snapshot-history.image"
	}
	want := schema.Expectation{View: target, Volume: volume, Continuation: true}
	if out.Operation != "convert-volume" || out.Format != "UDZO" || out.Encrypted != outer || out.Password != password || out.HostInput != nil || !expectationsEqual(out.Expect, want) {
		return false, fmt.Errorf("volume conversion %s lost its strict native transition/preservation contract", out.Name)
	}
	return encrypted, nil
}

func requireVolumeConversionOutputs(pairs []Paired, cases map[string]corpus.Case, major int) error {
	counts := map[string]int{}
	for _, pair := range pairs {
		out := pair.Output
		if out.Operation != "convert-volume" {
			continue
		}
		if _, err := validateVolumeConversionOutput(out); err != nil {
			return err
		}
		counts[CaseKey(out.Source)]++
	}
	for recipe, stages := range map[string][]string{"encrypted-volumes": {"password-changed", "converted"}, "encrypted-snapshot-history": {"retained-again", "aes128-nested", "aes256-nested", "decrypted"}} {
		for _, profile := range []string{"apfs", "apfsx"} {
			for _, stage := range stages {
				ref := schema.CaseRef{Producer: major, Recipe: recipe, Profile: profile, Stage: stage}
				_, target, _, err := VolumeConversionTarget(ref)
				if err != nil {
					return err
				}
				after := ref
				after.Stage = target
				if _, ok := cases[CaseKey(ref)]; !ok {
					return fmt.Errorf("missing original volume conversion source %s", CaseKey(ref))
				}
				if _, ok := cases[CaseKey(after)]; !ok {
					return fmt.Errorf("missing original volume conversion target %s", CaseKey(after))
				}
				if counts[CaseKey(ref)] != 1 {
					return fmt.Errorf("volume conversion %s requires exactly one continued output", CaseKey(ref))
				}
			}
		}
	}
	return nil
}

func conversionExtentPaths(source *schema.Observation) []string {
	var result []string
	seen := map[string]bool{}
	for _, view := range source.Views {
		for _, entry := range view.Entries {
			if entry.Extents != nil && !seen[entry.Path] {
				result = append(result, entry.Path)
				seen[entry.Path] = true
			}
		}
	}
	return result
}

func checkConvertedSharing(got, want *schema.Observation) error {
	for _, expected := range want.Views {
		volume := want.Volumes[expected.Volume]
		actualVolume, err := namedVolume(got, volumeName(volume))
		if err != nil {
			return err
		}
		actual, err := observedView(got, actualVolume.Index, expected.Snapshot)
		if err != nil {
			return err
		}
		entries := map[string]schema.Entry{}
		for _, entry := range actual.Entries {
			entries[entry.Path] = entry
		}
		for _, a := range expected.Entries {
			if a.Extents == nil {
				continue
			}
			x, ok := entries[a.Path]
			if !ok || x.Extents == nil {
				return fmt.Errorf("conversion omitted native extent evidence for %s:%s", expected.Snapshot, a.Path)
			}
			for _, b := range expected.Entries {
				if a.Path >= b.Path || b.Extents == nil {
					continue
				}
				y, ok := entries[b.Path]
				if !ok || y.Extents == nil {
					return fmt.Errorf("conversion omitted native extent evidence for %s:%s", expected.Snapshot, b.Path)
				}
				if sharedPhysicalBytes(a.Extents.Data, b.Extents.Data) != sharedPhysicalBytes(x.Extents.Data, y.Extents.Data) || sharedPhysicalBytes(a.Extents.Resource, b.Extents.Resource) != sharedPhysicalBytes(x.Extents.Resource, y.Extents.Resource) {
					return fmt.Errorf("conversion changed native data/fork sharing in %s:%s/%s", expected.Snapshot, a.Path, b.Path)
				}
			}
		}
	}
	return nil
}
