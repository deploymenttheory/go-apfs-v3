package native

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
)

// requireEncryptedEditOutputs prevents an entire host cohort from silently
// omitting a filesystem, source cipher, encoding or encryption policy.
func requireEncryptedEditOutputs(pairs []Paired, cases map[string]corpus.Case, major int) error {
	profiles := []string{"apfs", "apfsx", "hfsplus", "hfsx"}
	ciphers := []string{"aes128", "aes256"}
	for _, profile := range profiles {
		for _, stage := range []string{"before", "after", "before-aes128", "before-aes256", "after-aes128", "after-aes256"} {
			key := fmt.Sprintf("%d/encrypted-image-edits/%s/%s", major, profile, stage)
			if _, ok := cases[key]; !ok {
				return fmt.Errorf("missing native encrypted-edit control %s", key)
			}
		}
	}
	type outputKey struct{ profile, source, policy, format string }
	wanted := map[outputKey]bool{}
	for _, profile := range profiles {
		for _, cipher := range ciphers {
			for _, policy := range []string{"preserve", "rekey", "remove"} {
				for _, format := range []string{"UDRO", "UDZO"} {
					wanted[outputKey{profile, "before-" + cipher, policy, format}] = false
				}
			}
		}
	}
	for _, pair := range pairs {
		out := pair.Output
		if out.Source.Producer != major || out.Source.Recipe != "encrypted-image-edits" || out.Operation != "edit" {
			continue
		}
		policy := "remove"
		if out.Encrypted {
			switch out.Password {
			case "encrypted-image-edits.image":
				policy = "preserve"
			case "output":
				policy = "rekey"
			default:
				return fmt.Errorf("encrypted edit %s has an unknown password policy", out.Name)
			}
		} else if out.Password != "" {
			return fmt.Errorf("plaintext edit %s retains an image-password reference", out.Name)
		}
		key := outputKey{out.Source.Profile, out.Source.Stage, policy, out.Format}
		seen, exists := wanted[key]
		if !exists || seen {
			return fmt.Errorf("unexpected or duplicated encrypted edit %s: %+v", out.Name, key)
		}
		view := "after-aes128"
		if out.Source.Stage == "before-aes256" {
			view = "after-aes256"
		}
		if out.Expect.View != view || !out.Expect.NewIdentities || len(out.Expect.IgnoreTimes) != 0 {
			return fmt.Errorf("encrypted edit %s lost its native after-state or strict preservation expectation", out.Name)
		}
		if policy == "preserve" && out.Format == "UDZO" && !out.Expect.Continuation {
			return fmt.Errorf("encrypted edit %s has no native/product/native continuation", out.Name)
		}
		wanted[key] = true
	}
	for key, seen := range wanted {
		if !seen {
			return fmt.Errorf("missing encrypted edit for macOS %d: %+v", major, key)
		}
	}
	return nil
}
