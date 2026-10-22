package native

import (
	"context"
	"fmt"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func (v *Verifier) checkReplacedImagePassword(ctx context.Context, p Paired, image string) error {
	out := p.Output
	if out.Operation != "edit" || out.Source.Recipe != "encrypted-image-edits" || !out.Encrypted || out.Password != "output" {
		return nil
	}
	source, ok := v.Cases[CaseKey(out.Source)]
	if !ok || source.Observation == nil || source.Observation.Image.Encryption == nil {
		return fmt.Errorf("rekeyed image lacks its native source credentials")
	}
	recipe, ok := v.Recipes[out.Source.Recipe]
	if !ok {
		return fmt.Errorf("rekeyed image lacks its native credential recipe")
	}
	old, ok := recipe.Passwords[source.Observation.Image.Encryption.Password]
	if !ok {
		return fmt.Errorf("rekeyed image has an unknown source password reference")
	}
	current, ok := p.Passwords[out.Password]
	if !ok || current == old {
		return fmt.Errorf("rekeyed image does not declare a distinct replacement credential")
	}
	_, err := v.Disk.Imageinfo(ctx, image, []byte(old))
	if err == nil {
		return fmt.Errorf("native reader opened a rekeyed output with the replaced image password")
	}
	// This is the retained hdiutil diagnostic for rejected image credentials.
	// I/O, privilege, tool-launch and metadata failures do not prove rejection.
	if !strings.Contains(err.Error(), "imageinfo failed - Authentication error") {
		return fmt.Errorf("native old-password check failed unexpectedly: %w", err)
	}
	return nil
}

// checkEncryptedEditPolicy compares Apple's measured output encryption with
// the captured native source policy independently of the product's report.
func (v *Verifier) checkEncryptedEditPolicy(out schema.Output, observed *schema.Observation) error {
	if out.Operation != "edit" || out.Source.Recipe != "encrypted-image-edits" {
		return nil
	}
	if observed == nil {
		return fmt.Errorf("encrypted edit has no native output observation")
	}
	if !out.Encrypted {
		properties, ok := observed.Image.Imageinfo["Properties"].(map[string]any)
		if !ok || properties["Encrypted"] != false {
			return fmt.Errorf("explicit envelope removal did not produce a native plaintext image")
		}
		return nil
	}
	source, ok := v.Cases[CaseKey(out.Source)]
	if !ok || source.Observation == nil || source.Observation.Image.Encryption == nil {
		return fmt.Errorf("encrypted edit has no native source encryption policy")
	}
	want, err := nativeImageCipher(source.Observation.Image.Imageinfo)
	if err != nil {
		return fmt.Errorf("native encrypted source policy: %w", err)
	}
	if want != source.Observation.Image.Encryption.Cipher {
		return fmt.Errorf("captured source cipher disagrees with native imageinfo")
	}
	got, err := nativeImageCipher(observed.Image.Imageinfo)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("encrypted edit changed native image cipher from %s to %s", want, got)
	}
	return nil
}

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
