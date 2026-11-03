package native

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func nativeEncryptedOutputPolicy() (*Verifier, Paired, *schema.Observation) {
	ref := schema.CaseRef{Producer: 15, Recipe: "encrypted-image-edits", Profile: "apfs", Stage: "before-aes256"}
	source := &schema.Observation{Image: schema.Image{Encryption: &schema.ImageEncryption{Cipher: "AES-256", Password: "image"}, Imageinfo: encryptedImageInfo("AES-256")}}
	v := &Verifier{Cases: map[string]corpus.Case{CaseKey(ref): {Observation: source}}, Recipes: map[string]schema.Recipe{ref.Recipe: {Passwords: map[string]string{"image": "original public fixture password"}}}}
	p := Paired{Output: schema.Output{Operation: "edit", Encrypted: true, Password: "output", Source: ref}, Passwords: map[string]string{"output": "replacement public fixture password"}}
	return v, p, &schema.Observation{Image: schema.Image{Imageinfo: encryptedImageInfo("AES-256")}}
}

func TestEncryptedEditPolicyUsesApplesMeasuredSourceAndOutputCipher(t *testing.T) {
	for _, operation := range []string{"edit", "convert-volume", "delete-snapshot"} {
		t.Run(operation, func(t *testing.T) {
			v, p, observed := nativeEncryptedOutputPolicy()
			p.Output.Operation = operation
			if err := v.checkEncryptedEditPolicy(p.Output, observed); err != nil {
				t.Fatal(err)
			}
			observed.Image.Imageinfo = encryptedImageInfo("AES-128")
			if err := v.checkEncryptedEditPolicy(p.Output, observed); err == nil {
				t.Fatal("native cipher downgrade passed despite product policy")
			}
			p.Output.Encrypted, p.Output.Password = false, ""
			if err := v.checkEncryptedEditPolicy(p.Output, observed); err == nil {
				t.Fatal("explicit decryption accepted a still-encrypted image")
			}
			observed.Image.Imageinfo = map[string]any{"Properties": map[string]any{"Encrypted": false}}
			if err := v.checkEncryptedEditPolicy(p.Output, observed); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRekeyedOutputRequiresNativeAuthenticationRejectionOfTheOldPassword(t *testing.T) {
	v, p, _ := nativeEncryptedOutputPolicy()
	disk := &envelopeDisk{}
	v.Disk = disk
	for _, nativeErr := range []error{nil, errors.New("disk I/O failed"), errors.New("Insufficient privileges (-69863)")} {
		disk.infoErr = nativeErr
		if err := v.checkReplacedImagePassword(context.Background(), p, "output.dmg"); err == nil {
			t.Fatal("old-password acceptance or unrelated native failure passed", nativeErr)
		}
	}
	disk.infoErr = errors.New("hdiutil: imageinfo failed - Authentication error")
	if err := v.checkReplacedImagePassword(context.Background(), p, "output.dmg"); err != nil {
		t.Fatal(err)
	}
	if string(disk.password) != "original public fixture password" {
		t.Fatal("native check did not use the replaced source credential")
	}
}

func encryptedEditInventory() ([]Paired, map[string]corpus.Case) {
	cases := map[string]corpus.Case{}
	var pairs []Paired
	for _, profile := range []string{"apfs", "apfsx", "hfsplus", "hfsx"} {
		for _, stage := range []string{"before", "after", "before-aes128", "before-aes256", "after-aes128", "after-aes256"} {
			key := fmt.Sprintf("15/encrypted-image-edits/%s/%s", profile, stage)
			cases[key] = corpus.Case{Producer: 15, Recipe: "encrypted-image-edits", Profile: profile, Stage: stage}
		}
		for _, cipher := range []string{"aes128", "aes256"} {
			for _, policy := range []string{"preserve", "rekey", "remove"} {
				for _, format := range []string{"UDRO", "UDZO"} {
					out := schema.Output{
						Name: fmt.Sprint(profile, cipher, policy, format), Operation: "edit", Format: format,
						Source: schema.CaseRef{Producer: 15, Recipe: "encrypted-image-edits", Profile: profile, Stage: "before-" + cipher},
						Expect: schema.Expectation{View: "after-" + cipher, NewIdentities: true, Continuation: policy == "preserve" && format == "UDZO"},
					}
					switch policy {
					case "preserve":
						out.Encrypted, out.Password = true, "encrypted-image-edits.image"
					case "rekey":
						out.Encrypted, out.Password = true, "output"
					}
					pairs = append(pairs, Paired{Output: out})
				}
			}
		}
	}
	return pairs, cases
}

func TestEncryptedEditsRequireAllNativeControlsAndOutputPolicies(t *testing.T) {
	pairs, cases := encryptedEditInventory()
	if err := requireEncryptedEditOutputs(pairs, cases, 15); err != nil {
		t.Fatal(err)
	}
	for i := range pairs {
		remaining := append(append([]Paired(nil), pairs[:i]...), pairs[i+1:]...)
		if err := requireEncryptedEditOutputs(remaining, cases, 15); err == nil {
			t.Fatal("missing output passed", pairs[i].Output.Name)
		}
	}
	delete(cases, "15/encrypted-image-edits/hfsx/after-aes256")
	if err := requireEncryptedEditOutputs(pairs, cases, 15); err == nil {
		t.Fatal("missing native reference passed")
	}
}

func TestEncryptedEditsCannotWeakenPreservationOrOmitContinuation(t *testing.T) {
	for _, corrupt := range []func(*schema.Output){
		func(out *schema.Output) { out.Expect.Continuation = false },
		func(out *schema.Output) { out.Expect.IgnoreTimes = []string{"change"} },
		func(out *schema.Output) { out.Expect.NewIdentities = false },
		func(out *schema.Output) { out.Expect.View = "before-aes128" },
	} {
		pairs, cases := encryptedEditInventory()
		corrupt(&pairs[1].Output) // first preserve UDZO output
		if err := requireEncryptedEditOutputs(pairs, cases, 15); err == nil {
			t.Fatal("weakened encryption qualification passed")
		}
	}
	pairs, cases := encryptedEditInventory()
	pairs = append(pairs, pairs[0])
	if err := requireEncryptedEditOutputs(pairs, cases, 15); err == nil {
		t.Fatal("duplicated output passed")
	}
}
