package native

import (
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestRandomPasswordKeybagsCannotRelaxUnrelatedOutputDeterminism(t *testing.T) {
	original := schema.Output{Name: "password-changed.dmg", File: "password-changed.dmg", Operation: "change-password", Format: "UDZO", SHA256: "first", Source: schema.CaseRef{Producer: 26, Recipe: "encrypted-snapshot-history", Profile: "apfs", Stage: "final"}, Expect: schema.Expectation{View: "password-changed", Volume: "EncryptedHistory", Continuation: true}}
	pair := func(output schema.Output, same bool) error {
		first := HostOutputs{Manifest: schema.Outputs{Lock: "original-lock", Outputs: []schema.Output{output}}}
		if !same {
			output.SHA256 = "different"
		}
		second := HostOutputs{Manifest: schema.Outputs{Lock: "original-lock", Outputs: []schema.Output{output}}}
		_, err := Pair(map[string]HostOutputs{"linux": first, "windows": second})
		return err
	}
	if err := pair(original, false); err != nil {
		t.Fatal(err)
	}
	if err := pair(original, true); err == nil || !strings.Contains(err.Error(), "reused random keybag") {
		t.Fatal("identical password outputs accepted", err)
	}
	for _, change := range []func(*schema.Output){
		func(o *schema.Output) { o.Source.Recipe = "file-corpus" },
		func(o *schema.Output) { o.Source.Stage = "retained" },
		func(o *schema.Output) { o.Expect.Continuation = false },
		func(o *schema.Output) { o.Expect.ContinuationRefusal = "unsupported feature" },
		func(o *schema.Output) { o.Encrypted = true },
		func(o *schema.Output) { o.Expect.IgnoreTimes = []string{"change"} },
	} {
		output := original
		change(&output)
		if err := pair(output, false); err == nil {
			t.Fatal("unqualified random keybag exception accepted", output)
		}
	}
	original.Operation = "edit"
	if err := pair(original, false); err == nil || !strings.Contains(err.Error(), "plaintext bytes differ") {
		t.Fatal("ordinary encrypted volume edits lost device determinism", err)
	}
}

func TestEncryptedVolumeQualificationRequiresRetainedNativeControls(t *testing.T) {
	if err := requireEncryptedVolumeOutputs(nil, nil, 26); err == nil {
		t.Fatal("all encrypted history outputs could be omitted")
	}
}
