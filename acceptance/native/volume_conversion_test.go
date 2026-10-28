package native

import (
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestVolumeConversionRequiresAnExactNativePreservationContract(t *testing.T) {
	source := schema.CaseRef{Producer: 26, Recipe: "encrypted-snapshot-history", Profile: "apfs", Stage: "decrypted"}
	valid := schema.Output{Name: "converted", Operation: "convert-volume", Format: "UDZO", Source: source, Expect: schema.Expectation{View: "converted", Volume: "EncryptedHistory", Continuation: true}}
	if randomized, err := validateVolumeConversionOutput(valid); err != nil || !randomized {
		t.Fatal("native encryption contract rejected", err)
	}
	for _, change := range []func(*schema.Output){
		func(o *schema.Output) { o.Source.Stage = "final" },
		func(o *schema.Output) { o.Expect.NewIdentities = true },
		func(o *schema.Output) { o.Expect.IgnoreTimes = []string{"change"} },
		func(o *schema.Output) { o.Expect.Continuation = false },
		func(o *schema.Output) { o.Expect.View = "retained" },
		func(o *schema.Output) { o.Expect.Volume = "Peer" },
		func(o *schema.Output) { o.Source.Producer = 15 },
		func(o *schema.Output) { o.Operation = "build" },
	} {
		out := valid
		change(&out)
		if _, err := validateVolumeConversionOutput(out); err == nil {
			t.Fatal("unqualified randomized/preservation exception accepted", out)
		}
	}
	if err := requireVolumeConversionOutputs(nil, nil, 26); err == nil {
		t.Fatal("missing conversion outputs passed")
	}
}
