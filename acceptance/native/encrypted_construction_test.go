package native

import (
	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"testing"
)

func encryptedConstructionOutput(profile, cipher string) schema.Output {
	password := ""
	if cipher != "" {
		password = "encrypted-construction.image"
	}
	return schema.Output{Name: "constructed", Operation: "create-encrypted", Source: schema.CaseRef{Producer: 26, Recipe: "encrypted-volumes", Profile: profile, Stage: "clone-shared"}, Format: "UDZO", Encrypted: cipher != "", Password: password, Expect: schema.Expectation{Subtree: "Fixture", Volume: "Primary", Continuation: true, Container: &schema.ContainerExpectation{CapacityBytes: 1536 << 20, EmptyVolumes: []string{"Fresh Encrypted Peer"}, EncryptedVolumes: map[string]string{"Primary": "primary", "Fresh Encrypted Peer": "peer"}, ImageCipher: cipher}}}
}
func TestEncryptedConstructionRequiresEveryQualifiedProfileAndEnvelope(t *testing.T) {
	var pairs []Paired
	cases := map[string]corpus.Case{}
	for _, profile := range []string{"apfs", "apfsx"} {
		ref := schema.CaseRef{Producer: 26, Recipe: "encrypted-volumes", Profile: profile, Stage: "encrypted-peer"}
		cases[CaseKey(ref)] = corpus.Case{Observation: &schema.Observation{Volumes: make([]schema.Volume, 3)}}
		for _, cipher := range []string{"", "AES-128", "AES-256"} {
			pairs = append(pairs, Paired{Output: encryptedConstructionOutput(profile, cipher)})
		}
	}
	if err := requireEncryptedConstruction(pairs, cases, 26); err != nil {
		t.Fatal(err)
	}
	if err := requireEncryptedConstruction(pairs[1:], cases, 26); err == nil {
		t.Fatal("missing encrypted construction was accepted")
	}
	for _, change := range []func(*schema.Output){
		func(o *schema.Output) { o.Source.Recipe = "arbitrary" },
		func(o *schema.Output) { o.Expect.Continuation = false },
		func(o *schema.Output) { o.Expect.Container.EncryptedVolumes["Peer"] = "primary" },
		func(o *schema.Output) { o.Expect.Container.ImageCipher = "unknown" },
	} {
		output := encryptedConstructionOutput("apfs", "")
		change(&output)
		if err := validateEncryptedConstruction(output); err == nil {
			t.Fatal("unqualified randomized construction was admitted")
		}
	}
}
