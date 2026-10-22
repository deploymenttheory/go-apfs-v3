package native

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func cloneObservation(t *testing.T, original *schema.Observation) *schema.Observation {
	t.Helper()
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var copy schema.Observation
	if err := json.Unmarshal(b, &copy); err != nil {
		t.Fatal(err)
	}
	return &copy
}

// These hand-built tool transcripts test the independent verifier; acceptance
// expectations themselves always come from the immutable Apple captures.
func containerObservation(fresh bool) *schema.Observation {
	obs := &schema.Observation{Image: schema.Image{DiskBytes: 1600 << 20}}
	seed, prefix := 1, "Fixture/"
	if fresh {
		seed, prefix = 2, ""
	}
	for index, name := range []string{"Reserved", "Limited"} {
		obs.Volumes = append(obs.Volumes, schema.Volume{Index: index, Diskutil: map[string]any{"VolumeName": name}, APFS: &schema.APFSVolume{VolumeUUID: fmt.Sprintf("10000000-0000-0000-0000-%012d", seed*10+index), ContainerUUID: fmt.Sprintf("20000000-0000-0000-0000-%012d", seed)}})
		obs.Views = append(obs.Views, schema.View{Volume: index, Entries: []schema.Entry{entry(prefix+"data", uint64(seed*100+index))}})
	}
	if fresh {
		obs.Volumes = append(obs.Volumes, schema.Volume{Index: 2, Diskutil: map[string]any{"VolumeName": "Fresh Empty"}, APFS: &schema.APFSVolume{VolumeUUID: "10000000-0000-0000-0000-000000000023", ContainerUUID: "20000000-0000-0000-0000-000000000002"}})
		obs.Views = append(obs.Views, schema.View{Volume: 2})
	}
	bindInventory(obs)
	return obs
}

func bindInventory(obs *schema.Observation) {
	var volumes strings.Builder
	for _, v := range obs.Volumes {
		fmt.Fprintf(&volumes, "<dict><key>APFSVolumeUUID</key><string>%s</string><key>Name</key><string>%s</string><key>Roles</key><array>", v.APFS.VolumeUUID, volumeName(v))
		if v.APFS.Role != "" {
			fmt.Fprintf(&volumes, "<string>%s</string>", v.APFS.Role)
		}
		fmt.Fprintf(&volumes, "</array><key>CapacityReserve</key><integer>%d</integer><key>CapacityQuota</key><integer>%d</integer></dict>", v.APFS.ReserveBytes, v.APFS.QuotaBytes)
	}
	text := fmt.Sprintf("<plist><dict><key>Containers</key><array><dict><key>APFSContainerUUID</key><string>%s</string><key>Volumes</key><array>%s</array></dict></array></dict></plist>", obs.Volumes[0].APFS.ContainerUUID, volumes.String())
	obs.Commands = []schema.Command{{Argv: []string{"diskutil", "apfs", "list", "-plist"}, Status: "0", StdoutText: text}}
}

func TestContainerVerdictRequiresAllContentsAndNativeMetadata(t *testing.T) {
	source, output := containerObservation(false), containerObservation(true)
	out := schema.Output{Operation: "container", Expect: schema.Expectation{Subtree: "Fixture", Container: &schema.ContainerExpectation{CapacityBytes: 1600 << 20, EmptyVolumes: []string{"Fresh Empty"}}}}
	v := &Verifier{}
	check := func(got *schema.Observation) ([]Difference, error) {
		return v.compareConstructedContainer(got, corpus.Case{Observation: source}, out)
	}
	if d, err := check(output); err != nil || len(d) != 0 {
		t.Fatalf("complete native inventory failed: %v %v", d, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*schema.Observation)
	}{
		{"second volume data changed", func(o *schema.Observation) { o.Views[1].Entries[0].SHA256 = "wrong" }},
		{"second volume clock changed", func(o *schema.Observation) { o.Views[1].Entries[0].Times.Change++ }},
		{"missing second volume", func(o *schema.Observation) { o.Volumes = append(o.Volumes[:1], o.Volumes[2:]...) }},
		{"empty volume gained data", func(o *schema.Observation) { o.Views[2].Entries = []schema.Entry{entry("unexpected", 999)} }},
		{"quota lost", func(o *schema.Observation) { o.Volumes[1].APFS.QuotaBytes = 1 << 20 }},
		{"case policy lost", func(o *schema.Observation) { o.Volumes[1].APFS.CaseSensitive = true }},
		{"unexpected role", func(o *schema.Observation) { o.Volumes[1].APFS.Role = "Data" }},
		{"unexpected group", func(o *schema.Observation) { o.Volumes[1].APFS.GroupUUID = o.Volumes[1].APFS.VolumeUUID }},
		{"source identity reused", func(o *schema.Observation) { o.Volumes[1].APFS.VolumeUUID = source.Volumes[1].APFS.VolumeUUID }},
		{"wrong capacity", func(o *schema.Observation) { o.Image.DiskBytes-- }},
		{"unexpected snapshot", func(o *schema.Observation) { o.Views = append(o.Views, schema.View{Volume: 0, Snapshot: "old"}) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cloneObservation(t, output)
			tc.change(got)
			bindInventory(got)
			if d, err := check(got); err == nil && len(d) == 0 {
				t.Fatal("damaged container escaped native verdict")
			}
		})
	}
}

func TestContainerOutputsCannotDisappearOrChangeExpectations(t *testing.T) {
	cases := map[string]corpus.Case{}
	var pairs []Paired
	for _, recipe := range []string{"container-volumes", "volume-groups"} {
		ref := schema.CaseRef{Producer: 15, Recipe: recipe, Profile: "apfs", Stage: "final"}
		cases[CaseKey(ref)] = corpus.Case{Observation: containerObservation(false)}
		for _, format := range []string{"UDRO", "UDZO"} {
			expect := schema.Expectation{Subtree: "Fixture", Volume: "Reserved", Continuation: format == "UDZO", Container: &schema.ContainerExpectation{CapacityBytes: 1600 << 20, EmptyVolumes: []string{"Fresh Empty"}}}
			if recipe == "volume-groups" {
				expect.Volume, expect.SystemMember = "", "System"
				expect.Container.CapacityBytes, expect.Container.EmptyVolumes = 768<<20, nil
				if expect.Continuation {
					expect.ContinuationRefusal = "APFS volume mutation profile: unsupported feature"
				}
			}
			pairs = append(pairs, Paired{Output: schema.Output{Operation: "container", Source: ref, Format: format, Expect: expect}})
		}
	}
	if err := requireContainerOutputs(pairs, cases, 15); err != nil {
		t.Fatal(err)
	}
	if err := requireContainerOutputs(pairs[:3], cases, 15); err == nil {
		t.Fatal("all-host output omission escaped verification")
	}
	withoutContinuation := append([]Paired(nil), pairs...)
	withoutContinuation[3].Output.Expect.Continuation = false
	if err := requireContainerOutputs(withoutContinuation, cases, 15); err == nil {
		t.Fatal("all-host System allocation omission escaped verification")
	}
	a := schema.Expectation{Container: &schema.ContainerExpectation{CapacityBytes: 1600 << 20}}
	b := schema.Expectation{Container: &schema.ContainerExpectation{CapacityBytes: 768 << 20}}
	if expectationsEqual(a, b) {
		t.Fatal("different container expectations paired across hosts")
	}
}
