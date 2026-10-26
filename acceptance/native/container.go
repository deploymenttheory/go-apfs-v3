package native

import (
	"fmt"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// compareConstructedContainer checks the complete newly built inventory against
// Apple's retained volumes. Only identities are fresh; file clocks, hard links,
// content, attributes and group relationships remain independently asserted.
func (v *Verifier) compareConstructedContainer(got *schema.Observation, source corpus.Case, out schema.Output) ([]Difference, error) {
	expect := out.Expect.Container
	if expect == nil || (out.Operation != "container" && out.Operation != "create-encrypted") || out.Expect.Subtree != "Fixture" || expect.CapacityBytes <= 0 {
		return nil, fmt.Errorf("invalid fresh-container expectation")
	}
	wantVolumes, err := fixture.APFSInventory(source.Observation)
	if err != nil {
		return nil, fmt.Errorf("native source inventory: %w", err)
	}
	actualVolumes, err := fixture.APFSInventory(got)
	if err != nil {
		return nil, fmt.Errorf("constructed inventory: %w", err)
	}
	if len(actualVolumes) != len(wantVolumes)+len(expect.EmptyVolumes) || len(got.Views) != len(actualVolumes) {
		return nil, fmt.Errorf("constructed inventory: got %d volumes/%d views, want %d live volumes", len(actualVolumes), len(got.Views), len(wantVolumes)+len(expect.EmptyVolumes))
	}
	var diffs []Difference
	add := func(name, field string, actual, expected any) {
		g, w := fmt.Sprint(actual), fmt.Sprint(expected)
		if g != w {
			diffs = append(diffs, Difference{Path: name, Field: field, Got: g, Want: w})
		}
	}
	add("", "container.capacityBytes", got.Image.DiskBytes, expect.CapacityBytes)
	ids := map[string]bool{}
	sourceIDs := map[string]bool{}
	for _, volume := range wantVolumes {
		for _, id := range []string{volume.APFS.ContainerUUID, volume.APFS.VolumeUUID, volume.APFS.GroupUUID} {
			sourceIDs[strings.ToUpper(id)] = true
		}
	}
	actualByName := map[string]schema.Volume{}
	containerID := ""
	for _, volume := range actualVolumes {
		if volume.APFS == nil {
			return nil, fmt.Errorf("constructed volume %q is not APFS", volumeName(volume))
		}
		id := strings.ToUpper(volume.APFS.VolumeUUID)
		if id == "" || id == "00000000-0000-0000-0000-000000000000" || ids[id] || sourceIDs[id] {
			return nil, fmt.Errorf("constructed volume %q has empty or repeated UUID", volumeName(volume))
		}
		ids[id] = true
		actualByName[volumeName(volume)] = volume
		if containerID == "" {
			containerID = volume.APFS.ContainerUUID
		}
		if containerID == "" || !strings.EqualFold(containerID, volume.APFS.ContainerUUID) {
			return nil, fmt.Errorf("constructed volumes do not belong to one identified container")
		}
	}
	if sourceIDs[strings.ToUpper(containerID)] || ids[strings.ToUpper(containerID)] {
		return nil, fmt.Errorf("constructed container reused a filesystem identity")
	}
	for _, volume := range actualVolumes {
		group := strings.ToUpper(volume.APFS.GroupUUID)
		if group != "" && (group == "00000000-0000-0000-0000-000000000000" || sourceIDs[group] || ids[group] || strings.EqualFold(group, containerID)) {
			return nil, fmt.Errorf("constructed volume %q reused a group identity", volumeName(volume))
		}
	}
	seenNames := map[string]bool{}
	for _, expected := range wantVolumes {
		name := volumeName(expected)
		seenNames[name] = true
		actual, ok := actualByName[name]
		if !ok {
			return nil, fmt.Errorf("constructed volume %q is absent", name)
		}
		if expected.APFS == nil || actual.APFS == nil {
			return nil, fmt.Errorf("container source volume %q is not APFS", name)
		}
		if strings.EqualFold(actual.APFS.VolumeUUID, expected.APFS.VolumeUUID) || strings.EqualFold(actual.APFS.ContainerUUID, expected.APFS.ContainerUUID) {
			return nil, fmt.Errorf("constructed volume %q reused a source filesystem identity", name)
		}
		add(name, "volume.caseSensitive", actual.APFS.CaseSensitive, expected.APFS.CaseSensitive)
		add(name, "volume.role", actual.APFS.Role, expected.APFS.Role)
		add(name, "volume.reserveBytes", actual.APFS.ReserveBytes, expected.APFS.ReserveBytes)
		add(name, "volume.quotaBytes", actual.APFS.QuotaBytes, expected.APFS.QuotaBytes)
		add(name, "volume.encrypted", actual.APFS.Encrypted, expect.EncryptedVolumes[name] != "")
		add(name, "volume.snapshots", len(actual.APFS.Snapshots), 0)
		wantView, err := observedView(source.Observation, expected.Index, "")
		if err != nil {
			return nil, err
		}
		actualView, err := observedView(got, actual.Index, "")
		if err != nil {
			return nil, err
		}
		for _, difference := range CompareViews(actualView, wantView, CompareOptions{Subtree: out.Expect.Subtree, IgnoreIdentity: true}) {
			difference.Path = name + ":" + difference.Path
			diffs = append(diffs, difference)
		}
		if expected.APFS.Role == "System" {
			for _, actualEntry := range actualView.Entries {
				for _, expectedEntry := range wantView.Entries {
					if expectedEntry.Path == out.Expect.Subtree+"/"+actualEntry.Path {
						add(name+":"+actualEntry.Path, "identity.namespace", actualEntry.ID>>32, expectedEntry.ID>>32)
					}
				}
			}
		}
		for _, peer := range wantVolumes {
			other, err := namedVolume(got, volumeName(peer))
			if err != nil || other.APFS == nil {
				return nil, fmt.Errorf("missing APFS peer %q", volumeName(peer))
			}
			wantShared := expected.APFS.GroupUUID != "" && strings.EqualFold(expected.APFS.GroupUUID, peer.APFS.GroupUUID)
			gotShared := actual.APFS.GroupUUID != "" && strings.EqualFold(actual.APFS.GroupUUID, other.APFS.GroupUUID)
			add(name+":"+volumeName(peer), "volume.groupMembership", gotShared, wantShared)
		}
	}
	for _, name := range expect.EmptyVolumes {
		if name == "" || seenNames[name] {
			return nil, fmt.Errorf("invalid empty-volume declaration %q", name)
		}
		seenNames[name] = true
		volume, ok := actualByName[name]
		if !ok {
			return nil, fmt.Errorf("empty volume %q is absent", name)
		}
		view, err := observedView(got, volume.Index, "")
		if err != nil {
			return nil, err
		}
		add(name, "empty.entries", len(view.Entries), 0)
		add(name, "empty.caseSensitive", volume.APFS.CaseSensitive, out.Operation == "create-encrypted" && out.Source.Profile == "apfsx")
		add(name, "empty.role", volume.APFS.Role, "")
		add(name, "empty.groupUUID", volume.APFS.GroupUUID, "")
		add(name, "empty.reserveBytes", volume.APFS.ReserveBytes, 0)
		add(name, "empty.quotaBytes", volume.APFS.QuotaBytes, 0)
		add(name, "empty.encrypted", volume.APFS.Encrypted, expect.EncryptedVolumes[name] != "")
		add(name, "empty.snapshots", len(volume.APFS.Snapshots), 0)
	}
	// A relative signature path may occur on several source volumes. Each
	// occurrence needs its own successful native codesign verdict.
	expectedSignatures := map[string]int{}
	for _, volume := range wantVolumes {
		view, _ := observedView(source.Observation, volume.Index, "")
		for _, bundle := range out.Expect.Codesign {
			for _, e := range view.Entries {
				if e.Path == out.Expect.Subtree+"/"+bundle && e.Kind == "dir" {
					expectedSignatures[bundle]++
				}
			}
		}
	}
	for _, signature := range got.Checks.Codesign {
		if signature.Status != 0 || expectedSignatures[signature.Path] == 0 {
			return nil, fmt.Errorf("unexpected or failed codesign verdict for %q", signature.Path)
		}
		expectedSignatures[signature.Path]--
	}
	for bundle, remaining := range expectedSignatures {
		add(bundle, "codesign.missing", remaining, 0)
	}
	return diffs, nil
}

func requireContainerOutputs(pairs []Paired, cases map[string]corpus.Case, major int) error {
	produced := map[string]int{}
	for _, pair := range pairs {
		o := pair.Output
		if o.Operation == "create-encrypted" {
			if err := validateEncryptedConstruction(o); err != nil {
				return err
			}
			continue
		}
		if o.Operation != "container" && o.Expect.Container == nil {
			continue
		}
		if o.Operation != "container" || o.Expect.Container == nil || o.Expect.DiskSHA256 != "" || o.Expect.Workspace != nil || o.Expect.AppleDouble != nil {
			return fmt.Errorf("invalid container output %q", o.Name)
		}
		if o.Format != "UDRO" && o.Format != "UDZO" {
			return fmt.Errorf("unsupported container output format %q", o.Format)
		}
		if o.Expect.Subtree != "Fixture" || o.Encrypted || o.Expect.Continuation != (o.Format == "UDZO") {
			return fmt.Errorf("container output %q lost its build or continuation contract", o.Name)
		}
		switch o.Source.Recipe {
		case "container-volumes":
			if o.Expect.Volume != "Reserved" || o.Expect.Container.CapacityBytes != 1600<<20 || len(o.Expect.Container.EmptyVolumes) != 1 || o.Expect.Container.EmptyVolumes[0] != "Fresh Empty" || o.Expect.SystemMember != "" || o.Expect.ContinuationRefusal != "" {
				return fmt.Errorf("container output %q lost its quota/reservation/empty-volume contract", o.Name)
			}
		case "volume-groups":
			refusal := ""
			if o.Format == "UDZO" {
				refusal = "APFS volume mutation profile: unsupported feature"
			}
			if o.Expect.SystemMember != "System" || o.Expect.Container.CapacityBytes != 768<<20 || len(o.Expect.Container.EmptyVolumes) != 0 || o.Expect.ContinuationRefusal != refusal {
				return fmt.Errorf("container output %q lost its System allocation or role-refusal contract", o.Name)
			}
		default:
			return fmt.Errorf("unqualified container source %q", o.Source.Recipe)
		}
		produced[CaseKey(o.Source)+"/"+o.Format]++
	}
	for _, recipe := range []string{"container-volumes", "volume-groups"} {
		ref := schema.CaseRef{Producer: major, Recipe: recipe, Profile: "apfs", Stage: "final"}
		if k, ok := cases[CaseKey(ref)]; !ok || k.Observation == nil {
			return fmt.Errorf("missing native container control %s", CaseKey(ref))
		}
		for _, format := range []string{"UDRO", "UDZO"} {
			key := CaseKey(ref) + "/" + format
			if produced[key] != 1 {
				return fmt.Errorf("container %s: got %d outputs, want exactly one", key, produced[key])
			}
		}
	}
	return nil
}
