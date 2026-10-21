package native

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func preservedMetadataObservation() *schema.Observation {
	obs := &schema.Observation{}
	for i, role := range []string{"Data", "System"} {
		obs.Volumes = append(obs.Volumes, schema.Volume{Index: i, Diskutil: map[string]any{"VolumeName": role}, APFS: &schema.APFSVolume{
			VolumeUUID: fmt.Sprintf("10000000-0000-4000-8000-%012d", i+1), ContainerUUID: "20000000-0000-4000-8000-000000000001", Role: role,
			GroupUUID: "30000000-0000-4000-8000-000000000001", ReserveBytes: 4096, QuotaBytes: 8192,
		}})
	}
	obs.Volumes[0].APFS.Snapshots = []schema.Snapshot{{Name: "retained", XID: 20, UUID: "40000000-0000-4000-8000-000000000001", CreatedNS: 30, ChangedNS: 40}}
	obs.Volumes = append(obs.Volumes, schema.Volume{Index: 2, Diskutil: map[string]any{
		"VolumeName": "HFS", "VolumeUUID": "50000000-0000-4000-8000-000000000001", "TotalSize": int64(128 << 20), "Size": int64(128 << 20), "VolumeAllocationBlockSize": int64(4096),
	}, HFS: &schema.HFSVolume{Journaled: true}})
	bindMetadataInventory(obs)
	return obs
}

func bindMetadataInventory(obs *schema.Observation) {
	var listed strings.Builder
	id := ""
	for _, volume := range obs.Volumes {
		if volume.APFS == nil {
			continue
		}
		id = volume.APFS.ContainerUUID
		fmt.Fprintf(&listed, "<dict><key>APFSVolumeUUID</key><string>%s</string><key>Name</key><string>%s</string><key>CapacityReserve</key><integer>%d</integer><key>CapacityQuota</key><integer>%d</integer><key>Roles</key><array><string>%s</string></array></dict>", volume.APFS.VolumeUUID, volume.Diskutil["VolumeName"], volume.APFS.ReserveBytes, volume.APFS.QuotaBytes, volume.APFS.Role)
	}
	text := fmt.Sprintf("<plist><dict><key>Containers</key><array><dict><key>APFSContainerUUID</key><string>%s</string><key>Volumes</key><array>%s</array></dict></array></dict></plist>", id, listed.String())
	setMetadataTranscript(obs, text)
}

func setMetadataTranscript(obs *schema.Observation, text string) {
	obs.Commands = []schema.Command{{Argv: []string{"diskutil", "apfs", "list", "-plist"}, Status: "0", StdoutText: text, StdoutSHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(text)))}}
}

func copyMetadataObservation(t *testing.T, obs *schema.Observation) *schema.Observation {
	t.Helper()
	data, err := json.Marshal(obs)
	if err != nil {
		t.Fatal(err)
	}
	var copied schema.Observation
	if err := json.Unmarshal(data, &copied); err != nil {
		t.Fatal(err)
	}
	return &copied
}

func TestPreservedVolumeMetadataRequiresNativePoliciesAndSnapshotIdentities(t *testing.T) {
	want := preservedMetadataObservation()
	for _, tc := range []struct {
		name   string
		change func(*schema.Observation)
	}{
		{"APFS volume identity", func(o *schema.Observation) { o.Volumes[0].APFS.VolumeUUID = "10000000-0000-4000-8000-000000000099" }},
		{"APFS container identity", func(o *schema.Observation) {
			for i := 0; i < 2; i++ {
				o.Volumes[i].APFS.ContainerUUID = "20000000-0000-4000-8000-000000000099"
			}
		}},
		{"System role lost", func(o *schema.Observation) { o.Volumes[1].APFS.Role = "Data" }},
		{"group relationship lost", func(o *schema.Observation) { o.Volumes[1].APFS.GroupUUID = "" }},
		{"case policy", func(o *schema.Observation) { o.Volumes[0].APFS.CaseSensitive = true }},
		{"reservation", func(o *schema.Observation) { o.Volumes[0].APFS.ReserveBytes++ }},
		{"quota", func(o *schema.Observation) { o.Volumes[0].APFS.QuotaBytes++ }},
		{"encryption", func(o *schema.Observation) { o.Volumes[0].APFS.Encrypted = true }},
		{"encryption rolled flag", func(o *schema.Observation) { o.Volumes[0].APFS.EncRolled = true }},
		{"snapshot removed", func(o *schema.Observation) { o.Volumes[0].APFS.Snapshots = nil }},
		{"snapshot added", func(o *schema.Observation) {
			o.Volumes[0].APFS.Snapshots = append(o.Volumes[0].APFS.Snapshots, schema.Snapshot{Name: "extra", XID: 21})
		}},
		{"snapshot renamed", func(o *schema.Observation) { o.Volumes[0].APFS.Snapshots[0].Name = "Retained" }},
		{"snapshot XID", func(o *schema.Observation) { o.Volumes[0].APFS.Snapshots[0].XID++ }},
		{"snapshot UUID", func(o *schema.Observation) {
			o.Volumes[0].APFS.Snapshots[0].UUID = "40000000-0000-4000-8000-000000000099"
		}},
		{"snapshot creation clock", func(o *schema.Observation) { o.Volumes[0].APFS.Snapshots[0].CreatedNS++ }},
		{"snapshot change clock", func(o *schema.Observation) { o.Volumes[0].APFS.Snapshots[0].ChangedNS++ }},
		{"HFS identity", func(o *schema.Observation) {
			o.Volumes[2].Diskutil["VolumeUUID"] = "50000000-0000-4000-8000-000000000099"
		}},
		{"HFS case policy", func(o *schema.Observation) { o.Volumes[2].HFS.CaseSensitive = true }},
		{"HFS journal policy", func(o *schema.Observation) { o.Volumes[2].HFS.Journaled = false }},
		{"HFS size", func(o *schema.Observation) { o.Volumes[2].Diskutil["TotalSize"] = int64(64 << 20) }},
		{"HFS allocation block size", func(o *schema.Observation) { o.Volumes[2].Diskutil["VolumeAllocationBlockSize"] = int64(8192) }},
		{"missing HFS size", func(o *schema.Observation) { delete(o.Volumes[2].Diskutil, "Size") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := copyMetadataObservation(t, want)
			tc.change(got)
			bindMetadataInventory(got)
			if diffs, err := comparePreservedVolumeMetadata(got, want); err != nil || len(diffs) == 0 {
				t.Fatalf("changed metadata must produce a native difference: %v: %v", diffs, err)
			}
		})
	}
}

func TestPreservedMetadataUsesOriginalNativeInventoryWithoutChangingEvidence(t *testing.T) {
	want := preservedMetadataObservation()
	got := copyMetadataObservation(t, want)
	for _, obs := range []*schema.Observation{got, want} {
		for i := 0; i < 2; i++ {
			obs.Volumes[i].APFS.Role, obs.Volumes[i].APFS.ContainerUUID = "", ""
		}
	}
	before, _ := json.Marshal(want)
	if diffs, err := comparePreservedVolumeMetadata(got, want); err != nil || len(diffs) != 0 {
		t.Fatalf("matching historical metadata failed: %v %v", diffs, err)
	}
	for _, replacement := range [][2]string{
		{"<string>System</string></array>", "<string>Data</string></array>"},
		{"20000000-0000-4000-8000-000000000001", "20000000-0000-4000-8000-000000000099"},
	} {
		changed := copyMetadataObservation(t, got)
		setMetadataTranscript(changed, strings.ReplaceAll(changed.Commands[0].StdoutText, replacement[0], replacement[1]))
		if diffs, err := comparePreservedVolumeMetadata(changed, want); err != nil || len(diffs) == 0 {
			t.Fatalf("changed original native listing escaped metadata verdict: %v %v", diffs, err)
		}
	}
	after, _ := json.Marshal(want)
	if string(before) != string(after) {
		t.Fatal("metadata projection rewrote retained evidence")
	}
}

func TestPreservedMetadataRejectsAmbiguousInventoriesAndAcceptsReordering(t *testing.T) {
	want := preservedMetadataObservation()
	for _, tc := range []struct {
		name   string
		change func(*schema.Observation)
	}{
		{"missing volume", func(o *schema.Observation) { o.Volumes = o.Volumes[:2] }},
		{"duplicate name", func(o *schema.Observation) { o.Volumes[2].Diskutil["VolumeName"] = "Data" }},
		{"missing name", func(o *schema.Observation) { delete(o.Volumes[2].Diskutil, "VolumeName") }},
		{"missing native transcript", func(o *schema.Observation) { o.Commands = nil }},
		{"duplicate snapshot", func(o *schema.Observation) {
			o.Volumes[0].APFS.Snapshots = append(o.Volumes[0].APFS.Snapshots, o.Volumes[0].APFS.Snapshots[0])
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := copyMetadataObservation(t, want)
			tc.change(got)
			if _, err := comparePreservedVolumeMetadata(got, want); err == nil {
				t.Fatal("ambiguous preserved metadata was accepted")
			}
		})
	}
	got := copyMetadataObservation(t, want)
	got.Volumes[0], got.Volumes[2] = got.Volumes[2], got.Volumes[0]
	got.Volumes[0].Index, got.Volumes[2].Index = 0, 2
	got.Volumes[1].FreeBytes++
	got.Volumes[0].HFS.JournalSHA256 = "journal contents may change"
	got.Volumes[0].Diskutil["VolumeUUID"] = strings.ToLower(fmt.Sprint(got.Volumes[0].Diskutil["VolumeUUID"]))
	if diffs, err := comparePreservedVolumeMetadata(got, want); err != nil || len(diffs) != 0 {
		t.Fatalf("attachment order or mutable accounting changed the static verdict: %v %v", diffs, err)
	}
	// View-only controls have no recorded filesystem metadata to project.
	viewOnly := &schema.Observation{Volumes: []schema.Volume{{Diskutil: map[string]any{"VolumeName": "view-only"}}}}
	if diffs, err := comparePreservedVolumeMetadata(viewOnly, viewOnly); err != nil || len(diffs) != 0 {
		t.Fatalf("view-only control unexpectedly requires metadata: %v %v", diffs, err)
	}
}
