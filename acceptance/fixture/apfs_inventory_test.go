package fixture

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

const inventoryListing = `<plist version="1.0"><dict><key>Containers</key><array><dict>
<key>APFSContainerUUID</key><string>11111111-2222-4333-8444-555555555555</string>
<key>Volumes</key><array>
<dict><key>APFSVolumeUUID</key><string>aaaaaaaa-1111-4222-8333-444444444444</string><key>Name</key><string>Data</string><key>Roles</key><array><string>Data</string></array><key>CapacityReserve</key><integer>4096</integer><key>CapacityQuota</key><integer>8192</integer><key>Encryption</key><false/></dict>
<dict><key>APFSVolumeUUID</key><string>bbbbbbbb-1111-4222-8333-444444444444</string><key>Name</key><string>System</string><key>Roles</key><array><string>System</string></array><key>CapacityReserve</key><integer>0</integer><key>CapacityQuota</key><integer>0</integer><key>Encryption</key><false/></dict>
</array></dict></array></dict></plist>`

func observedAPFSInventory() *schema.Observation {
	obs := &schema.Observation{Volumes: []schema.Volume{
		{Index: 0, Diskutil: map[string]any{"VolumeName": "Data"}, APFS: &schema.APFSVolume{VolumeUUID: "AAAAAAAA-1111-4222-8333-444444444444", ReserveBytes: 4096, QuotaBytes: 8192}},
		{Index: 1, Diskutil: map[string]any{"VolumeName": "System"}, APFS: &schema.APFSVolume{VolumeUUID: "BBBBBBBB-1111-4222-8333-444444444444"}},
	}}
	setInventoryTranscript(obs, inventoryListing)
	return obs
}

func setInventoryTranscript(obs *schema.Observation, listing string) {
	sum := sha256.Sum256([]byte(listing))
	obs.Commands = []schema.Command{{Argv: []string{"diskutil", "apfs", "list", "-plist"}, Status: "0", StdoutText: listing, StdoutSHA256: fmt.Sprintf("%x", sum)}}
}

func TestAPFSInventoryRecoversNativeRolesWithoutChangingEvidence(t *testing.T) {
	obs := observedAPFSInventory()
	before, _ := json.Marshal(obs)
	got, err := APFSInventory(obs)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].APFS.Role != "Data" || got[1].APFS.Role != "System" || got[0].APFS.ContainerUUID != "11111111-2222-4333-8444-555555555555" || got[1].APFS.ContainerUUID != got[0].APFS.ContainerUUID {
		t.Fatalf("native inventory not restored: %+v", got)
	}
	got[0].APFS.Role = "changed copy"
	got[0].Diskutil["VolumeName"] = "changed copy"
	after, _ := json.Marshal(obs)
	if string(before) != string(after) {
		t.Fatal("historical evidence changed through enriched records")
	}
	// A newer listing from an unrelated container must not replace the final
	// source inventory. Failed commands cannot supply an expectation either.
	unrelated := observedAPFSInventory().Commands[0]
	unrelated.StdoutText = strings.ReplaceAll(inventoryListing, "aaaaaaaa-1111-4222-8333-444444444444", "cccccccc-1111-4222-8333-444444444444")
	unrelated.StdoutText = strings.ReplaceAll(unrelated.StdoutText, "bbbbbbbb-1111-4222-8333-444444444444", "dddddddd-1111-4222-8333-444444444444")
	unrelated.StdoutSHA256 = ""
	obs.Commands = append(obs.Commands, unrelated, schema.Command{Argv: unrelated.Argv, Status: "1", StdoutText: "failed output"})
	if _, err := APFSInventory(obs); err != nil {
		t.Fatal("unrelated later command:", err)
	}
}

func TestAPFSInventoryRejectsContradictoryNativeEvidence(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*schema.Observation)
	}{
		{"missing-listing", func(o *schema.Observation) { o.Commands = nil }},
		{"changed-transcript", func(o *schema.Observation) { o.Commands[0].StdoutText += " " }},
		{"truncated-xml", func(o *schema.Observation) { setInventoryTranscript(o, inventoryListing[:len(inventoryListing)-8]) }},
		{"missing-volume", func(o *schema.Observation) { o.Volumes = o.Volumes[:1] }},
		{"duplicate-observed-identity", func(o *schema.Observation) { o.Volumes[1].APFS.VolumeUUID = o.Volumes[0].APFS.VolumeUUID }},
		{"zero-observed-identity", func(o *schema.Observation) { o.Volumes[0].APFS.VolumeUUID = "00000000-0000-0000-0000-000000000000" }},
		{"changed-name", func(o *schema.Observation) { o.Volumes[0].Diskutil["VolumeName"] = "Other" }},
		{"changed-reserve", func(o *schema.Observation) { o.Volumes[0].APFS.ReserveBytes = 8192 }},
		{"changed-quota", func(o *schema.Observation) { o.Volumes[0].APFS.QuotaBytes = 4096 }},
		{"conflicting-role", func(o *schema.Observation) { o.Volumes[0].APFS.Role = "System" }},
		{"conflicting-container", func(o *schema.Observation) { o.Volumes[0].APFS.ContainerUUID = "22222222-2222-4333-8444-555555555555" }},
		{"duplicate-listing-identity", func(o *schema.Observation) {
			setInventoryTranscript(o, strings.ReplaceAll(inventoryListing, "bbbbbbbb-1111-4222-8333-444444444444", "aaaaaaaa-1111-4222-8333-444444444444"))
		}},
		{"missing-roles", func(o *schema.Observation) {
			setInventoryTranscript(o, strings.ReplaceAll(inventoryListing, "<key>Roles</key>", "<key>Unknown</key>"))
		}},
		{"duplicate-roles", func(o *schema.Observation) {
			setInventoryTranscript(o, strings.Replace(inventoryListing, "<string>Data</string></array>", "<string>Data</string><string>Data</string></array>", 1))
		}},
		{"duplicate-plist-key", func(o *schema.Observation) {
			setInventoryTranscript(o, strings.Replace(inventoryListing, "<key>Name</key>", "<key>CapacityQuota</key>", 1))
		}},
		{"unsupported-plist-value", func(o *schema.Observation) {
			setInventoryTranscript(o, strings.Replace(inventoryListing, "<integer>4096</integer>", "<real>4096</real>", 1))
		}},
		{"trailing-xml", func(o *schema.Observation) { setInventoryTranscript(o, inventoryListing+"<plist><dict/></plist>") }},
		{"nested-scalar", func(o *schema.Observation) {
			setInventoryTranscript(o, strings.Replace(inventoryListing, "<string>Data</string>", "<string><string>Data</string></string>", 1))
		}},
		{"oversized-listing", func(o *schema.Observation) { setInventoryTranscript(o, strings.Repeat(" ", 8<<20+1)) }},
		{"excessive-depth", func(o *schema.Observation) {
			setInventoryTranscript(o, "<plist><dict><key>Containers</key>"+strings.Repeat("<array>", 66)+strings.Repeat("</array>", 66)+"</dict></plist>")
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := observedAPFSInventory()
			tc.change(obs)
			if _, err := APFSInventory(obs); err == nil {
				t.Fatal("contradictory evidence supplied a native inventory")
			}
		})
	}
}
