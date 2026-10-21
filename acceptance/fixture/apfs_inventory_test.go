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
<key>ContainerReference</key><string>disk6</string>
<key>Volumes</key><array>
<dict><key>APFSVolumeUUID</key><string>aaaaaaaa-1111-4222-8333-444444444444</string><key>Name</key><string>Data</string><key>Roles</key><array><string>Data</string></array><key>CapacityReserve</key><integer>4096</integer><key>CapacityQuota</key><integer>8192</integer><key>Encryption</key><false/></dict>
<dict><key>APFSVolumeUUID</key><string>bbbbbbbb-1111-4222-8333-444444444444</string><key>Name</key><string>System</string><key>Roles</key><array><string>System</string></array><key>CapacityReserve</key><integer>0</integer><key>CapacityQuota</key><integer>0</integer><key>Encryption</key><false/></dict>
</array></dict></array></dict></plist>`

func observedAPFSInventory() *schema.Observation {
	obs := &schema.Observation{Volumes: []schema.Volume{
		{Index: 0, Diskutil: map[string]any{"VolumeName": "Data", "APFSContainerReference": "disk6"}, APFS: &schema.APFSVolume{VolumeUUID: "AAAAAAAA-1111-4222-8333-444444444444", ReserveBytes: 4096, QuotaBytes: 8192}},
		{Index: 1, Diskutil: map[string]any{"VolumeName": "System", "APFSContainerReference": "disk6"}, APFS: &schema.APFSVolume{VolumeUUID: "BBBBBBBB-1111-4222-8333-444444444444"}},
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
	unrelated.StdoutText = strings.ReplaceAll(unrelated.StdoutText, "<string>disk6</string>", "<string>disk8</string>")
	unrelated.StdoutText = strings.ReplaceAll(unrelated.StdoutText, "11111111-2222-4333-8444-555555555555", "33333333-2222-4333-8444-555555555555")
	unrelated.StdoutSHA256 = ""
	obs.Commands = append(obs.Commands, unrelated, schema.Command{Argv: unrelated.Argv, Status: "1", StdoutText: "failed output"})
	if _, err := APFSInventory(obs); err != nil {
		t.Fatal("unrelated later command:", err)
	}
}

func TestAPFSInventoryScopesGlobalListingsBeforeTargetValidation(t *testing.T) {
	for _, unrelated := range []string{
		`<dict><key>ContainerReference</key><string>disk99</string></dict>`,
		`<dict><key>ContainerReference</key><string>disk99</string><key>Volumes</key><array/></dict>`,
		`<dict><key>ContainerReference</key><string>disk99</string><key>Volumes</key><string>transient</string></dict>`,
		`<dict><key>ContainerReference</key><string>disk99</string><key>Volumes</key><array><string>transient</string></array></dict>`,
	} {
		obs := observedAPFSInventory()
		listing := strings.Replace(inventoryListing, "<key>Containers</key><array>", "<key>Containers</key><array>"+unrelated, 1)
		setInventoryTranscript(obs, listing)
		if _, err := APFSInventory(obs); err != nil {
			t.Errorf("unrelated global inventory row affected the target: %s: %v", unrelated, err)
		}
	}
	// A known container UUID can also identify unrelated rows when a source has
	// no device reference. The volume UUIDs still bind the selected full listing.
	obs := observedAPFSInventory()
	for i := range obs.Volumes {
		delete(obs.Volumes[i].Diskutil, "APFSContainerReference")
		obs.Volumes[i].APFS.ContainerUUID = "11111111-2222-4333-8444-555555555555"
	}
	unrelated := `<dict><key>APFSContainerUUID</key><string>33333333-2222-4333-8444-555555555555</string></dict>`
	setInventoryTranscript(obs, strings.Replace(inventoryListing, "<key>Containers</key><array>", "<key>Containers</key><array>"+unrelated, 1))
	if _, err := APFSInventory(obs); err != nil {
		t.Fatal("known unrelated container identity affected the target:", err)
	}
	previous := obs.Commands[0]
	setInventoryTranscript(obs, `<plist><dict><key>Containers</key><array><dict><key>APFSContainerUUID</key><string>11111111-2222-4333-8444-555555555555</string></dict></array></dict></plist>`)
	obs.Commands = append([]schema.Command{previous}, obs.Commands...)
	if _, err := APFSInventory(obs); err == nil {
		t.Fatal("target identified by container UUID bypassed its missing volume inventory")
	}
}

func TestAPFSInventoryNeverFallsBackPastInvalidTargetEvidence(t *testing.T) {
	for _, tc := range []struct {
		name    string
		listing string
		scoped  bool
	}{
		{"missing-volumes", `<plist><dict><key>Containers</key><array><dict><key>ContainerReference</key><string>disk6</string></dict></array></dict></plist>`, false},
		{"empty-volumes", `<plist><dict><key>Containers</key><array><dict><key>ContainerReference</key><string>disk6</string><key>APFSContainerUUID</key><string>11111111-2222-4333-8444-555555555555</string><key>Volumes</key><array/></dict></array></dict></plist>`, false},
		{"malformed-target-volume", strings.Replace(inventoryListing, "<key>Volumes</key><array>", "<key>Volumes</key><array><string>invalid</string>", 1), false},
		{"conflicting-reference", strings.ReplaceAll(inventoryListing, "<string>disk6</string>", "<string>disk8</string>"), false},
		{"wrong-volume-identities", strings.ReplaceAll(strings.ReplaceAll(inventoryListing, "aaaaaaaa-1111-4222-8333-444444444444", "cccccccc-1111-4222-8333-444444444444"), "bbbbbbbb-1111-4222-8333-444444444444", "dddddddd-1111-4222-8333-444444444444"), false},
		{"ambiguous-target", strings.Replace(inventoryListing, "<key>Containers</key><array>", `<key>Containers</key><array><dict><key>ContainerReference</key><string>disk6</string></dict>`, 1), false},
		{"missing-scoped-target", `<plist><dict><key>Containers</key><array><dict><key>ContainerReference</key><string>disk99</string></dict></array></dict></plist>`, true},
		{"unidentifiable-transient", `<plist><dict><key>Containers</key><array><dict/></array></dict></plist>`, false},
		{"unidentifiable-malformed-volumes", `<plist><dict><key>Containers</key><array><dict><key>Volumes</key><array><string>transient</string></array></dict></array></dict></plist>`, false},
		{"unidentifiable-empty-volumes", `<plist><dict><key>Containers</key><array><dict><key>Volumes</key><array/></dict></array></dict></plist>`, false},
		{"invalid-unrelated-identity", `<plist><dict><key>Containers</key><array><dict><key>APFSContainerUUID</key><string>invalid</string><key>Volumes</key><string>transient</string></dict></array></dict></plist>`, false},
		{"invalid-unrelated-reference", `<plist><dict><key>Containers</key><array><dict><key>ContainerReference</key><string>invalid</string><key>Volumes</key><array/></dict></array></dict></plist>`, false},
		{"unidentifiable-duplicate-volume-identities", `<plist><dict><key>Containers</key><array><dict><key>Volumes</key><array><dict><key>APFSVolumeUUID</key><string>cccccccc-1111-4222-8333-444444444444</string></dict><dict><key>APFSVolumeUUID</key><string>cccccccc-1111-4222-8333-444444444444</string></dict></array></dict></array></dict></plist>`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := observedAPFSInventory()
			previous := obs.Commands[0]
			setInventoryTranscript(obs, tc.listing)
			if tc.scoped {
				obs.Commands[0].Argv = append(obs.Commands[0].Argv, "disk6")
			}
			obs.Commands = append([]schema.Command{previous}, obs.Commands...)
			if _, err := APFSInventory(obs); err == nil {
				t.Fatal("invalid latest target listing was replaced by older valid evidence")
			}
		})
	}
	obs := observedAPFSInventory()
	previous := obs.Commands[0]
	obs.Commands[0].StdoutText = ""
	obs.Commands = append([]schema.Command{previous}, obs.Commands...)
	if _, err := APFSInventory(obs); err == nil || !strings.Contains(err.Error(), "text unavailable") {
		t.Fatalf("omitted native text must remain an explicit evidence refusal, got %v", err)
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
