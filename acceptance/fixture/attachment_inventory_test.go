package fixture

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// attachmentInventoryCommander supplies native topology replies without running
// any filesystem tools. Its first list can deliberately lag behind hdiutil.
type attachmentInventoryCommander struct {
	attach    map[string]any
	listings  []map[string]any
	infos     map[string]map[string]any
	apfs      map[string]any
	listCalls int
	calls     [][]string
}

func (c *attachmentInventoryCommander) Run(_ context.Context, cmd Command) Result {
	c.calls = append(c.calls, cmd.Argv)
	command := strings.Join(cmd.Argv, " ")
	var value any
	switch {
	case cmd.Argv[0] == "plutil":
		return Result{Stdout: cmd.Stdin}
	case strings.HasPrefix(command, "hdiutil attach "):
		value = c.attach
	case strings.HasPrefix(command, "diskutil list "):
		value = c.listings[min(c.listCalls, len(c.listings)-1)]
		c.listCalls++
	case strings.HasPrefix(command, "diskutil info "):
		value = c.infos[cmd.Argv[len(cmd.Argv)-1]]
	case strings.HasPrefix(command, "diskutil apfs list "):
		value = c.apfs
	default:
		return Result{Err: fmt.Errorf("unexpected command: %v", cmd.Argv)}
	}
	out, err := json.Marshal(value)
	return Result{Stdout: out, Err: err}
}

func attachedHFSInventory(attachHint, listHint, infoHint string) *attachmentInventoryCommander {
	return &attachmentInventoryCommander{
		attach: map[string]any{"system-entities": []any{
			map[string]any{"dev-entry": "/dev/disk8s1", "content-hint": "Apple_HFS", "potentially-mountable": true},
			map[string]any{"dev-entry": "/dev/disk8", "content-hint": attachHint},
		}},
		listings: []map[string]any{
			{"AllDisksAndPartitions": []any{map[string]any{"DeviceIdentifier": "disk8", "Content": listHint}}},
			{"AllDisksAndPartitions": []any{map[string]any{"DeviceIdentifier": "disk8", "Content": "GUID_partition_scheme", "Partitions": []any{map[string]any{"DeviceIdentifier": "disk8s1", "Content": "Apple_HFS"}}}}},
		},
		infos: map[string]map[string]any{
			"/dev/disk8":   {"Content": infoHint},
			"/dev/disk8s1": {"Content": "Apple_HFS", "FilesystemType": "hfs", "VolumeName": "encrypted-image-edits", "VolumeUUID": "592B550D-7A7C-3660-A558-4C183E86BEF8"},
		},
	}
}

func TestAttachmentDiscoveryWaitsForPartitionSlicesInsteadOfMountingTheirWholeDisk(t *testing.T) {
	instantWaits(t)
	for _, tc := range []struct{ name, attachHint, listHint, infoHint string }{
		{"native GPT topology", "GUID_partition_scheme", "GUID_partition_scheme", "GUID_partition_scheme"},
		{"attach hint while both diskutil replies lag", "GUID_partition_scheme", "", ""},
		{"list hint while info lags", "", "GUID_partition_scheme", ""},
		{"info hint while list lags", "", "", "GUID_partition_scheme"},
		{"Apple partition map", "Apple_partition_scheme", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commander := attachedHFSInventory(tc.attachHint, tc.listHint, tc.infoHint)
			disk := &HostDisk{C: commander, T: &Transcript{}}
			att, err := disk.Attach(context.Background(), "continued.dmg", AttachOptions{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			if commander.listCalls != 2 || len(att.Volumes) != 1 || att.Volumes[0].Dev != "/dev/disk8s1" || att.Volumes[0].Name != "encrypted-image-edits" {
				t.Fatalf("partition readiness selected a non-filesystem device: list checks=%d, volumes=%+v", commander.listCalls, att.Volumes)
			}
		})
	}
}

func TestAttachmentDiscoveryNeverReturnsAPartitionSchemeAfterItsWaitBudget(t *testing.T) {
	instantWaits(t)
	commander := attachedHFSInventory("GUID_partition_scheme", "", "")
	commander.listings = commander.listings[:1]
	disk := &HostDisk{C: commander, T: &Transcript{}}
	att, err := disk.Attach(context.Background(), "continued.dmg", AttachOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if commander.listCalls != ShortWait.Attempts || len(att.Volumes) != 0 {
		t.Fatalf("spent readiness budget must leave an empty inventory: checks=%d, volumes=%+v", commander.listCalls, att.Volumes)
	}
}

func TestRefreshExcludesPartitionSchemesEvenWithAStaleFilesystemType(t *testing.T) {
	commander := attachedHFSInventory("", "", "GUID_partition_scheme")
	commander.infos["/dev/disk8"]["FilesystemType"] = "hfs"
	disk := &HostDisk{C: commander, T: &Transcript{}}
	att := &Attachment{Dev: "/dev/disk8"}
	if err := disk.Refresh(context.Background(), att); err != nil {
		t.Fatal(err)
	}
	if len(att.Volumes) != 0 {
		t.Fatalf("a known partition scheme cannot be a filesystem: %+v", att.Volumes)
	}
}

func TestAttachmentDiscoveryPreservesBareFilesystemsAndUnformattedRawDisks(t *testing.T) {
	for _, tc := range []struct{ name, hint, fs, volume string }{
		{"bare HFS", "Apple_HFS", "hfs", "Bare HFS"},
		{"bare HFS before filesystem classification", "Apple_HFS", "", ""},
		{"unformatted raw", "", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			commander := attachedHFSInventory(tc.hint, tc.hint, tc.hint)
			commander.attach["system-entities"] = []any{map[string]any{"dev-entry": "/dev/disk8", "content-hint": tc.hint, "potentially-mountable": tc.fs != ""}}
			commander.infos["/dev/disk8"]["FilesystemType"] = tc.fs
			commander.infos["/dev/disk8"]["VolumeName"] = tc.volume
			disk := &HostDisk{C: commander, T: &Transcript{}}
			att, err := disk.Attach(context.Background(), "sectors.raw", AttachOptions{Raw: true})
			if err != nil {
				t.Fatal(err)
			}
			if commander.listCalls != 1 || len(att.Volumes) != 1 || att.Volumes[0].Dev != "/dev/disk8" || att.Volumes[0].Name != tc.volume {
				t.Fatalf("bare device discovery changed: checks=%d, volumes=%+v", commander.listCalls, att.Volumes)
			}
		})
	}
}

func TestRefreshStillDiscoversAPFSContainersBeforeApplyingTheBareDiskGuard(t *testing.T) {
	for _, hint := range []string{"", "GUID_partition_scheme"} {
		t.Run(hint, func(t *testing.T) {
			commander := attachedHFSInventory(hint, hint, hint)
			commander.infos["/dev/disk8"]["APFSContainerReference"] = "disk9"
			commander.infos["/dev/disk8"]["Content"] = "Apple_APFS"
			commander.infos["/dev/disk9s1"] = map[string]any{"FilesystemType": "apfs", "VolumeName": "Primary", "VolumeUUID": "APFS-UUID"}
			commander.apfs = map[string]any{"Containers": []any{map[string]any{"Volumes": []any{map[string]any{"DeviceIdentifier": "disk9s1"}}}}}
			disk := &HostDisk{C: commander, T: &Transcript{}}
			att, err := disk.Attach(context.Background(), "container.dmg", AttachOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if commander.listCalls != 1 || att.Container != "disk9" || len(att.Volumes) != 1 || att.Volumes[0].Dev != "/dev/disk9s1" || att.Volumes[0].FS != "apfs" {
				t.Fatalf("APFS container discovery changed: container=%q, volumes=%+v", att.Container, att.Volumes)
			}
		})
	}
}
