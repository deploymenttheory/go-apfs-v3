package native

import (
	"encoding/json"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

const (
	partitionTestVolumeUUID = "C2E98763-98F4-4634-9667-DEF320E68E1B"
	partitionTestDiskUUID   = "40456078-BAF3-442C-96CC-2D7183A97EFB"
)

// These field shapes are retained native imageinfo/diskutil observations. In
// particular, the APFS volume disk8s1 belongs to physical store disk7s4; neither
// device suffix supplies the deliberately different image partition ordinal 7.
func partitionTestState(apfs, bare bool) (map[string]any, *schema.Observation) {
	const bytes = 64 << 20
	info := map[string]any{"partitions": map[string]any{
		"block-size": 512, "partition-scheme": "GUID", "partitions": []any{
			map[string]any{"partition-hint": "Primary GPT Header", "partition-synthesized": true, "partition-start": 1, "partition-length": 1},
			map[string]any{"partition-number": 7, "partition-UUID": partitionTestDiskUUID, "partition-hint": "Apple_APFS", "partition-start": 40, "partition-length": 130992},
		},
	}}
	root := map[string]any{"Content": "GUID_partition_scheme", "DeviceIdentifier": "disk7", "Size": bytes,
		"Partitions": []any{map[string]any{"Content": "Apple_APFS", "DeviceIdentifier": "disk7s4", "DiskUUID": partitionTestDiskUUID, "Size": 67067904}}}
	volume := schema.Volume{APFS: &schema.APFSVolume{VolumeUUID: partitionTestVolumeUUID}, Diskutil: map[string]any{
		"VolumeUUID": partitionTestVolumeUUID, "DeviceIdentifier": "disk8s1", "APFSPhysicalStores": []any{map[string]any{"APFSPhysicalStore": "disk7s4"}},
	}}
	obs := &schema.Observation{Image: schema.Image{PartitionMap: "GPT", DiskBytes: bytes, SectorSize: 512,
		Partitions: map[string]any{"WholeDisks": []any{"disk7"}, "AllDisksAndPartitions": []any{root}}}, Volumes: []schema.Volume{volume}}
	if !apfs {
		volume.APFS, volume.HFS = nil, &schema.HFSVolume{}
		volume.Diskutil["DeviceIdentifier"], volume.Diskutil["PartitionMapPartitionOffset"] = "disk7s4", 20480
		delete(volume.Diskutil, "APFSPhysicalStores")
		partitionTestEntries(info)[1].(map[string]any)["partition-hint"] = "Apple_HFS"
		root["Partitions"].([]any)[0].(map[string]any)["Content"] = "Apple_HFS"
		obs.Volumes[0] = volume
	}
	if bare {
		obs.Image.PartitionMap = "none"
		root["Content"] = ""
		delete(root, "Partitions")
		mapInfo := info["partitions"].(map[string]any)
		mapInfo["partition-scheme"] = "none"
		hint := "Apple_APFS"
		if apfs {
			volume.Diskutil["APFSPhysicalStores"].([]any)[0].(map[string]any)["APFSPhysicalStore"] = "disk7"
		} else {
			hint = "Apple_HFS"
			volume.Diskutil["DeviceIdentifier"] = "disk7"
			delete(volume.Diskutil, "PartitionMapPartitionOffset")
		}
		mapInfo["partitions"] = []any{map[string]any{"partition-hint": hint, "partition-start": 0, "partition-length": bytes / 512, "partition-synthesized": true}}
	}
	return info, obs
}

func partitionTestEntries(info map[string]any) []any {
	return info["partitions"].(map[string]any)["partitions"].([]any)
}

func TestContinuationPartitionUsesNativeOrdinalAndWholeImageBinding(t *testing.T) {
	for _, apfs := range []bool{true, false} {
		for _, bare := range []bool{true, false} {
			info, live := partitionTestState(apfs, bare)
			// Exercise the JSON number representation used by actual observations
			// as well as the native API maps used above.
			data, err := json.Marshal(live)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(data, live); err != nil {
				t.Fatal(err)
			}
			want := 7
			if bare {
				want = 0
			}
			if got, err := continuationPartition(info, live, partitionTestVolumeUUID); err != nil || got != want {
				t.Fatalf("APFS=%v bare=%v: ordinal=%d want=%d: %v", apfs, bare, got, want, err)
			}
		}
	}
}

func TestContinuationPartitionRejectsUnboundOrAmbiguousNativeEvidence(t *testing.T) {
	for name, damage := range map[string]func(map[string]any, *schema.Observation){
		"missing imageinfo":         func(info map[string]any, _ *schema.Observation) { delete(info, "partitions") },
		"missing selected volume":   func(_ map[string]any, live *schema.Observation) { live.Volumes = nil },
		"duplicate selected volume": func(_ map[string]any, live *schema.Observation) { live.Volumes = append(live.Volumes, live.Volumes[0]) },
		"missing store": func(_ map[string]any, live *schema.Observation) {
			delete(live.Volumes[0].Diskutil, "APFSPhysicalStores")
		},
		"APFS identity mismatch": func(_ map[string]any, live *schema.Observation) {
			live.Volumes[0].APFS.VolumeUUID = partitionTestDiskUUID
		},
		"ambiguous physical UUID": func(_ map[string]any, live *schema.Observation) {
			root := live.Image.Partitions["AllDisksAndPartitions"].([]any)[0].(map[string]any)
			root["Partitions"] = append(root["Partitions"].([]any), map[string]any{"DiskUUID": partitionTestDiskUUID, "DeviceIdentifier": "disk7s99"})
		},
		"multiple stores": func(_ map[string]any, live *schema.Observation) {
			stores := live.Volumes[0].Diskutil["APFSPhysicalStores"].([]any)
			live.Volumes[0].Diskutil["APFSPhysicalStores"] = append(stores, stores[0])
		},
		"store outside image": func(_ map[string]any, live *schema.Observation) {
			live.Volumes[0].Diskutil["APFSPhysicalStores"].([]any)[0].(map[string]any)["APFSPhysicalStore"] = "disk99s1"
		},
		"different UUID": func(info map[string]any, _ *schema.Observation) {
			partitionTestEntries(info)[1].(map[string]any)["partition-UUID"] = partitionTestVolumeUUID
		},
		"duplicate ordinal": func(info map[string]any, _ *schema.Observation) {
			entry := map[string]any{"partition-number": 7, "partition-UUID": partitionTestVolumeUUID, "partition-start": 200, "partition-length": 8}
			info["partitions"].(map[string]any)["partitions"] = append(partitionTestEntries(info), entry)
		},
		"duplicate UUID": func(info map[string]any, _ *schema.Observation) {
			entry := map[string]any{"partition-number": 9, "partition-UUID": partitionTestDiskUUID, "partition-start": 200, "partition-length": 8}
			info["partitions"].(map[string]any)["partitions"] = append(partitionTestEntries(info), entry)
		},
		"fractional ordinal": func(info map[string]any, _ *schema.Observation) {
			partitionTestEntries(info)[1].(map[string]any)["partition-number"] = 1.5
		},
		"negative ordinal": func(info map[string]any, _ *schema.Observation) {
			partitionTestEntries(info)[1].(map[string]any)["partition-number"] = -1
		},
		"negative partition start": func(info map[string]any, _ *schema.Observation) {
			partitionTestEntries(info)[1].(map[string]any)["partition-start"] = -40
		},
		"negative partition length": func(info map[string]any, _ *schema.Observation) {
			partitionTestEntries(info)[1].(map[string]any)["partition-length"] = -130992
		},
		"overflowed partition length": func(info map[string]any, _ *schema.Observation) {
			partitionTestEntries(info)[1].(map[string]any)["partition-length"] = ^uint64(0)
		},
		"synthesized ordinal": func(info map[string]any, _ *schema.Observation) {
			partitionTestEntries(info)[0].(map[string]any)["partition-number"] = 1
		},
		"physical size changed": func(_ map[string]any, live *schema.Observation) {
			root := live.Image.Partitions["AllDisksAndPartitions"].([]any)[0].(map[string]any)
			root["Partitions"].([]any)[0].(map[string]any)["Size"] = 4096
		},
		"whole disk size changed": func(_ map[string]any, live *schema.Observation) { live.Image.DiskBytes++ },
		"block geometry changed": func(info map[string]any, _ *schema.Observation) {
			info["partitions"].(map[string]any)["block-size"] = 4096
		},
		"partition outside image": func(info map[string]any, _ *schema.Observation) {
			partitionTestEntries(info)[1].(map[string]any)["partition-start"] = 131072
		},
		"filesystem hint changed": func(info map[string]any, _ *schema.Observation) {
			partitionTestEntries(info)[1].(map[string]any)["partition-hint"] = "Apple_HFS"
		},
		"partition scheme changed": func(info map[string]any, _ *schema.Observation) {
			info["partitions"].(map[string]any)["partition-scheme"] = "none"
		},
		"unsupported map": func(_ map[string]any, live *schema.Observation) { live.Image.PartitionMap = "APM" },
	} {
		t.Run(name, func(t *testing.T) {
			info, live := partitionTestState(true, false)
			damage(info, live)
			if _, err := continuationPartition(info, live, partitionTestVolumeUUID); err == nil {
				t.Fatal("unbound native partition was admitted")
			}
		})
	}
}

func TestContinuationPartitionRefusesUnprovenBareZeroAndChangedHFSOffset(t *testing.T) {
	for name, damage := range map[string]func(map[string]any, *schema.Observation){
		"missing scheme": func(info map[string]any, _ *schema.Observation) {
			delete(info["partitions"].(map[string]any), "partition-scheme")
		},
		"partition store": func(_ map[string]any, live *schema.Observation) {
			live.Volumes[0].Diskutil["APFSPhysicalStores"].([]any)[0].(map[string]any)["APFSPhysicalStore"] = "disk7s1"
		},
		"short filesystem": func(info map[string]any, _ *schema.Observation) {
			partitionTestEntries(info)[0].(map[string]any)["partition-length"] = 8
		},
		"numbered filesystem": func(info map[string]any, _ *schema.Observation) {
			partitionTestEntries(info)[0].(map[string]any)["partition-number"] = 0
		},
		"partition children": func(_ map[string]any, live *schema.Observation) {
			live.Image.Partitions["AllDisksAndPartitions"].([]any)[0].(map[string]any)["Partitions"] = []any{map[string]any{}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			info, live := partitionTestState(true, true)
			damage(info, live)
			if _, err := continuationPartition(info, live, partitionTestVolumeUUID); err == nil {
				t.Fatal("missing whole-image evidence silently became ordinal zero")
			}
		})
	}
	info, live := partitionTestState(false, false)
	live.Volumes[0].Diskutil["PartitionMapPartitionOffset"] = 4096
	if _, err := continuationPartition(info, live, partitionTestVolumeUUID); err == nil {
		t.Fatal("changed native HFS partition offset was admitted")
	}
}

func TestContinuationPartitionJoinsNativeHFSXAndHFSPartitionTypeNames(t *testing.T) {
	info, live := partitionTestState(false, false)
	live.Volumes[0].HFS.CaseSensitive = true
	partitionTestEntries(info)[1].(map[string]any)["partition-hint"] = "Apple_HFSX"
	if got, err := continuationPartition(info, live, partitionTestVolumeUUID); err != nil || got != 7 {
		t.Fatal("native HFSX imageinfo did not join the same diskutil HFS partition", got, err)
	}
}
