package native

import (
	"encoding/hex"
	"fmt"
	"math"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// continuationPartition joins Apple's original image partition ordinals to the
// selected filesystem in the current raw observation. Synthesized APFS volume
// device suffixes and discovery positions are not image partition ordinals.
func continuationPartition(info map[string]any, live *schema.Observation, selectedUUID string) (int, error) {
	selected, err := partitionSelectedVolume(live, selectedUUID)
	if err != nil {
		return 0, err
	}
	store, err := partitionPhysicalStore(selected)
	if err != nil {
		return 0, err
	}
	roots, ok := live.Image.Partitions["AllDisksAndPartitions"].([]any)
	wholeDisks, wholeOK := live.Image.Partitions["WholeDisks"].([]any)
	if !ok || len(roots) != 1 || !wholeOK || len(wholeDisks) != 1 {
		return 0, fmt.Errorf("native disk listing does not identify one whole image")
	}
	root, ok := roots[0].(map[string]any)
	device, deviceOK := root["DeviceIdentifier"].(string)
	size, sizeOK := metadataInteger(root["Size"])
	if !ok || !deviceOK || device == "" || wholeDisks[0] != device || !sizeOK || size <= 0 || size != live.Image.DiskBytes {
		return 0, fmt.Errorf("native whole-image identity or size is inconsistent")
	}
	mapInfo, ok := info["partitions"].(map[string]any)
	if !ok {
		return 0, fmt.Errorf("native imageinfo has no partition map")
	}
	blockSize, ok := metadataInteger(mapInfo["block-size"])
	if !ok || blockSize <= 0 || blockSize != int64(live.Image.SectorSize) || size%blockSize != 0 {
		return 0, fmt.Errorf("native imageinfo block geometry differs from the raw image")
	}
	entries, ok := mapInfo["partitions"].([]any)
	if !ok || len(entries) == 0 {
		return 0, fmt.Errorf("native imageinfo has no partition entries")
	}
	switch live.Image.PartitionMap {
	case "none":
		if mapInfo["partition-scheme"] != "none" || store != device || len(entries) != 1 {
			return 0, fmt.Errorf("bare filesystem is not bound to the whole native image")
		}
		if children, present := root["Partitions"]; present {
			list, valid := children.([]any)
			if !valid || len(list) != 0 {
				return 0, fmt.Errorf("bare native image contains partition children")
			}
		}
		entry, valid := entries[0].(map[string]any)
		start, startOK := metadataInteger(entry["partition-start"])
		length, lengthOK := metadataInteger(entry["partition-length"])
		_, numbered := entry["partition-number"]
		if !valid || entry["partition-synthesized"] != true || numbered || !startOK || start != 0 || !lengthOK || length != size/blockSize || !partitionFilesystemContent(entry["partition-hint"], selected) {
			return 0, fmt.Errorf("native imageinfo does not describe one whole-image filesystem")
		}
		return 0, nil
	case "GPT":
		if mapInfo["partition-scheme"] != "GUID" || root["Content"] != "GUID_partition_scheme" {
			return 0, fmt.Errorf("native imageinfo and diskutil partition schemes differ")
		}
	default:
		return 0, fmt.Errorf("unsupported native continuation partition map %q", live.Image.PartitionMap)
	}
	children, ok := root["Partitions"].([]any)
	if !ok || len(children) == 0 {
		return 0, fmt.Errorf("native GPT disk has no physical partitions")
	}
	var physical map[string]any
	physicalDevices, physicalUUIDs := map[string]bool{}, map[string]bool{}
	for _, child := range children {
		entry, valid := child.(map[string]any)
		id, idOK := partitionUUID(entry["DiskUUID"])
		device, deviceOK := entry["DeviceIdentifier"].(string)
		if !valid || !idOK || !deviceOK || device == "" || physicalDevices[device] || physicalUUIDs[id] {
			return 0, fmt.Errorf("native GPT disk has malformed or ambiguous physical partitions")
		}
		physicalDevices[device], physicalUUIDs[id] = true, true
		if device == store {
			physical = entry
		}
	}
	if physical == nil {
		return 0, fmt.Errorf("native physical store %q is absent from the image", store)
	}
	uuid, valid := partitionUUID(physical["DiskUUID"])
	physicalSize, sizeOK := metadataInteger(physical["Size"])
	if !valid || !sizeOK || physicalSize <= 0 {
		return 0, fmt.Errorf("native physical partition has no valid UUID or size")
	}
	ordinals, uuids := map[int64]bool{}, map[string]bool{}
	ordinal := int64(0)
	for _, value := range entries {
		entry, valid := value.(map[string]any)
		if !valid {
			return 0, fmt.Errorf("native imageinfo has a malformed partition entry")
		}
		if synthesized, present := entry["partition-synthesized"]; present {
			flag, valid := synthesized.(bool)
			if !valid {
				return 0, fmt.Errorf("native imageinfo has an invalid synthesized marker")
			}
			if flag {
				if _, numbered := entry["partition-number"]; numbered {
					return 0, fmt.Errorf("native synthesized partition has an ordinal")
				}
				continue
			}
		}
		number, numberOK := metadataInteger(entry["partition-number"])
		id, idOK := partitionUUID(entry["partition-UUID"])
		start, startOK := metadataInteger(entry["partition-start"])
		length, lengthOK := metadataInteger(entry["partition-length"])
		if !numberOK || number <= 0 || number > math.MaxInt32 || ordinals[number] || !idOK || uuids[id] || !startOK || start == 0 || !lengthOK || length == 0 || start >= size/blockSize || length > size/blockSize-start {
			return 0, fmt.Errorf("native imageinfo has invalid or ambiguous GPT identity, ordinal or geometry")
		}
		ordinals[number], uuids[id] = true, true
		if id != uuid {
			continue
		}
		// Apple's imageinfo reports Apple_HFSX where diskutil reports Apple_HFS
		// for the same GPT type GUID. Both identify the HFS family; case policy
		// remains independently checked by the filesystem continuation verdict.
		if length > math.MaxInt64/blockSize || length*blockSize != physicalSize || !partitionFilesystemContent(physical["Content"], selected) || !partitionFilesystemContent(entry["partition-hint"], selected) {
			return 0, fmt.Errorf("native imageinfo partition differs from the selected physical store")
		}
		if offset, present := selected.Diskutil["PartitionMapPartitionOffset"]; selected.APFS == nil && present {
			n, valid := metadataInteger(offset)
			if !valid || n != start*blockSize {
				return 0, fmt.Errorf("native filesystem partition offset differs from imageinfo")
			}
		}
		ordinal = number
	}
	if ordinal == 0 {
		return 0, fmt.Errorf("native physical partition UUID is absent from imageinfo")
	}
	return int(ordinal), nil
}

func partitionSelectedVolume(live *schema.Observation, selectedUUID string) (schema.Volume, error) {
	uuid, valid := partitionUUID(selectedUUID)
	if live == nil || !valid {
		return schema.Volume{}, fmt.Errorf("native filesystem selection has no valid volume UUID")
	}
	var selected schema.Volume
	found := false
	for _, volume := range live.Volumes {
		id, valid := partitionUUID(volume.Diskutil["VolumeUUID"])
		if !valid || id != uuid {
			continue
		}
		if found {
			return schema.Volume{}, fmt.Errorf("native selected volume UUID is ambiguous")
		}
		selected, found = volume, true
	}
	if !found {
		return schema.Volume{}, fmt.Errorf("native selected volume UUID is absent")
	}
	if selected.APFS != nil {
		id, valid := partitionUUID(selected.APFS.VolumeUUID)
		if !valid || id != uuid {
			return schema.Volume{}, fmt.Errorf("native APFS volume identity differs from diskutil")
		}
	}
	return selected, nil
}

func partitionPhysicalStore(volume schema.Volume) (string, error) {
	if volume.APFS != nil {
		stores, ok := volume.Diskutil["APFSPhysicalStores"].([]any)
		if !ok || len(stores) != 1 {
			return "", fmt.Errorf("native APFS volume does not identify one physical store")
		}
		store, ok := stores[0].(map[string]any)
		device, valid := store["APFSPhysicalStore"].(string)
		if !ok || !valid || device == "" {
			return "", fmt.Errorf("native APFS physical store is malformed")
		}
		return device, nil
	}
	device, ok := volume.Diskutil["DeviceIdentifier"].(string)
	if volume.HFS == nil || !ok || device == "" {
		return "", fmt.Errorf("native filesystem has no physical device")
	}
	return device, nil
}

func partitionFilesystemContent(content any, volume schema.Volume) bool {
	return volume.APFS != nil && content == "Apple_APFS" || volume.HFS != nil && (content == "Apple_HFS" || content == "Apple_HFSX")
}

func partitionUUID(value any) (string, bool) {
	s, ok := value.(string)
	if !ok || len(s) != 36 || s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return "", false
	}
	hexValue := strings.ReplaceAll(s, "-", "")
	_, err := hex.DecodeString(hexValue)
	return strings.ToUpper(s), err == nil && hexValue != strings.Repeat("0", 32)
}
