package diskimage

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"sort"
	"strconv"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Apple device images describe their partition-map records separately. A single
// generic block can preserve bytes but still be rejected by native DiskImages.
// These descriptors change only the new envelope, never the supplied sectors.
func rawDiskLayout(source block.Source, image *Image) (encodingLayout, error) {
	type region struct {
		start, size int64
		name, kind  string
	}
	var regions []region
	layout := encodingLayout{variant: 1}
	if image.PartitionMap == "apm" {
		var driver [512]byte
		if err := block.ReadFull(source, driver[:], 0); err != nil {
			return layout, err
		}
		if string(driver[:2]) != "ER" || binary.BigEndian.Uint16(driver[2:]) != 512 {
			return layout, fmt.Errorf("raw APM repacking requires a 512-byte driver descriptor: %w", filesystem.ErrUnsupported)
		}
		regions = append(regions, region{0, 512, "Driver Descriptor Map", "DDM"})
	} else {
		header := make([]byte, 512)
		if err := block.ReadFull(source, header, 512); err != nil {
			return layout, err
		}
		if string(header[:8]) != "EFI PART" {
			return layout, fmt.Errorf("raw GPT repacking requires 512-byte logical sectors: %w", filesystem.ErrUnsupported)
		}
		le := binary.LittleEndian
		count, stride := uint64(le.Uint32(header[80:])), uint64(le.Uint32(header[84:]))
		if count == 0 || count > 4096 || stride < 128 || stride > 4096 || stride%128 != 0 || count*stride > 16<<20 {
			return layout, corrupt("GPT entry geometry changed")
		}
		tableBytes := int64(count * stride)
		tableSectors := (tableBytes + 511) / 512
		primaryTable := le.Uint64(header[72:])
		backupSector := le.Uint64(header[32:])
		if backupSector >= uint64(image.Size()/512) {
			return layout, corrupt("GPT backup header range")
		}
		backup := make([]byte, 512)
		if err := block.ReadFull(source, backup, int64(backupSector)*512); err != nil {
			return layout, err
		}
		if string(backup[:8]) != "EFI PART" || le.Uint32(backup[8:]) != 0x10000 || le.Uint32(backup[12:]) < 92 || le.Uint32(backup[12:]) > 512 ||
			le.Uint64(backup[24:]) != backupSector || le.Uint64(backup[32:]) != 1 || le.Uint32(backup[80:]) != uint32(count) || le.Uint32(backup[84:]) != uint32(stride) {
			return layout, corrupt("GPT backup header")
		}
		checksum := le.Uint32(backup[16:])
		clear(backup[16:20])
		if crc32.ChecksumIEEE(backup[:le.Uint32(backup[12:])]) != checksum {
			return layout, corrupt("GPT backup checksum")
		}
		backupTable := le.Uint64(backup[72:])
		if backupTable > uint64(image.Size()/512) || uint64(tableSectors) > uint64(image.Size()/512)-backupTable {
			return layout, corrupt("GPT backup table range")
		}
		data := make([]byte, tableBytes)
		if err := block.ReadFull(source, data, int64(backupTable)*512); err != nil {
			return layout, err
		}
		if crc32.ChecksumIEEE(data) != le.Uint32(backup[88:]) || le.Uint32(backup[88:]) != le.Uint32(header[88:]) {
			return layout, corrupt("GPT backup table checksum")
		}
		regions = append(regions, region{0, 512, "Protective Master Boot Record", "MBR"}, region{512, 512, "GPT Header", "Primary GPT Header"},
			region{int64(primaryTable) * 512, tableSectors * 512, "GPT Partition Data", "Primary GPT Table"},
			region{int64(backupTable) * 512, tableSectors * 512, "GPT Partition Data", "Backup GPT Table"}, region{int64(backupSector) * 512, 512, "GPT Header", "Backup GPT Header"})
	}
	for _, p := range image.Partitions {
		if p.Size == 0 {
			continue
		}
		kind := p.Type
		if image.PartitionMap == "gpt" {
			switch kind {
			case APFSType:
				kind = "Apple_APFS"
			case HFSType:
				kind = "Apple_HFS"
			default:
				kind = "unknown partition type"
			}
		}
		regions = append(regions, region{p.Offset, p.Size, p.Name, kind})
	}
	sort.Slice(regions, func(i, j int) bool { return regions[i].start < regions[j].start })
	end := int64(0)
	add := func(r region) {
		index := len(layout.blocks)
		name := fmt.Sprintf("%s (%s : %d)", r.name, r.kind, index)
		descriptor := uint32(index)
		if image.PartitionMap == "apm" {
			descriptor = uint32(int32(index - 1))
		}
		layout.blocks = append(layout.blocks, encodingBlock{start: r.start, size: r.size, name: name, cfName: name, id: strconv.Itoa(index - 1), attributes: "0x0050", descriptor: descriptor})
		end = r.start + r.size
	}
	for _, r := range regions {
		if r.start < end || r.start > image.Size() || r.size <= 0 || r.size > image.Size()-r.start {
			return layout, corrupt("raw disk layout overlap or range")
		}
		if r.start > end {
			add(region{end, r.start - end, "", "Apple_Free"})
		}
		add(r)
	}
	if end < image.Size() {
		add(region{end, image.Size() - end, "", "Apple_Free"})
	}
	if len(layout.blocks) > 4096 {
		return layout, filesystem.ErrLimit
	}
	return layout, nil
}
