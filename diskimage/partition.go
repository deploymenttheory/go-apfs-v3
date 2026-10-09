package diskimage

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"sort"
	"unicode/utf16"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const APFSType = "7C3457EF-0000-11AA-AA11-00306543ECAC"
const HFSType = "48465300-0000-11AA-AA11-00306543ECAC"

func partitions(s block.Source) (string, []Partition, error) {
	// GPT sector sizes are detected independently of filesystem block size.
	for _, sector := range []int64{512, 4096} {
		if s.Size() < sector+512 {
			continue
		}
		h := make([]byte, 512)
		if err := block.ReadFull(s, h, sector); err != nil {
			return "", nil, err
		}
		if string(h[:8]) == "EFI PART" {
			p, err := readGPT(s, sector)
			return "gpt", p, err
		}
	}
	if s.Size() >= 1024 {
		h := make([]byte, 512)
		if err := block.ReadFull(s, h, 512); err != nil {
			return "", nil, err
		}
		if string(h[:2]) == "PM" {
			p, err := readAPM(s)
			return "apm", p, err
		}
	}
	return "none", []Partition{{Index: 0, Type: "raw", Size: s.Size()}}, nil
}

func corrupt(what string) error { return fmt.Errorf("%s: %w", what, filesystem.ErrCorrupt) }

func readGPT(s block.Source, sector int64) ([]Partition, error) {
	h := make([]byte, sector)
	if err := block.ReadFull(s, h, sector); err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	hs := le.Uint32(h[12:])
	if le.Uint32(h[8:]) != 0x10000 || hs < 92 || int64(hs) > sector {
		return nil, corrupt("GPT header size or revision")
	}
	want := le.Uint32(h[16:])
	clear(h[16:20])
	if crc32.ChecksumIEEE(h[:hs]) != want {
		return nil, corrupt("GPT header checksum")
	}
	if le.Uint64(h[24:]) != 1 {
		return nil, corrupt("GPT primary header location")
	}
	first, last := le.Uint64(h[40:]), le.Uint64(h[48:])
	if first > last || last >= uint64(s.Size()/sector) {
		return nil, corrupt("GPT usable range")
	}
	count, stride := uint64(le.Uint32(h[80:])), uint64(le.Uint32(h[84:]))
	if count == 0 || stride < 128 || stride%128 != 0 {
		return nil, corrupt("GPT entry layout")
	}
	if count > 4096 || stride > 4096 || count*stride > 16<<20 {
		return nil, filesystem.ErrLimit
	}
	lba := le.Uint64(h[72:])
	if lba < 2 || lba >= first || count*stride > uint64(sector)*(first-lba) {
		return nil, corrupt("GPT entry range")
	}
	data := make([]byte, int(count*stride))
	if err := block.ReadFull(s, data, int64(lba)*sector); err != nil {
		return nil, err
	}
	if crc32.ChecksumIEEE(data) != le.Uint32(h[88:]) {
		return nil, corrupt("GPT entries checksum")
	}
	var out []Partition
	for n := uint64(0); n < count; n++ {
		e := data[n*stride : (n+1)*stride]
		if bytes.Equal(e[:16], make([]byte, 16)) {
			continue
		}
		start, end := le.Uint64(e[32:]), le.Uint64(e[40:])
		if start < first || end > last || end < start {
			return nil, corrupt("GPT partition range")
		}
		name := make([]uint16, 0, 36)
		for j := 56; j < 128; j += 2 {
			v := le.Uint16(e[j:])
			if v == 0 {
				break
			}
			name = append(name, v)
		}
		out = append(out, Partition{Index: int(n + 1), Name: string(utf16.Decode(name)), Type: guid(e[:16]), Offset: int64(start) * sector, Size: int64(end-start+1) * sector})
	}
	if err := nonoverlap(out); err != nil {
		return nil, err
	}
	return out, nil
}

func readAPM(s block.Source) ([]Partition, error) {
	be := binary.BigEndian
	var out []Partition
	var count uint32
	for n := uint32(1); n == 1 || n <= count; n++ {
		e := make([]byte, 512)
		if err := block.ReadFull(s, e, int64(n)*512); err != nil {
			return nil, err
		}
		if string(e[:2]) != "PM" {
			return nil, corrupt("APM entry signature")
		}
		if n == 1 {
			count = be.Uint32(e[4:])
			if count == 0 || count > 4096 {
				return nil, filesystem.ErrLimit
			}
		}
		if be.Uint32(e[4:]) != count {
			return nil, corrupt("APM entry count")
		}
		off, size := int64(be.Uint32(e[8:]))*512, int64(be.Uint32(e[12:]))*512
		if off > s.Size() || size > s.Size()-off {
			return nil, corrupt("APM partition range")
		}
		out = append(out, Partition{Index: int(n), Name: cstring(e[16:48]), Type: cstring(e[48:80]), Offset: off, Size: size})
	}
	if err := nonoverlap(out); err != nil {
		return nil, err
	}
	return out, nil
}

func nonoverlap(parts []Partition) error {
	sorted := append([]Partition(nil), parts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Offset < sorted[j].Offset })
	for i := 1; i < len(sorted); i++ {
		if sorted[i].Offset < sorted[i-1].Offset+sorted[i-1].Size {
			return corrupt("overlapping partitions")
		}
	}
	return nil
}

func cstring(b []byte) string {
	if n := bytes.IndexByte(b, 0); n >= 0 {
		b = b[:n]
	}
	return string(b)
}
func guid(b []byte) string {
	return fmt.Sprintf("%08X-%04X-%04X-%X-%X", binary.LittleEndian.Uint32(b), binary.LittleEndian.Uint16(b[4:]), binary.LittleEndian.Uint16(b[6:]), b[8:10], b[10:16])
}
