package diskimage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// A small spec-defined GPT isolates integrity checks from filesystem decoding.
func gptFixture(sector int) []byte {
	b := make([]byte, sector*12)
	le := binary.LittleEndian
	h := b[sector : sector*2]
	copy(h, "EFI PART")
	le.PutUint32(h[8:], 0x10000)
	le.PutUint32(h[12:], 92)
	le.PutUint64(h[24:], 1)
	le.PutUint64(h[32:], 11)
	le.PutUint64(h[40:], 3)
	le.PutUint64(h[48:], 9)
	le.PutUint64(h[72:], 2)
	le.PutUint32(h[80:], 2)
	le.PutUint32(h[84:], 128)
	entries := b[sector*2 : sector*2+256]
	entries[0] = 1
	le.PutUint64(entries[32:], 3)
	le.PutUint64(entries[40:], 4)
	entries[128] = 2
	le.PutUint64(entries[160:], 5)
	le.PutUint64(entries[168:], 8)
	le.PutUint32(h[88:], crc32.ChecksumIEEE(entries))
	le.PutUint32(h[16:], crc32.ChecksumIEEE(h[:92]))
	return b
}

func TestGPTEnumeratesEveryPartition(t *testing.T) {
	for _, sector := range []int{512, 4096} {
		img, err := New(bytes.NewReader(gptFixture(sector)))
		if err != nil {
			t.Fatal(err)
		}
		if img.PartitionMap != "gpt" || len(img.Partitions) != 2 {
			t.Fatalf("%+v", img)
		}
		p, err := img.Partition(2)
		if err != nil {
			t.Fatal(err)
		}
		if p.Size() != int64(sector*4) {
			t.Fatal(p.Size())
		}
		if _, err := img.Partition(0); err == nil {
			t.Fatal("silently selected a partition")
		}
	}
}

func TestGPTRejectsCorruptionWithoutRawFallback(t *testing.T) {
	for _, offset := range []int{512 + 24, 1024 + 16} {
		b := gptFixture(512)
		b[offset] ^= 1
		if _, err := New(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatalf("byte %d: %v", offset, err)
		}
	}
}

func TestGPTRejectsOverlappingPartitions(t *testing.T) {
	b := gptFixture(512)
	le := binary.LittleEndian
	le.PutUint64(b[1024+160:], 4)
	le.PutUint32(b[512+88:], crc32.ChecksumIEEE(b[1024:1280]))
	clear(b[528:532])
	le.PutUint32(b[528:], crc32.ChecksumIEEE(b[512:604]))
	if _, err := New(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal(err)
	}
}

func FuzzImageMetadata(f *testing.F) {
	f.Add(gptFixture(512))
	f.Add(make([]byte, 512))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 1<<20 {
			return
		}
		_, _ = New(bytes.NewReader(data))
	})
}

func TestAPMEnumeratesAndBoundsPartitions(t *testing.T) {
	b := make([]byte, 16*512)
	be := binary.BigEndian
	for n := 1; n <= 2; n++ {
		e := b[n*512 : (n+1)*512]
		copy(e, "PM")
		be.PutUint32(e[4:], 2)
		if n == 1 {
			be.PutUint32(e[8:], 1)
			be.PutUint32(e[12:], 2)
			copy(e[48:], "Apple_partition_map")
		} else {
			be.PutUint32(e[8:], 3)
			be.PutUint32(e[12:], 12)
			copy(e[16:], "Data")
			copy(e[48:], "Apple_HFS")
		}
	}
	i, err := New(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if i.PartitionMap != "apm" || len(i.Partitions) != 2 || i.Partitions[1].Name != "Data" {
		t.Fatalf("%+v", i)
	}
	be.PutUint32(b[1024+12:], 14)
	if _, err := New(bytes.NewReader(b)); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("accepted partition outside image", err)
	}
}
