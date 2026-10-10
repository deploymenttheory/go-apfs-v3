package diskimage

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Encode writes a single-volume UDIF, borrowing a sequential source of exactly
// size bytes. UDRO stores raw chunks; UDZO uses zlib. Both include block, data
// and master CRCs. Chunk boundaries and compression settings are fixed, making
// output independent of the host. Output must be discarded on any error.
func Encode(ctx context.Context, out io.Writer, source io.Reader, size int64, format string) error {
	return encode(ctx, out, source, size, format, encodingLayout{variant: 2, blocks: []encodingBlock{{size: size, name: "whole disk (Apple_HFS : 0)", cfName: "whole disk (Apple_HFS : 0)", id: "0", attributes: "0x0050", descriptor: 0xfffffffe}}})
}

type encodingBlock struct {
	descriptor                   uint32
	start, size                  int64
	name, cfName, id, attributes string
	table                        []byte // source block table, used only by repack validation
}
type encodingLayout struct {
	variant uint32
	blocks  []encodingBlock
	plst    []byte // admitted native placeholder, preserved byte-for-byte
}

func encode(ctx context.Context, out io.Writer, source io.Reader, size int64, format string, layout encodingLayout) error {
	if out == nil || source == nil || size <= 0 || size%512 != 0 || size > 1<<40 {
		return fs.ErrInvalid
	}
	if format != "UDRO" && format != "UDZO" {
		return fmt.Errorf("UDIF format %q: %w", format, filesystem.ErrUnsupported)
	}
	const chunkSize = 4 << 20
	raw := make([]byte, chunkSize)
	dataCRC, masterCRC := crc32.NewIEEE(), crc32.NewIEEE()
	var plist bytes.Buffer
	plist.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>resource-fork</key><dict><key>blkx</key><array>")
	stored := int64(0)
	write := func(b []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := out.Write(b)
		if err == nil && n != len(b) {
			err = io.ErrShortWrite
		}
		return err
	}
	for _, region := range layout.blocks {
		var chunks bytes.Buffer
		logicalCRC := crc32.NewIEEE()
		record := func(kind uint32, off, length, at, count int64) {
			b := make([]byte, 40)
			binary.BigEndian.PutUint32(b, kind)
			for i, v := range []int64{off / 512, length / 512, at, count} {
				binary.BigEndian.PutUint64(b[8+i*8:], uint64(v))
			}
			chunks.Write(b)
		}
		for off := int64(0); off < region.size; {
			if err := ctx.Err(); err != nil {
				return err
			}
			b := raw[:min(int64(len(raw)), region.size-off)]
			if _, err := io.ReadFull(source, b); err != nil {
				return err
			}
			_, _ = logicalCRC.Write(b)
			kind := uint32(1)
			payload := b
			if allZero(b) {
				// Type 0 is checksum-covered zero fill; type 2 ignores sectors in native CRCs.
				kind = 0
				payload = nil
			} else if format == "UDZO" {
				var compressed bytes.Buffer
				z, err := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
				if err != nil {
					return err
				}
				if _, err = z.Write(b); err != nil {
					return err
				}
				if err = z.Close(); err != nil {
					return err
				}
				if compressed.Len() < len(b) {
					kind = 0x80000005
					payload = compressed.Bytes()
				}
			}
			record(kind, off, int64(len(b)), stored, int64(len(payload)))
			if err := write(payload); err != nil {
				return err
			}
			_, _ = dataCRC.Write(payload)
			stored += int64(len(payload))
			off += int64(len(b))
		}
		record(0xffffffff, region.size, 0, stored, 0)
		table := make([]byte, 204)
		copy(table, "mish")
		be := binary.BigEndian
		be.PutUint32(table[4:], 1)
		be.PutUint64(table[8:], uint64(region.start/512))
		be.PutUint64(table[16:], uint64(region.size/512))
		be.PutUint32(table[32:], chunkSize/512+8)
		be.PutUint32(table[36:], region.descriptor)
		checksum := func(b []byte, crc uint32) { be.PutUint32(b, 2); be.PutUint32(b[4:], 32); be.PutUint32(b[8:], crc) }
		checksum(table[64:], logicalCRC.Sum32())
		be.PutUint32(table[200:], uint32(chunks.Len()/40))
		table = append(table, chunks.Bytes()...)
		plist.WriteString("<dict>")
		for _, pair := range [][2]string{{"Attributes", region.attributes}, {"CFName", region.cfName}, {"ID", region.id}, {"Name", region.name}} {
			plist.WriteString("<key>" + pair[0] + "</key><string>")
			if err := xml.EscapeText(&plist, []byte(pair[1])); err != nil {
				return err
			}
			plist.WriteString("</string>")
		}
		plist.WriteString("<key>Data</key><data>" + base64.StdEncoding.EncodeToString(table) + "</data></dict>")
		var blockCRC [4]byte
		be.PutUint32(blockCRC[:], logicalCRC.Sum32())
		_, _ = masterCRC.Write(blockCRC[:])
		if plist.Len() > 16<<20 {
			return filesystem.ErrLimit
		}
	}
	// Require EOF, so an incorrect size does not silently truncate a source.
	var extra [1]byte
	n, err := source.Read(extra[:])
	if n == 0 && err != nil && err != io.EOF {
		return err
	}
	if n != 0 || err != io.EOF {
		return fmt.Errorf("UDIF source size mismatch: %w", filesystem.ErrCorrupt)
	}
	plist.WriteString("</array>")
	if layout.plst != nil {
		plist.WriteString("<key>plst</key><array><dict><key>Attributes</key><string>0x0050</string><key>ID</key><string>0</string><key>Name</key><string></string><key>Data</key><data>" + base64.StdEncoding.EncodeToString(layout.plst) + "</data></dict></array>")
	}
	plist.WriteString("</dict></dict></plist>\n")
	if plist.Len() > 16<<20 {
		return filesystem.ErrLimit
	}
	if err = write(plist.Bytes()); err != nil {
		return err
	}
	be := binary.BigEndian
	checksum := func(b []byte, crc uint32) { be.PutUint32(b, 2); be.PutUint32(b[4:], 32); be.PutUint32(b[8:], crc) }
	footer := make([]byte, 512)
	copy(footer, "koly")
	be.PutUint32(footer[4:], 4)
	be.PutUint32(footer[8:], 512)
	be.PutUint32(footer[12:], 1)
	be.PutUint64(footer[32:], uint64(stored))
	be.PutUint32(footer[56:], 1)
	be.PutUint32(footer[60:], 1)
	checksum(footer[80:], dataCRC.Sum32())
	be.PutUint64(footer[216:], uint64(stored))
	be.PutUint64(footer[224:], uint64(plist.Len()))
	checksum(footer[352:], masterCRC.Sum32())
	be.PutUint32(footer[488:], layout.variant)
	be.PutUint64(footer[492:], uint64(size/512))
	return write(footer)
}
func allZero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
