package diskimage

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/base64"
	"encoding/binary"
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
	if out == nil || source == nil || size <= 0 || size%512 != 0 || size > 1<<40 {
		return fs.ErrInvalid
	}
	if format != "UDRO" && format != "UDZO" {
		return fmt.Errorf("UDIF format %q: %w", format, filesystem.ErrUnsupported)
	}
	const chunkSize = 4 << 20
	raw := make([]byte, chunkSize)
	var chunks bytes.Buffer
	dataCRC, logicalCRC := crc32.NewIEEE(), crc32.NewIEEE()
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
	record := func(kind uint32, off, length, at, count int64) {
		b := make([]byte, 40)
		binary.BigEndian.PutUint32(b, kind)
		for i, v := range []int64{off / 512, length / 512, at, count} {
			binary.BigEndian.PutUint64(b[8+i*8:], uint64(v))
		}
		chunks.Write(b)
	}
	for off := int64(0); off < size; {
		if err := ctx.Err(); err != nil {
			return err
		}
		b := raw[:min(int64(len(raw)), size-off)]
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
	// Require EOF, so an incorrect size does not silently truncate a source.
	var extra [1]byte
	n, err := source.Read(extra[:])
	if n != 0 || err != io.EOF {
		return fmt.Errorf("UDIF source size mismatch: %w", filesystem.ErrCorrupt)
	}
	record(0xffffffff, size, 0, stored, 0)
	table := make([]byte, 204)
	copy(table, "mish")
	be := binary.BigEndian
	be.PutUint32(table[4:], 1)
	be.PutUint64(table[16:], uint64(size/512))
	be.PutUint32(table[32:], chunkSize/512+8)
	be.PutUint32(table[36:], 0xfffffffe)
	checksum := func(b []byte, crc uint32) { be.PutUint32(b, 2); be.PutUint32(b[4:], 32); be.PutUint32(b[8:], crc) }
	checksum(table[64:], logicalCRC.Sum32())
	be.PutUint32(table[200:], uint32(chunks.Len()/40))
	table = append(table, chunks.Bytes()...)
	plist := []byte("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict><key>resource-fork</key><dict><key>blkx</key><array><dict><key>Attributes</key><string>0x0050</string><key>CFName</key><string>whole disk (Apple_HFS : 0)</string><key>ID</key><string>0</string><key>Name</key><string>whole disk (Apple_HFS : 0)</string><key>Data</key><data>" + base64.StdEncoding.EncodeToString(table) + "</data></dict></array></dict></dict></plist>\n")
	if len(plist) > 16<<20 {
		return filesystem.ErrLimit
	}
	if err = write(plist); err != nil {
		return err
	}
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
	be.PutUint64(footer[224:], uint64(len(plist)))
	var blockCRC [4]byte
	be.PutUint32(blockCRC[:], logicalCRC.Sum32())
	checksum(footer[352:], crc32.ChecksumIEEE(blockCRC[:]))
	be.PutUint32(footer[488:], 2)
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
