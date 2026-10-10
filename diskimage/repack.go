package diskimage

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// RepackReport describes preserved logical disk bytes, not a rebuilt filesystem.
type RepackReport struct {
	Format       string `json:"format"`
	SourceFormat string `json:"sourceFormat"`
	DiskBytes    int64  `json:"diskBytes"`
	DiskSHA256   string `json:"diskSHA256"`
}

// Repack borrows immutable, complete image storage and writes a new UDRO/UDZO
// envelope. Every decoded disk sector is retained, including unallocated sectors.
// It never unlocks APFS, interprets filesystem trees or repairs a disk. Encrypted
// DMG envelopes and unsupported container resources are refused. Source CRCs and
// complete block coverage are checked before output. The caller discards all
// output on error and keeps source open and unchanged until this call returns.
func Repack(ctx context.Context, out io.Writer, source block.Source, format string) (RepackReport, error) {
	var report RepackReport
	if out == nil || source == nil {
		return report, fs.ErrInvalid
	}
	if format == "" {
		format = "UDZO"
	}
	if format != "UDRO" && format != "UDZO" {
		return report, filesystem.ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	image, err := New(source)
	if errors.Is(err, filesystem.ErrAuthentication) {
		return report, fmt.Errorf("encrypted DMG repacking: %w", filesystem.ErrUnsupported)
	}
	if err != nil {
		return report, err
	}
	defer func() { _ = image.Close() }()
	layout, err := repackLayout(source, image)
	if err != nil {
		return report, err
	}
	if image.decoded != nil {
		if err = verifyUDIF(ctx, source, image.decoded, layout); err != nil {
			return report, err
		}
	}
	hash := sha256.New()
	reader := &contextReader{ctx: ctx, source: io.NewSectionReader(image.source, 0, image.Size())}
	if _, err = io.CopyBuffer(hash, reader, make([]byte, 128<<10)); err != nil {
		return report, err
	}
	want := hex.EncodeToString(hash.Sum(nil))
	hash.Reset()
	reader.source = io.NewSectionReader(image.source, 0, image.Size())
	if err = encode(ctx, out, io.TeeReader(reader, hash), image.Size(), format, layout); err != nil {
		return report, err
	}
	if hex.EncodeToString(hash.Sum(nil)) != want {
		return report, corrupt("repack source changed")
	}
	return RepackReport{Format: format, SourceFormat: image.Format, DiskBytes: image.Size(), DiskSHA256: want}, nil
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.source.Read(p)
}

func repackLayout(source block.Source, image *Image) (encodingLayout, error) {
	if image.Size() <= 0 || image.Size()%512 != 0 || image.Size() > 1<<40 {
		return encodingLayout{}, filesystem.ErrLimit
	}
	if image.decoded != nil {
		return readRepackLayout(source, image.Size())
	}
	if image.PartitionMap != "none" {
		return rawDiskLayout(source, image)
	}
	layout := encodingLayout{variant: 1}
	hint := "whole disk (unknown partition type : 0)"
	if image.PartitionMap == "none" {
		// Recognize bare filesystems explicitly: do not reinterpret sparse images,
		// encrypted containers or arbitrary files as raw disk sectors.
		header := make([]byte, 4096)
		if source.Size() < int64(len(header)) {
			return layout, filesystem.ErrUnsupported
		}
		if err := block.ReadFull(source, header, 0); err != nil {
			return layout, err
		}
		switch {
		case string(header[32:36]) == "NXSB":
			hint = "whole disk (Apple_APFS : 0)"
		case string(header[1024:1026]) == "H+", string(header[1024:1026]) == "HX":
			hint = "whole disk (Apple_HFS : 0)"
		default:
			return layout, fmt.Errorf("unrecognized raw disk: %w", filesystem.ErrUnsupported)
		}
		layout.variant = 2
	}
	layout.blocks = []encodingBlock{{size: image.Size(), name: hint, cfName: hint, id: "0", attributes: "0x0050", descriptor: 0xfffffffe}}
	return layout, nil
}

// CRC type 2 is CRC32, expressed as 32 bits in the 128-byte checksum field.
// An absent native checksum is admitted only with a completely zero field.
func checkCRC(field []byte, actual uint32) error {
	be := binary.BigEndian
	if allZero(field) {
		return nil
	}
	if be.Uint32(field) != 2 || be.Uint32(field[4:]) != 32 || !allZero(field[12:]) {
		return fmt.Errorf("UDIF checksum profile: %w", filesystem.ErrUnsupported)
	}
	if be.Uint32(field[8:]) != actual {
		return corrupt("UDIF checksum mismatch")
	}
	return nil
}

func verifyUDIF(ctx context.Context, source block.Source, decoded *udif, layout encodingLayout) error {
	footer := make([]byte, 512)
	if err := block.ReadFull(source, footer, source.Size()-512); err != nil {
		return err
	}
	be := binary.BigEndian
	buffer := make([]byte, 128<<10)
	hashRange := func(h io.Writer, source io.ReaderAt, off, size int64) error {
		_, err := io.CopyBuffer(h, &contextReader{ctx, io.NewSectionReader(source, off, size)}, buffer)
		return err
	}
	data := crc32.NewIEEE()
	if err := hashRange(data, source, int64(be.Uint64(footer[24:])), int64(be.Uint64(footer[32:]))); err != nil {
		return err
	}
	if err := checkCRC(footer[80:216], data.Sum32()); err != nil {
		return err
	}
	master := crc32.NewIEEE()
	for _, region := range layout.blocks {
		logical := crc32.NewIEEE()
		table := region.table
		for at := 204; at < len(table); at += 40 {
			chunk := table[at : at+40]
			kind := be.Uint32(chunk)
			if kind == 2 || kind == 0xffffffff || kind == 0x7ffffffe {
				continue
			}
			start := region.start + int64(be.Uint64(chunk[8:]))*512
			size := int64(be.Uint64(chunk[16:])) * 512
			if err := hashRange(logical, decoded, start, size); err != nil {
				return err
			}
		}
		if err := checkCRC(table[64:200], logical.Sum32()); err != nil {
			return err
		}
		// Native master CRC covers the declared CRC values in resource order,
		// including zero for an absent block checksum.
		_, _ = master.Write(table[72:76])
	}
	return checkCRC(footer[352:488], master.Sum32())
}
