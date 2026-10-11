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
	Format           string      `json:"format"`
	SourceFormat     string      `json:"sourceFormat"`
	DiskBytes        int64       `json:"diskBytes"`
	DiskSHA256       string      `json:"diskSHA256"`
	SourceEncryption *Encryption `json:"sourceEncryption,omitempty"`
	Encryption       *Encryption `json:"encryption,omitempty"`
}

// Repack borrows immutable, complete image storage and writes a new UDRO/UDZO
// envelope. Every decoded disk sector is retained, including unallocated sectors.
// It never unlocks APFS, interprets filesystem trees or repairs a disk. Encrypted
// DMG envelopes and unsupported container resources are refused. Source CRCs and
// complete block coverage are checked before output. The caller discards all
// output on error and keeps source open and unchanged until this call returns.
func Repack(ctx context.Context, out io.Writer, source block.Source, format string) (RepackReport, error) {
	report, err := RepackWithOptions(ctx, out, source, RepackOptions{Format: format})
	if errors.Is(err, filesystem.ErrAuthentication) {
		return report, fmt.Errorf("encrypted DMG repacking requires explicit credentials and output policy: %w", filesystem.ErrUnsupported)
	}
	return report, err
}

// RepackOptions keeps image passwords separate from APFS volume credentials.
// A nil SourcePassword means none supplied; a non-nil empty slice explicitly
// requests an empty password. Decrypt must be true to remove source encryption.
// Passwords are borrowed, never modified, and never included in reports.
type RepackOptions struct {
	Format         string
	SourcePassword []byte `json:"-"`
	Encryption     *EncryptionOptions
	Decrypt        bool
}

// RepackWithOptions preserves every decoded sector while replacing the image
// envelope. Encrypted output requires an empty io.WriteSeeker. No APFS password
// is used and separately encrypted APFS sectors remain opaque and unchanged.
func RepackWithOptions(ctx context.Context, out io.Writer, source block.Source, o RepackOptions) (RepackReport, error) {
	var report RepackReport
	if out == nil || source == nil {
		return report, fs.ErrInvalid
	}
	if o.Encryption != nil {
		if err := o.Encryption.Validate(); err != nil {
			return report, err
		}
		if o.Decrypt {
			return report, fs.ErrInvalid
		}
	}
	format := o.Format
	if format == "" {
		format = "UDZO"
	}
	if format != "UDRO" && format != "UDZO" {
		return report, filesystem.ErrUnsupported
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	var image *Image
	var err error
	if o.SourcePassword != nil {
		image, err = NewWithPassword(ctx, source, o.SourcePassword)
	} else {
		image, err = New(source)
	}
	if err != nil {
		return report, err
	}
	defer func() { _ = image.Close() }()
	if image.envelope != nil {
		if o.Encryption == nil && !o.Decrypt {
			return report, fmt.Errorf("encrypted source requires an explicit output encryption policy: %w", fs.ErrInvalid)
		}
		if err = admitRepackEnvelope(source, image.envelope); err != nil {
			return report, err
		}
		source = image.envelope
	}
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
	produce := func(w io.Writer) error {
		return encode(ctx, w, io.TeeReader(reader, hash), image.Size(), format, layout)
	}
	if o.Encryption != nil {
		seeker, ok := out.(io.WriteSeeker)
		if !ok {
			return report, fmt.Errorf("encrypted output requires a seekable destination: %w", fs.ErrInvalid)
		}
		_, err = Encrypt(ctx, seeker, *o.Encryption, produce)
	} else {
		err = produce(out)
	}
	if err != nil {
		return report, err
	}
	if hex.EncodeToString(hash.Sum(nil)) != want {
		return report, corrupt("repack source changed")
	}
	report = RepackReport{Format: format, SourceFormat: image.Format, DiskBytes: image.Size(), DiskSHA256: want, SourceEncryption: image.Encryption}
	if o.Encryption != nil {
		report.Encryption = &Encryption{Version: 2, Cipher: "AES-CBC", KeyBits: o.Encryption.KeyBits, BlockSize: 512}
	}
	return report, nil
}

type contextReader struct {
	ctx    context.Context
	source io.Reader
}

// Password rewrapping admits only the independently observed password-only
// envelope. Refuse certificate/keybag records and unknown nonzero header data
// instead of silently dropping credentials or other resources during repacking.
func admitRepackEnvelope(source block.Source, envelope *encryptedImage) error {
	if envelope.offset > 1<<20 {
		return filesystem.ErrLimit
	}
	b := make([]byte, envelope.offset)
	if err := block.ReadFull(source, b, 0); err != nil {
		return err
	}
	be := binary.BigEndian
	if be.Uint32(b[72:]) != 1 || be.Uint32(b[76:]) != 1 {
		return fmt.Errorf("repacking requires one password record: %w", filesystem.ErrUnsupported)
	}
	start, length := be.Uint64(b[80:]), be.Uint64(b[88:])
	// readEnvelope already validated all ranges and the password record.
	r := b[start : start+length]
	salt, iv, wrapped := be.Uint32(r[12:]), be.Uint32(r[48:]), be.Uint32(r[100:])
	if !allZero(b[96:start]) || !allZero(b[start+length:]) ||
		!allZero(r[16+salt:48]) || !allZero(r[52+iv:84]) || !allZero(r[104+wrapped:]) {
		return fmt.Errorf("unaccounted encrypted image header bytes: %w", filesystem.ErrUnsupported)
	}
	blockSize := int64(envelope.info.BlockSize)
	if source.Size() != envelope.offset+(envelope.size+blockSize-1)/blockSize*blockSize {
		return fmt.Errorf("unaccounted encrypted image trailing bytes: %w", filesystem.ErrUnsupported)
	}
	return nil
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
