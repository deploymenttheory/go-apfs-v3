package decmpfs

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto/sha256"
	"hash"
	"io"
	"io/fs"
	"math"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Encoded describes type-3 attribute storage or type-4 Resource Manager storage.
// Reason is nonempty when ordinary data storage should be kept instead. The
// caller discards resource output in that case, and on every error.
type Encoded struct {
	Attribute     []byte
	ResourceBytes int64
	LogicalSHA256 [32]byte
	Reason        string
}

// Encode writes a deterministic zlib decmpfs representation. Memory is bounded
// by one 64 KiB input block and codec scratch; descriptors are patched directly
// in an empty seekable resource destination. No logical-data staging is needed.
// allowResource must be false when a file has an independent resource fork.
func Encode(ctx context.Context, source block.Source, resource io.WriteSeeker, allowResource bool) (Encoded, error) {
	var result Encoded
	if source == nil || resource == nil {
		return result, fs.ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	size := source.Size()
	if size < 0 || size > 1<<40 {
		return result, filesystem.ErrLimit
	}
	if size == 0 {
		result.Reason = "empty-file"
		return result, nil
	}
	buffer := make([]byte, blockSize)
	var packed bytes.Buffer
	z, err := zlib.NewWriterLevel(&packed, zlib.DefaultCompression)
	if err != nil {
		return result, err
	}
	defer func() { _ = z.Close() }()
	digest := sha256.New()
	encodeBlock := func(off int64) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data := buffer[:min(int64(blockSize), size-off)]
		if err := block.ReadFull(source, data, off); err != nil {
			return nil, err
		}
		_, _ = digest.Write(data)
		packed.Reset()
		z.Reset(&packed)
		if _, err := z.Write(data); err != nil {
			return nil, err
		}
		if err := z.Close(); err != nil {
			return nil, err
		}
		if packed.Len() >= len(data)+1 {
			return append([]byte{0xff}, data...), nil
		}
		return packed.Bytes(), nil
	}
	var first []byte
	if size <= blockSize {
		first, err = encodeBlock(0)
		if err != nil {
			return result, err
		}
		if len(first)+16 <= maxAttribute {
			if int64(len(first)+16) >= size {
				result.Reason = "not-smaller"
				return result, nil
			}
			result.Attribute = diskHeader(3, uint64(size))
			result.Attribute = append(result.Attribute, first...)
			result.LogicalSHA256 = sum(digest)
			return result, nil
		}
	}
	if !allowResource {
		result.Reason = "independent-resource-fork"
		return result, nil
	}
	if end, err := resource.Seek(0, io.SeekEnd); err != nil {
		return result, err
	} else if end != 0 {
		return result, fs.ErrInvalid
	}
	blocks := (size + blockSize - 1) / blockSize
	end := int64(264) + blocks*8
	if end+50 > math.MaxUint32 {
		result.Reason = "resource-size-limit"
		return result, nil
	}
	if _, err = resource.Seek(end, io.SeekStart); err != nil {
		return result, err
	}
	for i := int64(0); i < blocks; i++ {
		data := first
		if first == nil || i != 0 {
			data, err = encodeBlock(i * blockSize)
		}
		if err != nil {
			return result, err
		}
		if end+int64(len(data))+50 > math.MaxUint32 {
			result.Reason = "resource-size-limit"
			return result, nil
		}
		if err = writeEncoded(ctx, resource, data); err != nil {
			return result, err
		}
		var descriptor [8]byte
		le.PutUint32(descriptor[:], uint32(end-260))
		le.PutUint32(descriptor[4:], uint32(len(data)))
		if _, err = resource.Seek(264+i*8, io.SeekStart); err != nil {
			return result, err
		}
		if err = writeEncoded(ctx, resource, descriptor[:]); err != nil {
			return result, err
		}
		end += int64(len(data))
		if _, err = resource.Seek(end, io.SeekStart); err != nil {
			return result, err
		}
	}
	// One cmpf resource, with the independently observed Resource Manager map.
	mapping := make([]byte, 50)
	be.PutUint16(mapping[24:], 28)
	be.PutUint16(mapping[26:], 50)
	copy(mapping[30:], "cmpf")
	be.PutUint16(mapping[36:], 10)
	be.PutUint16(mapping[38:], 1)
	be.PutUint16(mapping[40:], 0xffff)
	if err = writeEncoded(ctx, resource, mapping); err != nil {
		return result, err
	}
	header := make([]byte, 264)
	be.PutUint32(header, 256)
	be.PutUint32(header[4:], uint32(end))
	be.PutUint32(header[8:], uint32(end-256))
	be.PutUint32(header[12:], 50)
	be.PutUint32(header[256:], uint32(end-260))
	le.PutUint32(header[260:], uint32(blocks))
	if _, err = resource.Seek(0, io.SeekStart); err != nil {
		return result, err
	}
	if err = writeEncoded(ctx, resource, header); err != nil {
		return result, err
	}
	result.ResourceBytes = end + 50
	if result.ResourceBytes+16 >= size {
		result.Reason = "not-smaller"
		return result, nil
	}
	result.Attribute = diskHeader(4, uint64(size))
	result.LogicalSHA256 = sum(digest)
	return result, ctx.Err()
}

func diskHeader(kind uint32, size uint64) []byte {
	b := make([]byte, 16)
	le.PutUint32(b, 0x636d7066)
	le.PutUint32(b[4:], kind)
	le.PutUint64(b[8:], size)
	return b
}

func sum(h hash.Hash) (out [32]byte) { h.Sum(out[:0]); return out }

func writeEncoded(ctx context.Context, w io.Writer, b []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		return io.ErrShortWrite
	}
	return err
}
