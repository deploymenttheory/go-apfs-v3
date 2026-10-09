package decmpfs

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"io"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/codec/lz4"
	"github.com/deploymenttheory/go-apfs-v3/internal/codec/lzbitmap"
	"github.com/deploymenttheory/go-apfs-v3/internal/codec/lzfse"
)

func decode(kind uint32, dst, src []byte) error {
	if kind == 1 {
		if len(src) != len(dst) {
			return bad("stored size")
		}
		copy(dst, src)
		return nil
	}
	if len(src) == 0 {
		return bad("empty block")
	}
	stored := false
	switch kind {
	case 3, 4, 13, 14, 15, 16:
		stored = src[0] == 0xff
	case 7, 8:
		stored = src[0] == 6
	case 9, 10:
		stored = src[0] == 0xcc
	case 11, 12:
		stored = src[0] == 0xff
	}
	if stored {
		if len(src)-1 != len(dst) {
			return bad("stored block size")
		}
		copy(dst, src[1:])
		return nil
	}
	var n int
	var err error
	switch kind {
	case 3, 4:
		n, err = inflate(dst, src)
	case 7, 8:
		n, err = lzfse.DecodeLZVN(dst, src)
	case 11, 12:
		n, err = lzfse.Decode(dst, src)
	case 13, 14:
		n, err = lzbitmap.Decode(dst, src)
	case 15, 16:
		n, err = lz4.DecompressInto(dst, src)
	default:
		return bad("stored marker")
	}
	if err != nil {
		return fmt.Errorf("decmpfs type %d: %w: %w", kind, filesystem.ErrCorrupt, err)
	}
	if n != len(dst) {
		return bad("decoded size")
	}
	return nil
}

// Native decmpfs zlib blocks can omit the Adler-32 trailer. A present trailer
// must match. bytes.Reader implements ReadByte so flate cannot read ahead into
// the trailer; the bounded destination detects excess output independently.
func inflate(dst, src []byte) (int, error) {
	if len(src) < 2 || src[0]&15 != 8 || src[0]>>4 > 7 || binary.BigEndian.Uint16(src[:2])%31 != 0 || src[1]&32 != 0 {
		return 0, bad("zlib header")
	}
	input := bytes.NewReader(src[2:])
	r := flate.NewReader(input)
	defer func() { _ = r.Close() }()
	n, err := io.ReadFull(r, dst)
	if err != nil {
		return n, err
	}
	var extra [1]byte
	if count, err := r.Read(extra[:]); count != 0 || err != io.EOF {
		return n, bad("deflate size or terminator")
	}
	if input.Len() != 0 {
		if input.Len() != 4 || binary.BigEndian.Uint32(src[len(src)-4:]) != adler32.Checksum(dst) {
			return n, bad("zlib checksum or trailing bytes")
		}
	}
	return n, nil
}
