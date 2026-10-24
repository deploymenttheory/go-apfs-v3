package copyfile

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

var errHostAttributeConversion = errors.New("host named streams require unsupported attribute conversion")

// namedHostStreams validates FILE_STREAM_INFO without inventing a mapping from
// Windows alternate streams to macOS attributes or resource forks.
func namedHostStreams(buf []byte) (bool, error) {
	named := false
	seenDefault := false
	for count := 0; ; count++ {
		if count >= 4096 {
			return false, filesystem.ErrLimit
		}
		if len(buf) < 24 {
			return false, filesystem.ErrCorrupt
		}
		next, n := int(binary.LittleEndian.Uint32(buf)), int(binary.LittleEndian.Uint32(buf[4:]))
		if n == 0 || n%2 != 0 || n > len(buf)-24 || int64(binary.LittleEndian.Uint64(buf[8:])) < 0 || int64(binary.LittleEndian.Uint64(buf[16:])) < 0 {
			return false, filesystem.ErrCorrupt
		}
		// The unnamed data stream is exactly ::$DATA in UTF-16LE.
		if bytes.Equal(buf[24:24+n], []byte{':', 0, ':', 0, '$', 0, 'D', 0, 'A', 0, 'T', 0, 'A', 0}) {
			if seenDefault {
				return false, filesystem.ErrCorrupt
			}
			seenDefault = true
		} else {
			named = true
		}
		if next == 0 {
			return named, nil
		}
		if next%8 != 0 || next < 24+n || next > len(buf)-24 {
			return false, filesystem.ErrCorrupt
		}
		buf = buf[next:]
	}
}
