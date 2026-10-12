package copyfile

import (
	"encoding/binary"
	"github.com/deploymenttheory/go-apfs-v3/block"
)

// CopyableCompression follows the pinned copyfile_xattr header check. Inactive
// metadata is opaque: its declared compressed contents never replace file data.
func CopyableCompression(value block.Source) (bool, error) {
	if value.Size() < 16 {
		return false, nil
	}
	var header [16]byte
	if err := block.ReadFull(value, header[:], 0); err != nil {
		return false, err
	}
	if binary.LittleEndian.Uint32(header[:]) != 0x636d7066 {
		return false, nil
	}
	switch binary.LittleEndian.Uint32(header[4:]) {
	case 1, 3, 4, 7, 8, 9, 10, 11, 12, 13, 14:
		return true, nil
	}
	return false, nil
}
