package apfs

import (
	"bytes"
	"math/bits"
)

// Each allocation bitmap is bounded independently of payload size. Stream
// ownership is represented by extent records, never one map entry per block.
const maxMutationBitmapBytes = 64 << 20

// claimBits requires matching bit alignment, as provided by APFS chunk ranges.
// It returns the first conflicting relative bit without mutating that byte.
func claimBits(allocated, claimed []byte, allocatedStart, claimedStart, count uint64) (uint64, bool) {
	for off := uint64(0); off < count; {
		a, c := allocatedStart+off, claimedStart+off
		shift := a % 8
		take := min(8-shift, count-off)
		mask := byte(((uint16(1) << take) - 1) << shift)
		bad := (^allocated[a/8] | claimed[c/8]) & mask
		if bad != 0 {
			return off + uint64(bits.TrailingZeros8(bad)) - shift, false
		}
		claimed[c/8] |= mask
		off += take
	}
	return 0, true
}

func equalBitmap(a, b []byte, count uint64) bool {
	full := count / 8
	if !bytes.Equal(a[:full], b[:full]) {
		return false
	}
	if count%8 == 0 {
		return true
	}
	mask := byte((uint16(1) << (count % 8)) - 1)
	return a[full]&mask == b[full]&mask
}
