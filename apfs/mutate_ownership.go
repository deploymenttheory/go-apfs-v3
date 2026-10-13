package apfs

import (
	"bytes"
	"fmt"
	"math/bits"
	"slices"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// Each allocation bitmap is bounded independently of payload size. Stream
// ownership is represented by extent records, never one map entry per block.
const maxMutationBitmapBytes = 64 << 20

type ownedRange struct{ start, end, owner uint64 }

func validateExtentOwners(physical, streams []ownedRange) error {
	order := func(a, b ownedRange) int {
		if a.start < b.start {
			return -1
		}
		if a.start > b.start {
			return 1
		}
		return 0
	}
	slices.SortFunc(physical, order)
	slices.SortFunc(streams, order)
	for _, ranges := range [][]ownedRange{physical, streams} {
		for i, r := range ranges {
			if r.start >= r.end || r.owner == 0 || i > 0 && ranges[i-1].end > r.start {
				return corrupt("overlapping or empty owned extent", int64(r.start)*4096)
			}
		}
	}
	i, j := 0, 0
	for i < len(physical) && j < len(streams) {
		p, s := &physical[i], &streams[j]
		if p.start != s.start || p.owner != s.owner {
			return fmt.Errorf("file/physical extent ownership at %d: stream owner=%d, physical owner=%d: %w", s.start, s.owner, p.owner, filesystem.ErrCorrupt)
		}
		end := min(p.end, s.end)
		p.start, s.start = end, end
		if p.start == p.end {
			i++
		}
		if s.start == s.end {
			j++
		}
	}
	if i != len(physical) || j != len(streams) {
		return corrupt("unowned physical extent or missing stream extent", 0)
	}
	return nil
}

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
