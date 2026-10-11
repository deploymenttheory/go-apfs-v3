// Package buildsize supplies automatic capacity policy for fresh filesystems.
package buildsize

// These are construction padding, not on-disk allocation or volume reserves.
// APFS needs more room for subsequent copy-on-write transactions than HFS+.
// The policy is original Go, qualified against Apple construction and continued
// allocation; Apple's private DiskImages sizing algorithm is not a source port.
// See docs/image-sizing.md for the independent native measurements.
const (
	APFSPaddingBlocks uint64 = (8 << 20) / 4096
	HFSPaddingBlocks  uint64 = (2 << 20) / 4096
)

// AutomaticBlocks includes all allocated filesystem blocks, unused explicit
// volume reservations, format-specific padding, and 12.5% growth allowance.
// Call again whenever capacity-dependent metadata changes the allocation.
// Unused volume reservations do not inflate the proportional allowance.
func AutomaticBlocks(allocated, reserved, padding uint64) uint64 {
	return allocated + reserved + padding + (allocated+7)/8
}
