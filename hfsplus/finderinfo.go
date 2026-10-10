package hfsplus

import "github.com/deploymenttheory/go-apfs-v3/internal/finderinfo"

// Catalog storage retains the kernel-owned fields; the public attribute masks them.
func finderInfo(record []byte) []byte {
	return finderinfo.HFS(record[48:80], uint32(be.Uint16(record[42:])))
}
