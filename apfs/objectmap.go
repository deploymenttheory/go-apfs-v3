package apfs

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// resolve performs a predecessor search for (oid,xid) in the physical object
// map B-tree. It reads one node per level rather than loading the tree.
func (c *Container) resolve(omap PhysicalAddress, oid OID, xid XID) (PhysicalAddress, error) {
	h, err := c.object(omap, 11)
	if err != nil {
		return 0, err
	}
	address := PhysicalAddress(le.Uint64(h[48:]))
	seen := map[PhysicalAddress]bool{}
	var previousLevel uint16
	for depth := 0; depth < 32; depth++ {
		if seen[address] {
			return 0, corrupt("object map cycle", int64(address)*int64(c.BlockSize))
		}
		seen[address] = true
		kind := uint32(3)
		if depth == 0 {
			kind = 2
		}
		b, err := c.object(address, kind)
		if err != nil {
			return 0, err
		}
		flags, level, count := le.Uint16(b[32:]), le.Uint16(b[34:]), le.Uint32(b[36:])
		leaf := flags&2 != 0
		if le.Uint32(b[28:]) != 11 || flags&4 == 0 || leaf != (level == 0) || (depth > 0 && level+1 != previousLevel) {
			return 0, corrupt("object map node header", 0)
		}
		previousLevel = level
		toc, tocSize := 56+int(le.Uint16(b[40:])), int(le.Uint16(b[42:]))
		end := len(b)
		if flags&1 != 0 {
			end -= 40
		}
		keys := toc + tocSize
		if toc > end || keys > end || int(count) > tocSize/4 {
			return 0, corrupt("object map table", 0)
		}
		var found []byte
		var lastOID OID
		var lastXID XID
		for n := 0; n < int(count); n++ {
			entry := b[toc+n*4 : toc+n*4+4]
			kp := keys + int(le.Uint16(entry))
			vp := end - int(le.Uint16(entry[2:]))
			vl := 8
			if leaf {
				vl = 16
			}
			if kp < keys || kp+16 > end || vp < keys || vp+vl > end || kp+16 > vp {
				return 0, corrupt("object map record", 0)
			}
			ko, kx := OID(le.Uint64(b[kp:])), XID(le.Uint64(b[kp+8:]))
			if n > 0 && (ko < lastOID || (ko == lastOID && kx <= lastXID)) {
				return 0, corrupt("object map key order", 0)
			}
			lastOID, lastXID = ko, kx
			if ko > oid || (ko == oid && kx > xid) {
				break
			}
			if !leaf || ko == oid {
				found = b[vp : vp+vl]
			}
		}
		if found == nil {
			return 0, corrupt("unmapped volume object", 0)
		}
		if leaf {
			flags := le.Uint32(found)
			if flags&1 != 0 {
				return 0, corrupt("deleted volume object mapping", 0)
			}
			if flags&^uint32(1) != 0 {
				return 0, fmt.Errorf("object map flags %#x: %w", flags, filesystem.ErrUnsupported)
			}
			if le.Uint32(found[4:]) != c.BlockSize {
				return 0, fmt.Errorf("multi-block volume superblock: %w", filesystem.ErrUnsupported)
			}
			return PhysicalAddress(le.Uint64(found[8:])), nil
		}
		address = PhysicalAddress(le.Uint64(found))
	}
	return 0, filesystem.ErrLimit
}
