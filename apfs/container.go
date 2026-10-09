// Package apfs interprets Apple File System structures. This initial reader
// supports structural inspection and bounded, read-only file access.
// Layouts follow Apple's Apple File System Reference (2020-06-22).
package apfs

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

var le = binary.LittleEndian

// OID, XID and PhysicalAddress are deliberately distinct: virtual object
// identifiers must be resolved through an object map at a selected transaction.
type OID uint64
type XID uint64
type PhysicalAddress uint64

type Container struct {
	UUID                           string          `json:"uuid"`
	BlockSize                      uint32          `json:"blockSize"`
	BlockCount                     uint64          `json:"blockCount"`
	XID                            XID             `json:"xid"`
	Checkpoint                     PhysicalAddress `json:"checkpoint"`
	Volumes                        []Volume        `json:"volumes"`
	source                         block.Source
	id                             [16]byte
	keylockerStart, keylockerCount uint64
}

type Volume struct {
	OID                        OID    `json:"oid"`
	UUID                       string `json:"uuid"`
	Name                       string `json:"name"`
	CaseSensitive              bool   `json:"caseSensitive"`
	Role                       uint16 `json:"role"`
	VolumeGroup                string `json:"volumeGroup"`
	Flags                      uint64 `json:"flags"`
	CompatibleFeatures         uint64 `json:"compatibleFeatures"`
	ReadOnlyCompatibleFeatures uint64 `json:"readOnlyCompatibleFeatures"`
	IncompatibleFeatures       uint64 `json:"incompatibleFeatures"`
	Encrypted                  bool   `json:"encrypted"`
	Sealed                     bool   `json:"sealed"`
	Files                      uint64 `json:"files"`
	Directories                uint64 `json:"directories"`
	Snapshots                  uint64 `json:"snapshots"`
	container                  *Container
	omap                       PhysicalAddress
	root                       OID
	rootType                   uint32
	id                         [16]byte
	keys                       *volumeKeys
	xid                        XID
	snapMeta                   OID
	snapMetaType               uint32
	snapMetaExt                OID
}

// Open borrows source. It selects the highest valid container superblock in
// the contiguous checkpoint descriptor area. Once selected, failure to resolve
// its volumes is an error; it never silently falls back to an older view.
func Open(source block.Source) (*Container, error) {
	if source == nil || source.Size() < 4096 {
		return nil, corrupt("container size", 0)
	}
	h := make([]byte, 4096)
	if err := block.ReadFull(source, h, 0); err != nil {
		return nil, err
	}
	if string(h[32:36]) != "NXSB" {
		return nil, corrupt("container signature", 0)
	}
	bs := le.Uint32(h[36:])
	if bs < 4096 || bs > 65536 || bs&(bs-1) != 0 {
		return nil, corrupt("container block size", 0)
	}
	c := &Container{source: source, BlockSize: bs, BlockCount: le.Uint64(h[40:])}
	if c.BlockCount == 0 || c.BlockCount > uint64(source.Size()/int64(bs)) {
		return nil, corrupt("container block count", 0)
	}
	h, err := c.object(0, 1)
	if err != nil {
		return nil, err
	}
	count, base := le.Uint32(h[104:]), le.Uint64(h[112:])
	if count&0x80000000 != 0 {
		return nil, fmt.Errorf("checkpoint descriptor tree: %w", filesystem.ErrUnsupported)
	}
	if count > 65536 {
		return nil, filesystem.ErrLimit
	}
	if base > c.BlockCount || uint64(count) > c.BlockCount-base {
		return nil, corrupt("checkpoint area", 0)
	}
	selected := h
	for n := uint64(0); n < uint64(count); n++ {
		b := make([]byte, bs)
		if err := block.ReadFull(source, b, int64(base+n)*int64(bs)); err != nil {
			return nil, err
		}
		if string(b[32:36]) != "NXSB" || !validChecksum(b) {
			continue
		}
		if le.Uint32(b[24:])&0xffff != 1 || le.Uint32(b[36:]) != bs || le.Uint64(b[40:]) != c.BlockCount || !bytes.Equal(h[72:88], b[72:88]) {
			continue
		}
		if le.Uint64(b[16:]) > le.Uint64(selected[16:]) {
			selected = b
			c.Checkpoint = PhysicalAddress(base + n)
		}
	}
	c.UUID = uuid(selected[72:88])
	copy(c.id[:], selected[72:88])
	c.keylockerStart, c.keylockerCount = le.Uint64(selected[1296:]), le.Uint64(selected[1304:])
	c.XID = XID(le.Uint64(selected[16:]))
	// NX_INCOMPAT_VERSION2 is the current format. VERSION1 and FUSION
	// require distinct interpretation; read-only compatible bits do not.
	if flags := le.Uint64(selected[64:]); flags != 2 {
		return nil, fmt.Errorf("container incompatible features %#x: %w", flags, filesystem.ErrUnsupported)
	}
	if le.Uint32(selected[180:]) > 100 {
		return nil, corrupt("container volume slots", 0)
	}
	omap := PhysicalAddress(le.Uint64(selected[160:]))
	for n := 0; n < 100; n++ {
		oid := OID(le.Uint64(selected[184+n*8:]))
		if oid == 0 {
			continue
		}
		mapping, err := c.resolve(omap, oid, c.XID)
		if err != nil {
			return nil, err
		}
		if mapping.encrypted {
			return nil, corrupt("encrypted volume superblock mapping", 0)
		}
		address := mapping.address
		b, err := c.object(address, 13)
		if err != nil {
			return nil, err
		}
		if string(b[32:36]) != "APSB" || OID(le.Uint64(b[8:])) != oid || XID(le.Uint64(b[16:])) > c.XID {
			return nil, corrupt("volume superblock", int64(address)*int64(bs))
		}
		v := c.volume(b, c.XID)
		c.Volumes = append(c.Volumes, v)
	}
	return c, nil
}

// volume decodes an already verified current or snapshot superblock.
func (c *Container) volume(b []byte, xid XID) Volume {
	name := b[704:960]
	if end := bytes.IndexByte(name, 0); end >= 0 {
		name = name[:end]
	}
	features, flags := le.Uint64(b[56:]), le.Uint64(b[264:])
	v := Volume{OID: OID(le.Uint64(b[8:])), UUID: uuid(b[240:256]), Name: string(name), Role: le.Uint16(b[964:]), VolumeGroup: uuid(b[1008:1024]), CaseSensitive: features&1 == 0, Flags: flags, CompatibleFeatures: le.Uint64(b[40:]), ReadOnlyCompatibleFeatures: le.Uint64(b[48:]), IncompatibleFeatures: features, Encrypted: flags&1 == 0, Sealed: features&0x20 != 0, Files: le.Uint64(b[184:]), Directories: le.Uint64(b[192:]), Snapshots: le.Uint64(b[216:])}
	copy(v.id[:], b[240:256])
	v.container, v.omap, v.root, v.rootType = c, PhysicalAddress(le.Uint64(b[128:])), OID(le.Uint64(b[136:])), le.Uint32(b[116:])
	v.xid, v.snapMeta, v.snapMetaType, v.snapMetaExt = xid, OID(le.Uint64(b[152:])), le.Uint32(b[124:]), OID(le.Uint64(b[1000:]))
	return v
}

func (c *Container) object(address PhysicalAddress, kind uint32) ([]byte, error) {
	if uint64(address) >= c.BlockCount {
		return nil, corrupt("object address", 0)
	}
	off := int64(address) * int64(c.BlockSize)
	b := make([]byte, c.BlockSize)
	if err := block.ReadFull(c.source, b, off); err != nil {
		return nil, err
	}
	if !validChecksum(b) {
		return nil, corrupt("object checksum", off)
	}
	if le.Uint32(b[24:])&0xffff != kind {
		return nil, corrupt("object type", off)
	}
	return b, nil
}

func validChecksum(b []byte) bool {
	if len(b) < 8 || len(b)%4 != 0 {
		return false
	}
	const mod = uint64(0xffffffff)
	var a, s uint64
	for n := 8; n < len(b); n += 4 {
		a = (a + uint64(le.Uint32(b[n:]))) % mod
		s = (s + a) % mod
	}
	x := mod - (a+s)%mod
	y := mod - (a+x)%mod
	return le.Uint64(b) == (y<<32 | x)
}

func corrupt(structure string, offset int64) error {
	return &filesystem.Error{Op: "read", Structure: "APFS " + structure, Offset: offset, Err: filesystem.ErrCorrupt}
}
func uuid(b []byte) string {
	return fmt.Sprintf("%X-%X-%X-%X-%X", b[:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
