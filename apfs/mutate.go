package apfs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"math"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// MutableSource must be an exclusively owned, unpublished copy. Any error
// invalidates that copy. imageedit supplies immutable input and final publication.
type MutableSource interface {
	block.Source
	io.WriterAt
}
type Change = filesystem.Change
type ChangeReport struct {
	VolumeID    string   `json:"volumeId"`
	Changed     []uint64 `json:"changed"`
	FreeBlocks  uint64   `json:"freeBlocks"`
	Transaction uint64   `json:"transaction"`
}
type mutation struct {
	ctx                     context.Context
	disk                    MutableSource
	c                       *Container
	v                       *Volume
	nx, super               []byte
	xid, next               uint64
	ephemeral               map[uint64]ephemeral
	space                   *mutationSpace
	fs, extents, vmap, cmap *cowTree
	volumeMap, containerMap []byte
	volumeAddress           uint64
	retired                 map[uint64]bool
	mappings                map[uint64]uint64
	allocated, freed        uint64
}
type readOnlyMutation struct{ block.Source }

func (readOnlyMutation) WriteAt([]byte, int64) (int, error) { return 0, fs.ErrPermission }

// ValidateMutation admits only the fully accounted single-volume plaintext
// profile. Unknown metadata or ownership is a refusal, never a guessed free block.
func ValidateMutation(ctx context.Context, source block.Source) error {
	_, e := openMutation(ctx, readOnlyMutation{source})
	return e
}
func Modify(ctx context.Context, disk MutableSource, changes []Change, when time.Time) (ChangeReport, error) {
	var report ChangeReport
	if disk == nil || len(changes) == 0 || len(changes) > 4096 || when.IsZero() || when.Nanosecond() != 0 {
		return report, fs.ErrInvalid
	}
	stamp, e := buildTime(when)
	if e != nil {
		return report, e
	}
	m, e := openMutation(ctx, disk)
	if e != nil {
		return report, e
	}
	report.VolumeID = m.v.UUID
	if e = m.space.reclaim(); e != nil {
		return report, e
	}
	for _, change := range changes {
		if e = ctx.Err(); e != nil {
			return report, e
		}
		id, e := m.applyChange(change, stamp)
		if e != nil {
			return report, e
		}
		if id != 0 {
			report.Changed = append(report.Changed, id)
		}
	}
	if e = m.commit(stamp); e != nil {
		return report, e
	}
	report.FreeBlocks, report.Transaction = m.space.free, m.xid
	return report, nil
}
func openMutation(ctx context.Context, disk MutableSource) (*mutation, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	c, e := Open(disk)
	if e != nil {
		return nil, e
	}
	if c.BlockSize != 4096 || c.BlockCount > 1<<18 || len(c.Volumes) != 1 || c.Checkpoint == 0 {
		return nil, fmt.Errorf("mutation requires a bounded single-volume APFS checkpoint: %w", filesystem.ErrUnsupported)
	}
	v := &c.Volumes[0]
	if v.Encrypted || v.Sealed || v.Snapshots != 0 || v.Role != 0 || v.ReserveBlocks != 0 || v.QuotaBlocks != 0 || v.CompatibleFeatures&^uint64(2) != 0 || v.ReadOnlyCompatibleFeatures != 0 || v.IncompatibleFeatures&^uint64(0xb) != 0 || v.rootType != 2 {
		return nil, fmt.Errorf("APFS volume mutation profile: %w", filesystem.ErrUnsupported)
	}
	nx, e := c.object(c.Checkpoint, 1)
	if e != nil {
		return nil, e
	}
	if le.Uint64(nx[48:]) != 0 || le.Uint64(nx[56:]) != 0 || le.Uint64(nx[1296:]) != 0 || le.Uint64(nx[1304:]) != 0 || le.Uint64(nx[1240:]) != 0 || le.Uint64(nx[1248:]) != 0 || le.Uint64(nx[1256:]) != 0 || le.Uint64(nx[1272:]) != 0 || le.Uint64(nx[1352:]) != 0 || le.Uint64(nx[1360:]) != 0 || le.Uint64(nx[1368:]) != 0 || le.Uint64(nx[1376:]) != 0 || le.Uint64(nx[1400:]) != 0 || le.Uint64(nx[1392:]) != 0 {
		return nil, fmt.Errorf("APFS mutation structural profile: %w", filesystem.ErrUnsupported)
	}
	if !bytes.Equal(nx[72:88], c.id[:]) || le.Uint64(nx[96:]) <= uint64(c.XID) || le.Uint64(nx[96:]) == math.MaxUint64 {
		return nil, corrupt("mutation transaction counter", 0)
	}
	for _, offset := range []int{104, 108} {
		n := le.Uint32(nx[offset:])
		if n == 0 || n&0x80000000 != 0 {
			return nil, fmt.Errorf("APFS mutation structural profile: %w", filesystem.ErrUnsupported)
		}
	}
	m := &mutation{ctx: ctx, disk: disk, c: c, v: v, nx: bytes.Clone(nx), xid: le.Uint64(nx[96:]), next: le.Uint64(nx[88:]), ephemeral: map[uint64]ephemeral{}, retired: map[uint64]bool{}, mappings: map[uint64]uint64{}}
	if e = m.loadEphemeral(); e != nil {
		return nil, e
	}
	m.containerMap, e = m.readObject(le.Uint64(nx[160:]), 11, 0x40000000)
	if e != nil {
		return nil, e
	}
	if le.Uint32(m.containerMap[36:]) != 0 || le.Uint64(m.containerMap[64:]) != 0 || le.Uint32(m.containerMap[32:])&^uint32(1) != 0 {
		return nil, fmt.Errorf("APFS mutation structural profile: %w", filesystem.ErrUnsupported)
	}
	physical := func(id uint64) ([]byte, uint64, error) { b, e := m.readObject(id, 0, 0x40000000); return b, id, e }
	m.cmap, e = loadCOWTree(ctx, le.Uint64(m.containerMap[48:]), 11, 0x40000000, physical, orderedPair, m.nextOID)
	if e != nil {
		return nil, e
	}
	mapping, e := c.resolve(PhysicalAddress(le.Uint64(nx[160:])), v.OID, c.XID)
	if e != nil {
		return nil, e
	}
	m.volumeAddress = uint64(mapping.address)
	m.super, e = c.object(mapping.address, 13)
	if e != nil {
		return nil, e
	}
	m.super = bytes.Clone(m.super)
	if le.Uint64(m.super[160:]) != 0 || le.Uint64(m.super[168:]) != 0 || le.Uint32(m.super[120:]) != 0x40000002 {
		return nil, fmt.Errorf("APFS unmount/revert/extent-tree profile: %w", filesystem.ErrUnsupported)
	}
	m.volumeMap, e = m.readObject(uint64(v.omap), 11, 0x40000000)
	if e != nil {
		return nil, e
	}
	if le.Uint32(m.volumeMap[36:]) != 0 || le.Uint32(m.volumeMap[32:])&^uint32(1) != 0 {
		return nil, fmt.Errorf("APFS mutation structural profile: %w", filesystem.ErrUnsupported)
	}
	m.vmap, e = loadCOWTree(ctx, le.Uint64(m.volumeMap[48:]), 11, 0x40000000, physical, orderedPair, m.nextOID)
	if e != nil {
		return nil, e
	}
	ordering := (&volumeLayout{options: VolumeSpec{CaseSensitive: v.CaseSensitive}}).recordLess
	virtual := func(id uint64) ([]byte, uint64, error) {
		mapping, e := c.resolve(v.omap, OID(id), v.xid)
		if e != nil {
			return nil, 0, e
		}
		if mapping.encrypted {
			return nil, 0, filesystem.ErrUnsupported
		}
		b := make([]byte, 4096)
		e = block.ReadFull(disk, b, int64(mapping.address)*4096)
		return b, uint64(mapping.address), e
	}
	m.fs, e = loadCOWTree(ctx, uint64(v.root), 14, 0, virtual, ordering, m.nextOID)
	if e != nil {
		return nil, e
	}
	m.extents, e = loadCOWTree(ctx, le.Uint64(m.super[144:]), 15, 0x40000000, physical, ordering, m.nextOID)
	if e != nil {
		return nil, e
	}
	if e = m.loadSpace(); e != nil {
		return nil, fmt.Errorf("space manager: %w", e)
	}
	if e = m.validateOwnership(); e != nil {
		return nil, fmt.Errorf("ownership: %w", e)
	}
	return m, nil
}
func (m *mutation) nextOID() (uint64, error) {
	if m.next == 0 || m.next >= objectMask {
		return 0, filesystem.ErrLimit
	}
	id := m.next
	m.next++
	return id, nil
}
func (m *mutation) readObject(address uint64, kind, storage uint32) ([]byte, error) {
	if address >= m.c.BlockCount {
		return nil, corrupt("mutation object address", 0)
	}
	b := make([]byte, 4096)
	if e := block.ReadFull(m.disk, b, int64(address)*4096); e != nil {
		return nil, e
	}
	if !validChecksum(b) || le.Uint64(b[8:]) != address || le.Uint32(b[24:])&0xc0000000 != storage || (kind != 0 && le.Uint32(b[24:])&0xffff != kind) || le.Uint64(b[16:]) > uint64(m.c.XID) {
		return nil, corrupt("mutation physical object", int64(address)*4096)
	}
	return b, nil
}
func (m *mutation) loadEphemeral() error {
	n := le.Uint32(m.nx[140:])
	base, count, index := le.Uint64(m.nx[112:]), le.Uint32(m.nx[104:]), le.Uint32(m.nx[136:])
	if n < 2 || n > count || index >= count {
		return corrupt("checkpoint descriptor geometry", 0)
	}
	for i := uint32(0); i < n-1; i++ {
		address := base + uint64((index+i)%count)
		b, e := m.c.object(PhysicalAddress(address), 12)
		if e != nil {
			return e
		}
		if le.Uint64(b[16:]) != uint64(m.c.XID) || le.Uint32(b[32:]) != func() uint32 {
			if i == n-2 {
				return 1
			}
			return 0
		}() {
			return corrupt("checkpoint mapping sequence", 0)
		}
		entries := le.Uint32(b[36:])
		if entries > 101 {
			return corrupt("checkpoint mapping count", 0)
		}
		for j := uint32(0); j < entries; j++ {
			r := b[40+j*40:]
			ep := ephemeral{kind: le.Uint32(r), subtype: le.Uint32(r[4:]), oid: le.Uint64(r[24:]), address: le.Uint64(r[32:])}
			size := le.Uint32(r[8:])
			db, dc := le.Uint64(m.nx[120:]), uint64(le.Uint32(m.nx[108:]))
			if size == 0 || size%4096 != 0 || size > 64<<10 || ep.address < db || ep.address >= db+dc || uint64(size/4096) > db+dc-ep.address || le.Uint64(r[16:]) != 0 {
				return filesystem.ErrUnsupported
			}
			if _, ok := m.ephemeral[ep.oid]; ok {
				return corrupt("duplicate ephemeral object", 0)
			}
			ep.data = make([]byte, size)
			if e := block.ReadFull(m.disk, ep.data, int64(ep.address)*4096); e != nil {
				return e
			}
			if !validChecksum(ep.data) || le.Uint64(ep.data[8:]) != ep.oid || le.Uint64(ep.data[16:]) != uint64(m.c.XID) || le.Uint32(ep.data[24:]) != ep.kind {
				return corrupt("ephemeral object header", 0)
			}
			m.ephemeral[ep.oid] = ep
		}
	}
	reaper, ok := m.ephemeral[le.Uint64(m.nx[168:])]
	if !ok || reaper.kind != 0x80000011 || len(reaper.data) < 112 || le.Uint64(reaper.data[48:]) != 0 || le.Uint64(reaper.data[56:]) != 0 || le.Uint32(reaper.data[64:]) != 1 || le.Uint32(reaper.data[68:]) != 0 {
		return fmt.Errorf("APFS pending reaper: %w", filesystem.ErrUnsupported)
	}
	for _, ep := range m.ephemeral {
		if ep.oid != le.Uint64(m.nx[152:]) && ep.oid != reaper.oid && ep.subtype != 9 {
			return filesystem.ErrUnsupported
		}
	}
	return nil
}
func sealMutationObject(b []byte, oid, xid uint64, kind, subtype uint32) {
	sealObject(b, oid, xid, kind, subtype)
}

func (m *mutation) write(b []byte, offset uint64) error {
	if e := m.ctx.Err(); e != nil {
		return e
	}
	if offset > uint64(m.disk.Size()) || uint64(len(b)) > uint64(m.disk.Size())-offset {
		return corrupt("mutation write bounds", 0)
	}
	n, e := m.disk.WriteAt(b, int64(offset))
	if e == nil && n != len(b) {
		e = io.ErrShortWrite
	}
	return e
}
