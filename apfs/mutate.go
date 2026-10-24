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
	volumes                 []*mutation
	ctx                     context.Context
	disk                    MutableSource
	c                       *Container
	v                       *Volume
	nx, super               []byte
	xid, next               uint64
	ephemeral               map[uint64]ephemeral
	reaperLists             []ephemeral
	space                   *mutationSpace
	fs, extents, vmap, cmap *cowTree
	volumeMap, containerMap []byte
	volumeAddress           uint64
	retired                 map[uint64]bool
	mappings                map[uint64]uint64
	allocated, freed        uint64
	entries                 map[uint64]map[string]*mutationEntry
	links                   map[uint64]map[*mutationEntry]bool
	actor                   filesystem.Observation[uint32]
	reusePrepared           bool
	history                 *mutationHistory
}
type readOnlyMutation struct{ block.Source }

func (readOnlyMutation) WriteAt([]byte, int64) (int, error) { return 0, fs.ErrPermission }

// ValidateMutation admits fully accounted ordinary plaintext volumes and
// qualified retained histories. Unknown metadata or ownership is a refusal,
// never a guessed free block.
func ValidateMutation(ctx context.Context, source block.Source) error {
	_, e := openMutation(ctx, readOnlyMutation{source})
	return e
}
func Modify(ctx context.Context, disk MutableSource, changes []Change, when time.Time) (ChangeReport, error) {
	return ModifyVolume(ctx, disk, "", changes, when)
}

// ModifyVolume selects a UUID explicitly when a container has several volumes.
// All ordinary volumes are accounted before writing; untouched volumes retain
// their original superblocks, maps, trees and streams.
func ModifyVolume(ctx context.Context, disk MutableSource, volumeUUID string, changes []Change, when time.Time) (ChangeReport, error) {
	var report ChangeReport
	if disk == nil || len(changes) == 0 || len(changes) > 4096 || when.IsZero() || when.Nanosecond() != 0 {
		return report, fs.ErrInvalid
	}
	stamp, e := buildTime(when)
	if e != nil {
		return report, e
	}
	m, e := openMutationVolume(ctx, disk, volumeUUID)
	if e != nil {
		return report, e
	}
	if volumeUUID == "" && len(m.c.Volumes) > 1 {
		return report, fmt.Errorf("select an APFS volume UUID in a multiple-volume container: %w", fs.ErrInvalid)
	}
	report.VolumeID = m.v.UUID
	initialFree := m.space.free
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
	if len(report.Changed) == 0 {
		report.FreeBlocks, report.Transaction = initialFree, uint64(m.c.XID)
		return report, nil
	}
	if e = m.commit(stamp); e != nil {
		return report, e
	}
	report.FreeBlocks, report.Transaction = m.space.free, m.xid
	return report, nil
}
func openMutation(ctx context.Context, disk MutableSource) (*mutation, error) {
	return openMutationVolume(ctx, disk, "")
}
func openMutationVolume(ctx context.Context, disk MutableSource, volumeUUID string) (*mutation, error) {
	if e := ctx.Err(); e != nil {
		return nil, e
	}
	c, e := Open(disk)
	if e != nil {
		return nil, e
	}
	if c.BlockSize != 4096 || len(c.Volumes) == 0 || c.Checkpoint == 0 {
		return nil, fmt.Errorf("APFS mutation checkpoint geometry: %w", filesystem.ErrUnsupported)
	}
	if (c.BlockCount+7)/8 > maxMutationBitmapBytes {
		return nil, fmt.Errorf("APFS allocation bitmap budget: %w", filesystem.ErrLimit)
	}
	v := &c.Volumes[0]
	if volumeUUID != "" {
		found := false
		for i := range c.Volumes {
			if c.Volumes[i].UUID == volumeUUID {
				v, found = &c.Volumes[i], true
				break
			}
		}
		if !found {
			return nil, fs.ErrNotExist
		}
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
	for i := range c.Volumes {
		if e = admitMutationVolume(&c.Volumes[i]); e != nil {
			return nil, e
		}
	}
	storage, e := newStorageChecker(ctx, c)
	if e != nil {
		return nil, e
	}
	if e = storage.check(); e != nil {
		return nil, fmt.Errorf("ownership: %w", e)
	}
	m.ephemeral, m.space = storage.reader.ephemeral, storage.reader.space
	m.space.owner = m
	m.containerMap, m.cmap = bytes.Clone(storage.mapHeader), storage.cmap
	for _, tree := range m.space.queues {
		tree.newOID = m.nextOID
	}
	for _, state := range storage.volumes {
		volume := m
		if state.v != v {
			volume = &mutation{ctx: ctx, disk: disk, c: c, v: state.v, nx: m.nx, xid: m.xid, next: m.next, ephemeral: m.ephemeral, mappings: map[uint64]uint64{}}
		}
		volume.volumeAddress, volume.super = state.address, bytes.Clone(state.super)
		volume.volumeMap, volume.vmap = bytes.Clone(state.mapHeader), state.omap
		volume.fs, volume.extents = state.fs, state.extents
		for _, tree := range []*cowTree{volume.fs, volume.extents, volume.vmap, m.cmap} {
			tree.newOID = m.nextOID
		}
		m.volumes = append(m.volumes, volume)
	}
	if e = m.validateOwnership(storage); e != nil {
		return nil, fmt.Errorf("mutation admission: %w", e)
	}
	for _, volume := range m.volumes {
		volume.space = m.space
		if e = volume.loadEntries(); e != nil {
			return nil, fmt.Errorf("directory graph in volume %s: %w", volume.v.UUID, e)
		}
		if e = volume.updateStatistics(true); e != nil {
			return nil, fmt.Errorf("directory statistics in volume %s: %w", volume.v.UUID, e)
		}
	}
	return m, nil
}
func admitMutationVolume(v *Volume) error {
	if v.Encrypted || v.EncryptionRollingStateOID != 0 || v.Sealed || v.Role != 0 || v.CompatibleFeatures&^uint64(2) != 0 || v.ReadOnlyCompatibleFeatures != 0 || v.IncompatibleFeatures&^uint64(0xb) != 0 || v.rootType != 2 {
		return fmt.Errorf("APFS volume mutation profile: %w", filesystem.ErrUnsupported)
	}
	return nil
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
func (m *mutation) loadEphemeralObjects(allowEmptyReaperLists bool) error {
	objects, err := m.c.checkpointObjects(m.ctx, m.nx)
	if err != nil {
		return err
	}
	for _, object := range objects {
		if object.volume != 0 {
			return fmt.Errorf("volume-owned ephemeral object: %w", filesystem.ErrUnsupported)
		}
		m.ephemeral[object.oid] = object.ephemeral
	}
	reaper, ok := m.ephemeral[le.Uint64(m.nx[168:])]
	if !ok || reaper.kind != 0x80000011 || len(reaper.data) < 112 || le.Uint32(reaper.data[64:]) != 1 {
		return fmt.Errorf("APFS pending reaper: %w", filesystem.ErrUnsupported)
	}
	pages, err := m.emptyReaperLists(reaper.data, allowEmptyReaperLists)
	if err != nil {
		return err
	}
	for _, ep := range m.ephemeral {
		if ep.oid != le.Uint64(m.nx[152:]) && ep.oid != reaper.oid && !pages[ep.oid] && (ep.subtype != 9 || (ep.kind != 0x80000002 && ep.kind != 0x80000003)) {
			return filesystem.ErrUnsupported
		}
	}
	return nil
}
func sealMutationObject(b []byte, oid, xid uint64, kind, subtype uint32) {
	sealObject(b, oid, xid, kind, subtype)
}

func (m *mutation) write(b []byte, offset uint64) error {
	if e := m.prepareReuse(); e != nil {
		return e
	}
	return m.writeBytes(b, offset)
}

func (m *mutation) writeBytes(b []byte, offset uint64) error {
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
