package hfsplus

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"math"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v3/internal/mode"
)

// Change applies an ordinary file operation in unpublished scratch. Empty
// Operation retains the cp/chmod convenience: non-nil Data copies a fork,
// otherwise Mode changes permissions. Explicit operations are ordered; later
// paths can name earlier creations. Paths never follow symlinks. Hard-link
// aliases address shared contents; moves/removals address their named records.
// Data is borrowed for the call; mode strings use Apple's setmode grammar.
type Change = filesystem.Change

type ChangeReport struct {
	VolumeID   string   `json:"volumeId"`
	Changed    []uint64 `json:"changed"`
	FreeBlocks uint32   `json:"freeBlocks"`
}

// ValidateMutation verifies the admitted write profile and complete allocation
// ownership without changing any bytes. It is also the post-write consistency
// gate; independent native fsck qualification remains in acceptance CI.
func ValidateMutation(ctx context.Context, source block.Source) error {
	v, err := Open(source)
	if err != nil {
		return err
	}
	m := &mutation{ctx: ctx, disk: readOnlyMutation{source}, v: v, header: make([]byte, 512), trees: map[uint32]*mutableTree{}}
	if err = block.ReadFull(source, m.header, 1024); err != nil {
		return err
	}
	if err := m.admit(); err != nil {
		return err
	}
	return m.loadCatalog()
}

type readOnlyMutation struct{ block.Source }

func (readOnlyMutation) WriteAt([]byte, int64) (int, error) { return 0, fs.ErrPermission }

// Modify updates an exclusively owned UNPUBLISHED copy. It does not provide
// in-place crash recovery: discard the entire copy after any error. imageedit
// supplies managed scratch and completed-file publication. Sources must be
// clean, fully accounted HFS+/HFSX volumes; internal journals must be valid and
// empty. Journal storage is retained unchanged. Modification time is
// explicit so identical source bytes, changes and time are reproducible.
func Modify(ctx context.Context, disk MutableSource, changes []Change, when time.Time) (ChangeReport, error) {
	var report ChangeReport
	if disk == nil || len(changes) == 0 || len(changes) > 4096 || when.IsZero() || when.Nanosecond() != 0 {
		return report, fs.ErrInvalid
	}
	stamp := when.Unix() + 2082844800
	if stamp < 0 || stamp > math.MaxUint32 {
		return report, fs.ErrInvalid
	}
	v, err := Open(disk)
	if err != nil {
		return report, err
	}
	m := &mutation{ctx: ctx, disk: disk, v: v, header: make([]byte, 512), trees: map[uint32]*mutableTree{}}
	if err = block.ReadFull(disk, m.header, 1024); err != nil {
		return report, err
	}
	if err = m.admit(); err != nil {
		return report, err
	}
	if err = m.loadCatalog(); err != nil {
		return report, err
	}
	for _, c := range changes {
		if err = ctx.Err(); err != nil {
			return report, err
		}
		id, e := m.applyChange(c, uint32(stamp))
		if e != nil {
			return report, e
		}
		if id != 0 {
			report.Changed = append(report.Changed, uint64(id))
		}
	}
	if len(report.Changed) == 0 {
		report.VolumeID, report.FreeBlocks = v.VolumeID, be.Uint32(m.header[48:])
		return report, nil
	}
	if err = m.writeFork(m.allocation, m.bitmap, 0); err != nil {
		return report, err
	}
	be.PutUint32(m.header[20:], uint32(stamp))
	be.PutUint32(m.header[68:], be.Uint32(m.header[68:])+1)
	// hfs_flushvolumeheader distinguishes journaled and nonjournaled mounts.
	copy(m.header[8:12], "10.0")
	if v.Journaled {
		copy(m.header[8:12], "HFSJ")
	}
	if err = m.write(m.header, 1024); err != nil {
		return report, err
	}
	if err = m.write(m.header, uint64(disk.Size()-1024)); err != nil {
		return report, err
	}
	report.VolumeID = v.VolumeID
	report.FreeBlocks = be.Uint32(m.header[48:])
	return report, nil
}

type emptySource struct{}

func (emptySource) Size() int64                       { return 0 }
func (emptySource) ReadAt([]byte, int64) (int, error) { return 0, fs.ErrInvalid }

// visitLeaves bounds a complete structural walk without buffering file data or
// entire trees. Index links and heights are checked before visiting leaf data.
func (t *tree) visitLeaves(ctx context.Context, yield func(uint32, []byte, []treeRecord) error) error {
	seen := map[uint32]bool{}
	var visit func(uint32, int) error
	visit = func(id uint32, height int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if id == 0 || id >= t.total || seen[id] {
			return bad("full tree cycle")
		}
		seen[id] = true
		if len(seen) > 1<<18 {
			return filesystem.ErrLimit
		}
		b := make([]byte, t.nodeSize)
		if err := t.fork.read(b, uint64(id)*uint64(t.nodeSize)); err != nil {
			return err
		}
		if height == -1 {
			height = int(b[9])
		}
		if height < 1 || height > 16 || int(b[9]) != height || (height == 1 && b[8] != 255) || (height > 1 && b[8] != 0) {
			return bad("full tree node height")
		}
		r, err := nodeRecords(b, t.idOffset)
		if err != nil {
			return err
		}
		if height == 1 {
			return yield(id, b, r)
		}
		for _, item := range r {
			if len(item.value) != 4 {
				return bad("full tree index pointer")
			}
			if err = visit(be.Uint32(item.value), height-1); err != nil {
				return err
			}
		}
		return nil
	}
	if t.root == 0 {
		return ctx.Err()
	}
	return visit(t.root, -1)
}

func (m *mutation) admit() error {
	return m.admitProfile(false)
}

func (m *mutation) admitProfile(recovered bool) error {
	v := m.v
	if err := m.ctx.Err(); err != nil {
		return err
	}
	if (!v.Clean && !recovered) || v.Attributes & ^uint32(0x80003500) != 0 || (!v.Journaled && be.Uint32(m.header[12:]) != 0) {
		return fmt.Errorf("mutation requires a clean, unlocked HFS+/HFSX profile: %w", filesystem.ErrUnsupported)
	}
	if uint64(v.BlockCount)*uint64(v.BlockSize) != uint64(m.disk.Size()) {
		return fmt.Errorf("mutation requires complete allocation-block geometry: %w", filesystem.ErrUnsupported)
	}
	if v.BlockCount > 1<<27 {
		return filesystem.ErrLimit
	}
	alt := make([]byte, 512)
	if err := block.ReadFull(m.disk, alt, m.disk.Size()-1024); err != nil {
		return err
	}
	if !bytes.Equal(m.header[:4], alt[:4]) || !bytes.Equal(m.header[40:48], alt[40:48]) || !bytes.Equal(m.header[112:], alt[112:]) {
		return bad("primary/alternate structural disagreement")
	}
	// hfs_flushvolumeheader writes the alternate only with HFS_FVH_WRITE_ALT.
	// Clean native journaled detaches leave its unmounted bit clear. The primary
	// and actual journal determine cleanliness; all other flags must agree.
	if v.Journaled && ((be.Uint32(m.header[4:])^be.Uint32(alt[4:])) & ^uint32(0x100) != 0 || !bytes.Equal(m.header[12:16], alt[12:16])) {
		return bad("primary/alternate journal disagreement")
	}
	f, err := v.fileFork(m.ctx, 6, 0, m.header[112:192])
	if err != nil {
		return err
	}
	m.allocation = f
	n := (uint64(v.BlockCount) + 7) / 8
	if f.size < n {
		return bad("short allocation bitmap")
	}
	m.bitmap = make([]byte, n)
	m.claimed = make([]byte, n)
	if err = f.read(m.bitmap, 0); err != nil {
		return err
	}
	var free uint32
	for i := uint32(0); i < v.BlockCount; i++ {
		if !bitmapBit(m.bitmap, i) {
			free++
		}
	}
	if free != v.FreeBlocks {
		return bad("volume free block accounting")
	}
	// TN1150 reserves the first 1536 and last 1024 bytes, rounded outward to
	// allocation blocks. Their bits are accounted separately from file forks.
	for i := uint32(0); i < v.BlockCount; i++ {
		start, end := uint64(i)*uint64(v.BlockSize), uint64(i+1)*uint64(v.BlockSize)
		if start < 1536 || end > uint64(m.disk.Size()-1024) {
			if !bitmapBit(m.bitmap, i) {
				return bad("unallocated reserved block")
			}
			setBitmapBit(m.claimed, i, true)
		}
	}
	for _, special := range []struct {
		id  uint32
		off int
	}{{6, 112}, {3, 192}, {4, 272}, {8, 352}, {7, 432}} {
		f, e := v.fileFork(m.ctx, special.id, 0, m.header[special.off:special.off+80])
		if e != nil {
			return e
		}
		if e = m.claimFileFork(special.id, 0, f); e != nil {
			return e
		}
	}
	if v.overflow == nil {
		return fmt.Errorf("mutation requires an extents B-tree: %w", filesystem.ErrUnsupported)
	}
	if _, err = m.mutableTree(3, 192); err != nil {
		return err
	}
	if _, err = m.mutableTree(4, 272); err != nil {
		return err
	}
	if be.Uint64(v.attributeFork) > 0 {
		if _, err = m.mutableTree(8, 352); err != nil {
			return err
		}
	}
	objects := map[uint32]bool{}
	if err = v.catalog.visitLeaves(m.ctx, func(_ uint32, _ []byte, records []treeRecord) error {
		for _, r := range records {
			if len(r.value) < 2 {
				return bad("catalog admission record")
			}
			// cat_create/cat_update select a different timestamp conversion
			// when kHFSCatExpandedTimesMask is set. This writer emits the
			// ordinary 1904-epoch representation; retaining that flag would
			// reinterpret every newly written timestamp on native mount.
			kind := be.Uint16(r.value)
			if (kind == 1 || kind == 2) && len(r.value) >= 4 && be.Uint16(r.value[2:])&0x1000 != 0 {
				return fmt.Errorf("expanded HFS catalog timestamps: %w", filesystem.ErrUnsupported)
			}
			switch kind {
			case 1:
				if len(r.value) != 88 {
					return bad("catalog folder admission")
				}
				id := be.Uint32(r.value[8:])
				if (id != 2 && id < 16) || objects[id] {
					return bad("catalog folder identity")
				}
				objects[id] = true
			case 2:
				if len(r.value) != 248 {
					return bad("catalog file admission")
				}
				id := be.Uint32(r.value[8:])
				if id < 16 || objects[id] {
					return bad("catalog file identity")
				}
				objects[id] = true
				if string(r.value[48:56]) == "fdrpMACS" {
					return fmt.Errorf("directory hard links: %w", filesystem.ErrUnsupported)
				}
				for _, kind := range []byte{0, 255} {
					off := 88
					if kind == 255 {
						off = 168
					}
					f, e := v.fileFork(m.ctx, be.Uint32(r.value[8:]), kind, r.value[off:off+80])
					if e != nil {
						return e
					}
					if e = m.claimFileFork(id, kind, f); e != nil {
						return e
					}
				}
			case 3, 4:
			default:
				return bad("catalog admission kind")
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err = m.claimAttributes(); err != nil {
		return err
	}
	if v.Journaled {
		if err = m.admitJournal(); err != nil {
			return err
		}
	}
	if err = v.overflow.visitLeaves(m.ctx, func(_ uint32, _ []byte, records []treeRecord) error {
		for _, r := range records {
			if len(r.value) != 64 || !m.overflowUsed[string(r.key)] {
				return bad("unreachable overflow extent record")
			}
		}
		return nil
	}); err != nil {
		return err
	}
	for i := uint32(0); i < v.BlockCount; i++ {
		if bitmapBit(m.bitmap, i) != bitmapBit(m.claimed, i) {
			return fmt.Errorf("unaccounted HFS allocation block %d: %w", i, filesystem.ErrUnsupported)
		}
	}
	return m.ctx.Err()
}

func (m *mutation) claimFileFork(id uint32, kind byte, f *fork) error {
	if m.overflowUsed == nil {
		m.overflowUsed = map[string]bool{}
	}
	for i, e := range f.extents {
		if i >= 8 && i%8 == 0 {
			m.overflowUsed[string(extentKey(id, kind, uint32(e.logical/uint64(m.v.BlockSize))))] = true
		}
	}
	return m.claim(f)
}

func (m *mutation) claimAttributes() error {
	t := m.trees[8]
	if t == nil {
		return nil
	}
	base := &tree{fork: t.fork, root: be.Uint32(t.header[16:]), total: t.total, nodeSize: t.nodeSize, idOffset: 4}
	var descriptor []byte
	continuations := map[uint32][]byte{}
	var lastKey []byte
	finish := func() error {
		if descriptor == nil {
			return nil
		}
		f, e := resolveFork(m.ctx, m.disk, m.v.BlockSize, m.v.BlockCount, descriptor, func() (map[uint32][]byte, error) { return continuations, nil })
		if e != nil {
			return e
		}
		if len(continuations) != 0 {
			return bad("unreachable attribute extents")
		}
		descriptor = nil
		continuations = map[uint32][]byte{}
		return m.claim(f)
	}
	err := base.visitLeaves(m.ctx, func(_ uint32, _ []byte, records []treeRecord) error {
		for _, r := range records {
			if len(r.value) < 4 {
				return bad("attribute admission value")
			}
			if lastKey == nil || be.Uint32(lastKey[4:]) != be.Uint32(r.key[4:]) || !bytes.Equal(lastKey[12:], r.key[12:]) {
				if e := finish(); e != nil {
					return e
				}
			}
			switch be.Uint32(r.value) {
			case 0x10:
				if be.Uint32(r.key[8:]) != 0 || len(r.value) < 16 || int(be.Uint32(r.value[12:])) > len(r.value)-16 {
					return bad("inline attribute admission")
				}
			case 0x20:
				if be.Uint32(r.key[8:]) != 0 || len(r.value) != 88 || descriptor != nil {
					return bad("attribute fork admission")
				}
				descriptor = bytes.Clone(r.value[8:])
			case 0x30:
				if descriptor == nil || len(r.value) != 72 || be.Uint32(r.key[8:]) == 0 {
					return bad("attribute continuation admission")
				}
				continuations[be.Uint32(r.key[8:])] = bytes.Clone(r.value[8:])
			default:
				return fmt.Errorf("unknown attribute storage: %w", filesystem.ErrUnsupported)
			}
			lastKey = bytes.Clone(r.key)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return finish()
}

func extentKey(id uint32, kind byte, start uint32) []byte {
	b := make([]byte, 12)
	be.PutUint16(b, 10)
	b[2] = kind
	be.PutUint32(b[4:], id)
	be.PutUint32(b[8:], start)
	return b
}

func (m *mutation) replaceFork(id uint32, kind byte, descriptor []byte, data block.Source) error {
	f, err := m.v.fileFork(m.ctx, id, kind, descriptor)
	if err != nil {
		return err
	}
	blocks := (uint64(data.Size()) + uint64(m.v.BlockSize) - 1) / uint64(m.v.BlockSize)
	if blocks > math.MaxUint32 {
		return filesystem.ErrLimit
	}
	runs, err := m.resizeRuns(forkRuns(f, m.v.BlockSize), uint32(blocks))
	if err != nil {
		return err
	}
	if err = m.writePayload(forkFromRuns(m.disk, m.v.BlockSize, blocks*uint64(m.v.BlockSize), runs), data); err != nil {
		return err
	}
	return m.storeExtentRuns(id, kind, descriptor, uint64(data.Size()), runs)
}

// storeExtentRuns applies the same inline/overflow format to ordinary forks
// and the catalog file. The extents file itself remains self-describing.
func (m *mutation) storeExtentRuns(id uint32, kind byte, descriptor []byte, size uint64, runs []allocationRun) error {
	var oldKeys [][]byte
	if err := m.v.overflow.records(m.ctx, id, func(r treeRecord) error {
		if r.key[2] == kind {
			oldKeys = append(oldKeys, bytes.Clone(r.key))
		}
		return nil
	}); err != nil {
		return err
	}
	var err error
	t := m.trees[3]
	for _, key := range oldKeys {
		if err = t.set(key, nil, true); err != nil {
			return err
		}
	}
	var logical uint32
	for i, r := range runs {
		if i >= 8 && i%8 == 0 {
			value := make([]byte, 64)
			for j, x := range runs[i:min(i+8, len(runs))] {
				be.PutUint32(value[j*8:], x.start)
				be.PutUint32(value[j*8+4:], x.count)
			}
			if err = t.set(extentKey(id, kind, logical), value, false); err != nil {
				return err
			}
		}
		logical += r.count
	}
	encodeRuns(descriptor, size, runs)
	return nil
}

func (m *mutation) patchCatalog(id uint32, value []byte) error {
	if m.catalog == nil {
		if err := m.loadCatalog(); err != nil {
			return err
		}
	}
	r := m.catalog[id]
	if r == nil || len(r.value) != len(value) {
		return bad("catalog mutation target")
	}
	if err := m.trees[4].set(r.key, value, false); err != nil {
		return err
	}
	r.value = bytes.Clone(value)
	return nil
}

func (m *mutation) removeCompression(id uint32, catalog []byte) error {
	t := m.trees[8]
	if t == nil {
		return bad("compression without attributes tree")
	}
	var keys [][]byte
	var descriptor []byte
	continuations := map[uint32][]byte{}
	other := false
	err := m.v.attributes(m.ctx, uint64(id), func(name string, start uint32, value []byte) error {
		if name != filesystem.Decmpfs {
			other = true
			return nil
		}
		if start == 0 && be.Uint32(value) == 0x20 {
			descriptor = bytes.Clone(value[8:])
		} else if start > 0 {
			continuations[start] = bytes.Clone(value[8:])
		}
		return nil
	})
	if err != nil {
		return err
	}
	base := &tree{fork: t.fork, root: be.Uint32(t.header[16:]), total: t.total, nodeSize: t.nodeSize, idOffset: 4}
	if err = base.records(m.ctx, id, func(r treeRecord) error {
		name, e := unicodeName(r.key[12:])
		if e != nil {
			return e
		}
		if name == filesystem.Decmpfs {
			keys = append(keys, bytes.Clone(r.key))
		}
		return nil
	}); err != nil {
		return err
	}
	if len(keys) == 0 {
		return bad("missing compression record")
	}
	if descriptor != nil {
		f, e := resolveFork(m.ctx, m.disk, m.v.BlockSize, m.v.BlockCount, descriptor, func() (map[uint32][]byte, error) { return continuations, nil })
		if e != nil {
			return e
		}
		for _, r := range forkRuns(f, m.v.BlockSize) {
			if e = m.mark(r, false); e != nil {
				return e
			}
		}
	}
	for _, key := range keys {
		if err = t.set(key, nil, true); err != nil {
			return err
		}
	}
	if !other {
		be.PutUint16(catalog[2:], be.Uint16(catalog[2:])&^4)
	}
	return nil
}

func (m *mutation) validateFile(c Change, id uint64) error {
	b, e := m.v.catalogRecord(m.ctx, id)
	if e != nil {
		return e
	}
	if be.Uint16(b) != 2 || be.Uint16(b[42:])&0170000 != 0100000 {
		return fmt.Errorf("existing regular file required: %w", filesystem.ErrUnsupported)
	}
	if c.Data != nil && be.Uint16(b[42:])&06000 != 0 {
		return fmt.Errorf("replacement of set-ID file requires credential policy: %w", filesystem.ErrUnsupported)
	}
	flags := catalogBSDFlags(b)
	if flags&(0x00060006|0x40000000) != 0 || be.Uint16(b[2:])&1 != 0 {
		return fmt.Errorf("locked, immutable, append-only or dataless target: %w", filesystem.ErrUnsupported)
	}
	if c.Mode != "" {
		if _, e = mode.Parse(c.Mode, 022); e != nil {
			return e
		}
		if be.Uint16(b[2:])&8 != 0 {
			return fmt.Errorf("chmod of ACL-bearing file: %w", filesystem.ErrUnsupported)
		}
	}
	if b[41]&0x20 != 0 && c.Data != nil {
		h, e := decmpfs.Inspect(func(name string) (filesystem.Value, error) { return m.v.OpenAttribute(m.ctx, id, name) })
		if e != nil {
			return e
		}
		uses, e := decmpfs.UsesResourceFork(h.Type)
		if e != nil {
			return e
		}
		if uses && c.ResourceFork {
			return fmt.Errorf("resource fork belongs to active compression: %w", filesystem.ErrUnsupported)
		}
	}
	return nil
}

func (m *mutation) modifyFile(c Change, target uint64, stamp uint32) (uint32, error) {
	b, e := m.v.catalogRecord(m.ctx, target)
	if e != nil {
		return 0, e
	}
	b = bytes.Clone(b)
	id := be.Uint32(b[8:])
	if c.Data != nil {
		if !c.ResourceFork && b[41]&0x20 != 0 {
			h, e := decmpfs.Inspect(func(name string) (filesystem.Value, error) { return m.v.OpenAttribute(m.ctx, uint64(id), name) })
			if e != nil {
				return 0, e
			}
			uses, e := decmpfs.UsesResourceFork(h.Type)
			if e != nil {
				return 0, e
			}
			if e = m.removeCompression(id, b); e != nil {
				return 0, e
			}
			if uses {
				if e = m.replaceFork(id, 255, b[168:248], emptySource{}); e != nil {
					return 0, e
				}
			}
			b[41] &^= 0x20
		}
		kind, descriptor := byte(0), b[88:168]
		if c.ResourceFork {
			kind, descriptor = 255, b[168:248]
		}
		if e = m.replaceFork(id, kind, descriptor, c.Data); e != nil {
			return 0, e
		}
		be.PutUint32(b[16:], stamp)
	}
	if c.Mode != "" {
		p, _ := mode.Parse(c.Mode, 022)
		be.PutUint16(b[42:], uint16(p.Apply(uint32(be.Uint16(b[42:])))))
	}
	be.PutUint32(b[20:], stamp)
	if e = m.patchCatalog(id, b); e != nil {
		return 0, e
	}
	return id, nil
}
