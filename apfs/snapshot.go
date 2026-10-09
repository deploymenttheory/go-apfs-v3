package apfs

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const maxSnapshots = 4096

// Snapshot identifies a retained point-in-time filesystem. XID is the last
// included transaction, not a physical address or a container checkpoint.
// UUID is absent on older formats without extended snapshot metadata.
type Snapshot struct {
	Name       string                         `json:"name"`
	XID        XID                            `json:"xid"`
	UUID       filesystem.Observation[string] `json:"uuid"`
	CreateTime time.Time                      `json:"createTime"`
	ChangeTime time.Time                      `json:"changeTime"`
	Flags      uint32                         `json:"flags"`
}

type snapshotRecord struct {
	Snapshot
	superblock PhysicalAddress
}

// ListSnapshots enumerates retained snapshots in transaction order. The source
// and, for encrypted volumes, its unlocked key owner must remain open. Snapshot
// metadata and its name index are validated together within a bounded inventory.
func (v *Volume) ListSnapshots(ctx context.Context, yield func(Snapshot) error) error {
	if yield == nil {
		return fs.ErrInvalid
	}
	records, err := v.snapshots(ctx)
	if err != nil {
		return err
	}
	for _, r := range records {
		if err := ctx.Err(); err != nil {
			return err
		}
		if _, err := v.snapshotVolume(r); err != nil {
			return err
		}
		// The snapshot superblock precedes the extended metadata update. Use
		// the live metadata OID, resolving its retained version at this XID.
		r.UUID, err = v.snapshotUUID(r.XID)
		if err != nil {
			return err
		}
		if err := yield(r.Snapshot); err != nil {
			return err
		}
	}
	return nil
}

// OpenSnapshot returns a borrowed, read-only historical reader. Opening it does
// not change the live volume. It uses this volume's current object map with the
// snapshot's transaction bound and root. Unlock the live volume first; closing
// that unlock invalidates its snapshot readers and their borrowed values.
// The reader has no key ownership and needs no Close; values still need Close.
func (v *Volume) OpenSnapshot(ctx context.Context, xid XID) (filesystem.Reader, error) {
	return v.openSnapshot(ctx, func(r snapshotRecord) bool { return r.XID == xid })
}

// OpenSnapshotName selects the exact retained spelling returned by ListSnapshots.
// Snapshot selection never uses host filename folding or parses names as XIDs.
func (v *Volume) OpenSnapshotName(ctx context.Context, name string) (filesystem.Reader, error) {
	if !validSnapshotName(name) {
		return nil, fs.ErrInvalid
	}
	return v.openSnapshot(ctx, func(r snapshotRecord) bool { return r.Name == name })
}

// Expose only the common reader contract, not the internal Volume's key-owner
// operations. Both the historical Volume and its transaction are private.
type snapshotReader struct{ filesystem.Reader }

func (v *Volume) openSnapshot(ctx context.Context, match func(snapshotRecord) bool) (filesystem.Reader, error) {
	records, err := v.snapshots(ctx)
	if err != nil {
		return nil, err
	}
	for _, r := range records {
		if !match(r) {
			continue
		}
		if r.Flags != 0 {
			return nil, fmt.Errorf("snapshot metadata flags %#x: %w", r.Flags, filesystem.ErrUnsupported)
		}
		view, err := v.snapshotVolume(r)
		if err != nil {
			return nil, err
		}
		if _, err := view.Stat(ctx, view.Root()); err != nil {
			return nil, err
		}
		return snapshotReader{view}, nil
	}
	return nil, fmt.Errorf("retained snapshot: %w", fs.ErrNotExist)
}

func (v *Volume) snapshots(ctx context.Context) ([]snapshotRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if v.container == nil {
		return nil, corrupt("unopened snapshot volume", 0)
	}
	if err := v.access(); err != nil {
		return nil, err
	}
	if v.Snapshots > maxSnapshots {
		return nil, filesystem.ErrLimit
	}
	if v.snapMeta == 0 {
		if v.Snapshots != 0 {
			return nil, corrupt("missing snapshot metadata tree", 0)
		}
		return nil, nil
	}
	if v.snapMetaType != 0x40000002 {
		return nil, fmt.Errorf("snapshot metadata tree type %#x: %w", v.snapMetaType, filesystem.ErrUnsupported)
	}
	byXID := map[XID]snapshotRecord{}
	byName := map[string]XID{}
	err := v.walkRecords(ctx, recordTree{v.snapMeta, 16, true}, nil, func(r record) error {
		p := prefix(r.key)
		switch p.kind {
		case 1: // APFS_TYPE_SNAP_METADATA
			s, err := readSnapshotRecord(r)
			if err != nil {
				return err
			}
			if s.XID == 0 || s.XID > v.xid || s.superblock == 0 || uint64(s.superblock) >= v.container.BlockCount {
				return corrupt("snapshot transaction or superblock range", 0)
			}
			if _, exists := byXID[s.XID]; exists {
				return corrupt("duplicate snapshot transaction", 0)
			}
			byXID[s.XID] = s
		case 11: // APFS_TYPE_SNAP_NAME
			if p.id != objectMask || len(r.key) < 10 || len(r.value) != 8 {
				return corrupt("snapshot name record", 0)
			}
			name, err := snapshotName(r.key[10:], int(le.Uint16(r.key[8:])))
			if err != nil {
				return err
			}
			if _, exists := byName[name]; exists {
				return corrupt("duplicate snapshot name", 0)
			}
			byName[name] = XID(le.Uint64(r.value))
		default:
			return fmt.Errorf("snapshot record type %d: %w", p.kind, filesystem.ErrUnsupported)
		}
		if len(byXID) > maxSnapshots || len(byName) > maxSnapshots {
			return filesystem.ErrLimit
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if uint64(len(byXID)) != v.Snapshots || len(byName) != len(byXID) {
		return nil, corrupt("snapshot inventory count", 0)
	}
	result := make([]snapshotRecord, 0, len(byXID))
	for xid, r := range byXID {
		if byName[r.Name] != xid {
			return nil, corrupt("snapshot name index disagrees with metadata", 0)
		}
		result = append(result, r)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].XID < result[j].XID })
	return result, ctx.Err()
}

func readSnapshotRecord(r record) (snapshotRecord, error) {
	var s snapshotRecord
	if len(r.key) != 8 || prefix(r.key).kind != 1 || len(r.value) < 50 {
		return s, corrupt("snapshot metadata record", 0)
	}
	b := r.value
	name, err := snapshotName(b[50:], int(le.Uint16(b[48:])))
	if err != nil {
		return s, err
	}
	s.Name, s.XID, s.Flags = name, XID(prefix(r.key).id), le.Uint32(b[44:])
	s.CreateTime = time.Unix(0, int64(le.Uint64(b[16:]))).UTC()
	s.ChangeTime = time.Unix(0, int64(le.Uint64(b[24:]))).UTC()
	s.superblock = PhysicalAddress(le.Uint64(b[8:]))
	return s, nil
}

func snapshotName(b []byte, length int) (string, error) {
	if length < 2 || length != len(b) || b[len(b)-1] != 0 {
		return "", corrupt("snapshot name bounds or terminator", 0)
	}
	name := string(b[:len(b)-1])
	if !validSnapshotName(name) {
		return "", corrupt("snapshot name", 0)
	}
	return name, nil
}

func validSnapshotName(name string) bool {
	return name != "" && name != "." && name != ".." && utf8.ValidString(name) && !strings.ContainsAny(name, "/\x00")
}

func (v *Volume) snapshotVolume(r snapshotRecord) (*Volume, error) {
	c := v.container
	b, err := c.object(r.superblock, 13)
	if err != nil {
		return nil, err
	}
	if string(b[32:36]) != "APSB" || le.Uint32(b[24:]) != 0x4000000d || PhysicalAddress(le.Uint64(b[8:])) != r.superblock || XID(le.Uint64(b[16:])) > r.XID || !bytes.Equal(b[240:256], v.id[:]) {
		return nil, corrupt("snapshot volume superblock", int64(r.superblock)*int64(c.BlockSize))
	}
	view := c.volume(b, r.XID)
	if view.Encrypted != v.Encrypted {
		return nil, fmt.Errorf("snapshot encryption transition: %w", filesystem.ErrUnsupported)
	}
	// The retained superblock's apfs_omap_oid is not an independent historical
	// map. The live volume map preserves versions selected by the snapshot XID.
	view.omap, view.keys = v.omap, v.keys
	return &view, nil
}

func (v *Volume) snapshotUUID(xid XID) (filesystem.Observation[string], error) {
	result := filesystem.Observation[string]{State: filesystem.Absent}
	if v.snapMetaExt == 0 {
		return result, nil
	}
	mapping, err := v.container.resolve(v.omap, v.snapMetaExt, xid)
	if err != nil {
		return result, err
	}
	b, err := v.object(mapping, 29)
	if err != nil {
		return result, err
	}
	if OID(le.Uint64(b[8:])) != v.snapMetaExt || XID(le.Uint64(b[16:])) > xid || le.Uint64(b[40:]) != uint64(xid) {
		return result, corrupt("extended snapshot metadata identity", int64(mapping.address)*int64(v.container.BlockSize))
	}
	if le.Uint32(b[32:]) != 1 {
		return result, fmt.Errorf("extended snapshot metadata version: %w", filesystem.ErrUnsupported)
	}
	return filesystem.Observed(uuid(b[48:64])), nil
}
