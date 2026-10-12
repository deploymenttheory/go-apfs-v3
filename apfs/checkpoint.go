package apfs

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const (
	checkpointObjectLimit = 4096
	checkpointByteLimit   = 32 << 20
)

type ephemeral struct {
	kind, subtype uint32
	oid, address  uint64
	data          []byte
}

// CheckpointInfo describes structural completeness, not full filesystem health.
// An unsupported checkpoint cannot be discarded as though it were damaged.
type CheckpointInfo struct {
	Transaction     XID             `json:"transaction"`
	Address         PhysicalAddress `json:"address"`
	State           string          `json:"state"` // valid, invalid or unsupported.
	Reason          string          `json:"reason,omitempty"`
	DescriptorIndex uint32          `json:"descriptorIndex"`
	DescriptorCount uint32          `json:"descriptorCount"`
	DataIndex       uint32          `json:"dataIndex"`
	DataCount       uint32          `json:"dataCount"`
	Objects         int             `json:"objects"`
	err             error
}

type CheckpointReport struct {
	ContainerUUID        string           `json:"containerUUID"`
	BlockSize            uint32           `json:"blockSize"`
	BlockZeroTransaction XID              `json:"blockZeroTransaction"`
	BlockZeroValid       bool             `json:"blockZeroValid"`
	SelectedTransaction  XID              `json:"selectedTransaction"`
	SelectedAddress      PhysicalAddress  `json:"selectedAddress"`
	Candidates           []CheckpointInfo `json:"candidates"`
}

type checkpointCandidate struct {
	address PhysicalAddress
	data    []byte
}

func (c *Container) checkpointCandidates(ctx context.Context, zero []byte) ([]checkpointCandidate, error) {
	count, base := le.Uint32(zero[104:]), le.Uint64(zero[112:])
	if count&0x80000000 != 0 {
		return nil, fmt.Errorf("checkpoint descriptor tree: %w", filesystem.ErrUnsupported)
	}
	if count > 65536 {
		return nil, filesystem.ErrLimit
	}
	if uint64(count)*uint64(c.BlockSize) > checkpointByteLimit {
		return nil, filesystem.ErrLimit
	}
	if count == 0 || base == 0 || base > c.BlockCount || uint64(count) > c.BlockCount-base {
		return nil, corrupt("checkpoint area", 0)
	}
	var candidates []checkpointCandidate
	for i := uint64(0); i < uint64(count); i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		data := make([]byte, c.BlockSize)
		if err := block.ReadFull(c.source, data, int64(base+i)*int64(c.BlockSize)); err != nil {
			return nil, err
		}
		if string(data[32:36]) != "NXSB" || !bytes.Equal(zero[72:88], data[72:88]) {
			continue
		}
		if len(candidates) >= 256 {
			return nil, filesystem.ErrLimit
		}
		candidates = append(candidates, checkpointCandidate{PhysicalAddress(base + i), data})
	}
	slices.SortFunc(candidates, func(a, b checkpointCandidate) int {
		if ax, bx := le.Uint64(a.data[16:]), le.Uint64(b.data[16:]); ax != bx {
			if ax > bx {
				return -1
			}
			return 1
		}
		if a.address < b.address {
			return -1
		}
		if a.address > b.address {
			return 1
		}
		return 0
	})
	return candidates, nil
}

// InspectCheckpoints validates checkpoint mappings and stored objects without
// writing or falling back through damaged volume/object-map/filesystem trees.
// SelectedTransaction identifies the newest structurally complete checkpoint;
// recovery separately accounts its entire supported filesystem before writing.
func InspectCheckpoints(ctx context.Context, source block.Source) (CheckpointReport, error) {
	report, _, _, err := inspectCheckpoints(ctx, source)
	return report, err
}

func inspectCheckpoints(ctx context.Context, source block.Source) (CheckpointReport, *Container, []checkpointCandidate, error) {
	var report CheckpointReport
	if err := ctx.Err(); err != nil {
		return report, nil, nil, err
	}
	c, zero, err := readContainerGeometry(source, true)
	if err != nil {
		return report, nil, nil, err
	}
	report.ContainerUUID, report.BlockSize, report.BlockZeroTransaction = uuid(zero[72:88]), c.BlockSize, XID(le.Uint64(zero[16:]))
	report.BlockZeroValid = !c.locatorDamaged
	candidates, err := c.checkpointCandidates(ctx, zero)
	if err != nil {
		return report, nil, nil, err
	}
	blocked := false
	remaining := uint64(2 * checkpointByteLimit)
	for _, candidate := range candidates {
		nx := candidate.data
		info := CheckpointInfo{Transaction: XID(le.Uint64(nx[16:])), Address: candidate.address, State: "valid",
			DescriptorIndex: le.Uint32(nx[136:]), DescriptorCount: le.Uint32(nx[140:]), DataIndex: le.Uint32(nx[144:]), DataCount: le.Uint32(nx[148:])}
		c.Checkpoint, c.XID = info.Address, info.Transaction
		var objects []checkpointObject
		if !candidateHeader(c, zero, nx) {
			err = corrupt("checkpoint superblock header", int64(info.Address)*int64(c.BlockSize))
		} else if le.Uint32(nx[24:]) != 0x80000001 {
			err = fmt.Errorf("checkpoint superblock storage %#x: %w", le.Uint32(nx[24:]), filesystem.ErrUnsupported)
		} else if le.Uint64(nx[64:]) != 2 {
			err = fmt.Errorf("checkpoint incompatible features %#x: %w", le.Uint64(nx[64:]), filesystem.ErrUnsupported)
		} else {
			objects, err = c.checkpointObjectsWithBudget(ctx, nx, &remaining)
		}
		if err != nil {
			info.err = err
			info.Reason = err.Error()
			if errors.Is(err, filesystem.ErrCorrupt) {
				info.State = "invalid"
			} else if errors.Is(err, filesystem.ErrUnsupported) || errors.Is(err, filesystem.ErrLimit) {
				info.State = "unsupported"
				if report.SelectedAddress == 0 {
					blocked = true
				}
			} else {
				return report, nil, nil, err
			}
		} else {
			info.Objects = len(objects)
			if report.SelectedAddress == 0 && !blocked {
				report.SelectedAddress, report.SelectedTransaction = info.Address, info.Transaction
			}
		}
		report.Candidates = append(report.Candidates, info)
	}
	return report, c, candidates, nil
}

type checkpointIdentity struct{ volume, object uint64 }
type checkpointObject struct {
	ephemeral
	volume uint64
}

// checkpointObjects decodes one complete checkpoint, not a set of independently
// valid superblocks. Layout and selection follow Apple's File System Reference,
// pp. 26–27 and 40–42. Inspection, recovery and mutation share these checks.
// Objects remain bound to this checkpoint's XID and selected data-ring range.
func (c *Container) checkpointObjects(ctx context.Context, nx []byte) ([]checkpointObject, error) {
	remaining := uint64(checkpointByteLimit)
	return c.checkpointObjectsWithBudget(ctx, nx, &remaining)
}

func (c *Container) checkpointObjectsWithBudget(ctx context.Context, nx []byte, remaining *uint64) ([]checkpointObject, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(nx) != int(c.BlockSize) || c.Checkpoint == 0 {
		return nil, corrupt("checkpoint superblock", 0)
	}
	count, base, index, length := le.Uint32(nx[104:]), le.Uint64(nx[112:]), le.Uint32(nx[136:]), le.Uint32(nx[140:])
	dataCount, dataBase, dataIndex, dataLength := le.Uint32(nx[108:]), le.Uint64(nx[120:]), le.Uint32(nx[144:]), le.Uint32(nx[148:])
	if count&0x80000000 != 0 || dataCount&0x80000000 != 0 {
		return nil, fmt.Errorf("noncontiguous checkpoint regions: %w", filesystem.ErrUnsupported)
	}
	if count == 0 || length < 2 || length > count || index >= count || base == 0 || base > c.BlockCount || uint64(count) > c.BlockCount-base ||
		dataCount == 0 || dataLength == 0 || dataLength > dataCount || dataIndex >= dataCount || dataBase == 0 || dataBase > c.BlockCount || uint64(dataCount) > c.BlockCount-dataBase ||
		(base < dataBase+uint64(dataCount) && dataBase < base+uint64(count)) ||
		uint64(c.Checkpoint) != base+(uint64(index)+uint64(length)-1)%uint64(count) ||
		le.Uint32(nx[128:]) >= count || le.Uint32(nx[132:]) >= dataCount {
		return nil, corrupt("checkpoint ring geometry", 0)
	}
	if count > 65536 || dataCount > 65536 || uint64(dataLength)*uint64(c.BlockSize) > checkpointByteLimit {
		return nil, filesystem.ErrLimit
	}
	identities := map[checkpointIdentity]bool{}
	claimed := make([]bool, dataLength)
	var objects []checkpointObject
	var total uint64
	for i := uint32(0); i < length-1; i++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		address := base + (uint64(index)+uint64(i))%uint64(count)
		if uint64(c.BlockSize) > *remaining {
			return nil, filesystem.ErrLimit
		}
		*remaining -= uint64(c.BlockSize)
		mapping, err := c.object(PhysicalAddress(address), 12)
		if err != nil {
			return nil, err
		}
		last := uint32(0)
		if i == length-2 {
			last = 1 // CHECKPOINT_MAP_LAST.
		}
		if le.Uint32(mapping[24:]) != 0x4000000c || le.Uint32(mapping[28:]) != 0 || le.Uint32(mapping[32:])&^uint32(1) != 0 {
			return nil, fmt.Errorf("checkpoint mapping flags/type: %w", filesystem.ErrUnsupported)
		}
		if le.Uint64(mapping[8:]) != address || le.Uint64(mapping[16:]) != uint64(c.XID) || le.Uint32(mapping[32:]) != last {
			return nil, corrupt("checkpoint mapping sequence", int64(address)*int64(c.BlockSize))
		}
		entries := le.Uint32(mapping[36:])
		if entries == 0 || uint64(entries) > uint64(len(mapping)-40)/40 {
			return nil, corrupt("checkpoint mapping count", int64(address)*int64(c.BlockSize))
		}
		if len(objects)+int(entries) > checkpointObjectLimit {
			return nil, filesystem.ErrLimit
		}
		for j := uint32(0); j < entries; j++ {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			r := mapping[40+j*40 : 80+j*40]
			object := checkpointObject{ephemeral: ephemeral{kind: le.Uint32(r), subtype: le.Uint32(r[4:]), oid: le.Uint64(r[24:]), address: le.Uint64(r[32:])}, volume: le.Uint64(r[16:])}
			size := le.Uint32(r[8:])
			if object.kind&0xffff0000 != 0x80000000 {
				return nil, fmt.Errorf("checkpoint object storage %#x: %w", object.kind, filesystem.ErrUnsupported)
			}
			if size == 0 || size%c.BlockSize != 0 || object.oid == 0 || object.address < dataBase || object.address >= dataBase+uint64(dataCount) || uint64(size/c.BlockSize) > dataBase+uint64(dataCount)-object.address {
				return nil, corrupt("checkpoint object range", int64(address)*int64(c.BlockSize))
			}
			if size > 64<<10 || total+uint64(size) > checkpointByteLimit {
				return nil, filesystem.ErrLimit
			}
			identity := checkpointIdentity{object.volume, object.oid}
			if identities[identity] {
				return nil, corrupt("duplicate checkpoint object", int64(address)*int64(c.BlockSize))
			}
			identities[identity] = true
			delta := (object.address - dataBase + uint64(dataCount) - uint64(dataIndex)) % uint64(dataCount)
			blocks := uint64(size / c.BlockSize)
			if delta >= uint64(dataLength) || blocks > uint64(dataLength)-delta {
				return nil, corrupt("object outside selected checkpoint data", int64(address)*int64(c.BlockSize))
			}
			for k := uint64(0); k < blocks; k++ {
				if claimed[delta+k] {
					return nil, corrupt("overlapping checkpoint objects", int64(address)*int64(c.BlockSize))
				}
				claimed[delta+k] = true
			}
			if uint64(size) > *remaining {
				return nil, filesystem.ErrLimit
			}
			*remaining -= uint64(size)
			object.data = make([]byte, size)
			if err = block.ReadFull(c.source, object.data, int64(object.address)*int64(c.BlockSize)); err != nil {
				return nil, err
			}
			if !validChecksum(object.data) || le.Uint64(object.data[8:]) != object.oid || le.Uint64(object.data[16:]) != uint64(c.XID) || le.Uint32(object.data[24:]) != object.kind || le.Uint32(object.data[28:]) != object.subtype {
				return nil, corrupt("checkpoint object header", int64(object.address)*int64(c.BlockSize))
			}
			total += uint64(size)
			objects = append(objects, object)
		}
	}
	for _, required := range []struct {
		offset int
		kind   uint32
	}{{152, 0x80000005}, {168, 0x80000011}} {
		found := false
		for _, object := range objects {
			found = found || (object.volume == 0 && object.oid == le.Uint64(nx[required.offset:]) && object.kind == required.kind && object.subtype == 0)
		}
		if !found {
			return nil, corrupt("missing checkpoint root object", 0)
		}
	}
	return objects, nil
}
