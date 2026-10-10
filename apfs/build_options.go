package apfs

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io/fs"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const (
	VolumeRoleNone        uint16 = 0
	VolumeRoleSystem      uint16 = 1
	VolumeRoleData        uint16 = 0x40
	volumeGroupInodeSpace uint64 = 0x10
	systemObjIDMark       uint64 = 0x0fffffff00000000
)

// VolumeSpec borrows one immutable APFS reader. Reserve and Quota are byte
// counts rounded up to blocks; zero means no constraint. Native roles currently
// admitted for construction are None, System and Data.
type VolumeSpec struct {
	Reader         filesystem.Reader `json:"-"`
	Name           string
	CaseSensitive  bool
	UUID           [16]byte
	Role           uint16
	Reserve, Quota int64
}

// VolumeGroupSpec pairs the zero-based volume indexes System and Data. Each
// member must have the matching role and can belong to exactly one group.
// A zero UUID derives a group identity from the complete construction inputs.
type VolumeGroupSpec struct {
	System, Data int
	UUID         [16]byte
}

// ContainerBuildOptions describes one fresh, unencrypted APFS container.
// Volume order is significant and retained. Zero capacity selects automatic
// sizing; zero UUID derives an identity from all volume inputs and options.
type ContainerBuildOptions struct {
	Capacity int64
	Time     time.Time
	UUID     [16]byte
	Groups   []VolumeGroupSpec
}

// PlanContainer validates every volume and the shared allocation before hashing
// payloads. It borrows all readers through Write; it never modifies a source.
func PlanContainer(ctx context.Context, inputs []VolumeSpec, o ContainerBuildOptions) (*Layout, error) {
	if len(inputs) == 0 || len(inputs) > 100 || o.Capacity < 0 || o.Capacity > 1<<40 || o.Time.IsZero() {
		return nil, fs.ErrInvalid
	}
	if _, err := buildTime(o.Time); err != nil {
		return nil, err
	}
	o.Time = o.Time.UTC()
	o.Groups = append([]VolumeGroupSpec(nil), o.Groups...)
	p := &Layout{options: o}
	members := make(map[int]bool)
	groupIDs := make(map[[16]byte]bool)
	for _, g := range o.Groups {
		if g.System < 0 || g.System >= len(inputs) || g.Data < 0 || g.Data >= len(inputs) || g.System == g.Data || members[g.System] || members[g.Data] {
			return nil, fmt.Errorf("invalid APFS volume group members: %w", fs.ErrInvalid)
		}
		if inputs[g.System].Role != VolumeRoleSystem || inputs[g.Data].Role != VolumeRoleData || inputs[g.System].CaseSensitive != inputs[g.Data].CaseSensitive {
			return nil, fmt.Errorf("APFS group requires matching System/Data volumes: %w", fs.ErrInvalid)
		}
		members[g.System], members[g.Data] = true, true
		if g.UUID != [16]byte{} {
			if groupIDs[g.UUID] {
				return nil, filesystem.ErrConflict
			}
			groupIDs[g.UUID] = true
		}
	}
	ids := make(map[[16]byte]bool)
	for i, v := range inputs {
		if v.Reader == nil || v.Reserve < 0 || v.Quota < 0 || v.Reserve > 1<<40 || v.Quota > 1<<40 || v.Quota != 0 && v.Reserve > v.Quota {
			return nil, fs.ErrInvalid
		}
		if v.Role != VolumeRoleNone && v.Role != VolumeRoleSystem && v.Role != VolumeRoleData {
			return nil, fmt.Errorf("APFS construction role %#x: %w", v.Role, filesystem.ErrUnsupported)
		}
		if v.Role == VolumeRoleSystem && !members[i] {
			return nil, fmt.Errorf("system construction requires a System/Data volume group: %w", fs.ErrInvalid)
		}
		if v.UUID != [16]byte{} {
			if ids[v.UUID] {
				return nil, filesystem.ErrConflict
			}
			ids[v.UUID] = true
		}
		volume := &volumeLayout{reader: v.Reader, options: v, time: o.Time, budget: &p.metadataBytes, nextID: 16, grouped: members[i]}
		// Native grouped System roots/private directories keep reserved IDs 1–3.
		// User objects and apfs_next_obj_id use SYSTEM_OBJ_ID_MARK, as observed
		// in Apple-created volumes. UNIFIED_ID_SPACE_MARK is not an allocator
		// starting point: that value passed fsck but panicked the native driver.
		if volume.grouped && v.Role == VolumeRoleSystem {
			volume.nextID += systemObjIDMark
		}
		if err := volume.collect(ctx); err != nil {
			return nil, fmt.Errorf("volume %d (%q): %w", i, v.Name, err)
		}
		p.volumes = append(p.volumes, volume)
	}
	if err := p.arrange(ctx); err != nil {
		return nil, err
	}
	h := sha256.New()
	options, _ := json.Marshal(o)
	_, _ = h.Write(options)
	for _, v := range p.volumes {
		digest, err := v.fingerprint(ctx)
		if err != nil {
			return nil, err
		}
		_, _ = h.Write(digest)
	}
	seed := h.Sum(nil)
	derive := func(label string) [16]byte {
		sum := sha256.Sum256(append([]byte(label), seed...))
		var id [16]byte
		copy(id[:], sum[:])
		id[6] = (id[6] & 15) | 0x80
		id[8] = (id[8] & 63) | 0x80
		return id
	}
	if p.options.UUID == [16]byte{} {
		p.options.UUID = derive("APFS container")
	}
	for i, v := range p.volumes {
		if v.options.UUID == [16]byte{} {
			v.options.UUID = derive(fmt.Sprintf("APFS volume %d", i))
		}
	}
	for i, g := range p.options.Groups {
		if g.UUID == [16]byte{} {
			g.UUID = derive(fmt.Sprintf("APFS group %d", i))
			p.options.Groups[i] = g
		}
		p.volumes[g.System].group = g.UUID
		p.volumes[g.Data].group = g.UUID
	}
	// Explicit and derived identifiers share a namespace within their own kind.
	clear(ids)
	for _, v := range p.volumes {
		if ids[v.options.UUID] {
			return nil, filesystem.ErrConflict
		}
		ids[v.options.UUID] = true
		copy(v.superblock[240:256], v.options.UUID[:])
		copy(v.superblock[1008:1024], v.group[:])
	}
	clear(groupIDs)
	for _, g := range p.options.Groups {
		if groupIDs[g.UUID] {
			return nil, filesystem.ErrConflict
		}
		groupIDs[g.UUID] = true
	}
	for _, part := range p.parts {
		b := part.data
		if len(b) < 32 {
			continue
		}
		kind := le.Uint32(b[24:])
		if kind == 0x80000001 {
			copy(b[72:88], p.options.UUID[:])
		} else if kind != 13 {
			continue
		}
		sealBuildObject(b, le.Uint64(b[8:]), kind, le.Uint32(b[28:]))
	}
	return p, ctx.Err()
}
