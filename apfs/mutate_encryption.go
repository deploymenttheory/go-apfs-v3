package apfs

import (
	"bytes"
	"context"
	"fmt"
	"io/fs"
	"slices"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// EncryptionConversion requests a completed change to APFS volume storage,
// independently of its DMG envelope. Encrypt borrows a non-nil Password for new
// keys; decrypt uses the keys already owned by the authenticated MutationSource.
type EncryptionConversion struct {
	Encrypt  bool
	Password []byte `json:"-"`
}

// VolumeEncryptionReport describes the completed storage transition, not keys
// or credentials. The volume and retained filesystem identities are preserved.
type VolumeEncryptionReport struct {
	BeforeEncrypted bool   `json:"beforeEncrypted"`
	Encrypted       bool   `json:"encrypted"`
	Completed       bool   `json:"completed"`
	CryptoUser      string `json:"cryptoUser,omitempty"`
}

type EncryptionConversionReport struct {
	ChangeReport
	Encryption VolumeEncryptionReport `json:"volumeEncryption"`
}

// ConvertVolumeEncryption changes an exclusively owned, unpublished volume in
// place, retaining inode/snapshot identities and shared physical data ranges.
// Authenticate all peers with UnlockMutation first, even for a plaintext source.
// The MutationSource owns the resulting keys, so later commands can use the new
// state without retaining passwords. Any error invalidates the unpublished copy.
func ConvertVolumeEncryption(ctx context.Context, disk *MutationSource, volumeUUID string, conversion EncryptionConversion, when time.Time) (EncryptionConversionReport, error) {
	var report EncryptionConversionReport
	if disk == nil || conversion.Encrypt != (conversion.Password != nil) || when.IsZero() || when.Nanosecond() != 0 {
		return report, fs.ErrInvalid
	}
	stamp, err := buildTime(when)
	if err != nil {
		return report, err
	}
	m, err := openMutationVolume(ctx, disk, volumeUUID)
	if err != nil {
		return report, err
	}
	if volumeUUID == "" && len(m.c.Volumes) != 1 || m.v.Encrypted == conversion.Encrypt {
		return report, fs.ErrInvalid
	}
	previousKey := m.v.keys
	var key *volumeKeys
	var user, wrapped []byte
	if conversion.Encrypt {
		key, user, wrapped, err = newSoftwareVolumeKeys(ctx, m.v.id, conversion.Password)
		if err != nil {
			return report, err
		}
	}
	owned := false
	defer func() {
		if key != nil && !owned {
			key.xts = nil
		}
	}()
	// Plan all view/extent changes before touching payload bytes. The accountant
	// already establishes that no peer or metadata allocation aliases this data.
	trees, ranges, err := m.conversionPlan(conversion.Encrypt)
	if err != nil {
		return report, err
	}
	if err = m.convertKeybags(conversion.Encrypt, user, wrapped); err != nil {
		return report, err
	}
	if err = m.convertData(ranges, previousKey, key); err != nil {
		return report, err
	}
	if err = m.convertFilesystem(trees, conversion.Encrypt, key); err != nil {
		return report, err
	}
	if err = m.convertSnapshotSuperblocks(conversion.Encrypt); err != nil {
		return report, err
	}
	m.v.Encrypted, m.v.keys = conversion.Encrypt, key
	convertEncryptionSuperblock(m.super, conversion.Encrypt)
	if err = m.commit(stamp); err != nil {
		return report, err
	}
	if conversion.Encrypt {
		fresh, err := Open(disk)
		if err != nil {
			return report, err
		}
		for i := range fresh.Volumes {
			if fresh.Volumes[i].UUID == m.v.UUID {
				view, err := fresh.Volumes[i].Unlock(ctx, conversion.Password)
				if err != nil {
					return report, err
				}
				if err := view.Close(); err != nil {
					return report, err
				}
			}
		}
	}
	// Only the committed private state changes key ownership. Invalidate any
	// borrowed old-key readers before exposing the completed new storage state.
	disk.mu.Lock()
	if previousKey != nil {
		previousKey.mu.Lock()
		previousKey.xts = nil
		previousKey.mu.Unlock()
	}
	delete(disk.keys, m.v.id)
	if key != nil {
		disk.keys[m.v.id] = key
	}
	owned = true
	disk.mu.Unlock()
	if err = ValidateMutation(ctx, disk); err != nil {
		return report, err
	}
	state := VolumeEncryptionReport{BeforeEncrypted: !conversion.Encrypt, Encrypted: conversion.Encrypt, Completed: true}
	if conversion.Encrypt {
		state.CryptoUser = m.v.UUID
	}
	return EncryptionConversionReport{ChangeReport: ChangeReport{VolumeID: m.v.UUID, FreeBlocks: m.space.free, Transaction: m.xid}, Encryption: state}, nil
}

type conversionExtent struct{ start, end, crypto uint64 }

func (m *mutation) conversionPlan(encrypted bool) ([]*cowTree, []conversionExtent, error) {
	var trees []*cowTree
	var ranges []conversionExtent
	nodes := 0
	for _, view := range m.ownership.views {
		var records []buildRecord
		for _, original := range view.fs.all() {
			if err := m.ctx.Err(); err != nil {
				return nil, nil, err
			}
			r := buildRecord{bytes.Clone(original.key), bytes.Clone(original.value)}
			kind := prefix(r.key).kind
			if kind == 7 {
				continue // The target view gets exactly its own completed crypto state.
			}
			crypto := uint64(0)
			if encrypted {
				crypto = 4
			}
			switch kind {
			case 3:
				if err := extendedFields(r.value[92:], func(kind byte, data []byte) error {
					if kind == 8 {
						le.PutUint64(data[16:], crypto)
					}
					return nil
				}); err != nil {
					return nil, nil, err
				}
			case 4:
				if le.Uint16(r.value)&1 != 0 {
					le.PutUint64(r.value[28:], crypto)
				}
			case 8:
				address, size := le.Uint64(r.value[8:]), le.Uint64(r.value)&((1<<56)-1)
				if address != 0 {
					old := address
					if m.v.Encrypted {
						old = le.Uint64(r.value[16:])
					}
					ranges = append(ranges, conversionExtent{address, address + size/4096, old})
				}
				le.PutUint64(r.value, size)
				le.PutUint64(r.value[16:], 0)
				if encrypted && address != 0 {
					le.PutUint64(r.value, size|1<<56)
					le.PutUint64(r.value[16:], address)
				}
			}
			records = append(records, r)
		}
		storage := uint32(0)
		if encrypted {
			storage = 0x10000000
			state := make([]byte, 24)
			le.PutUint32(state, 1)
			records = append(records, buildRecord{buildKey(4, 7, 0), state})
		}
		less := view.fs.less
		slices.SortFunc(records, func(a, b buildRecord) int {
			if less(a.key, b.key) {
				return -1
			}
			if less(b.key, a.key) {
				return 1
			}
			return 0
		})
		tree, err := newBuildTree(records, 14, storage, false)
		if err != nil {
			return nil, nil, err
		}
		nodes += len(tree.nodes)
		if nodes > 16000 || len(ranges) > maxStorageRecords {
			return nil, nil, filesystem.ErrLimit
		}
		converted := &cowTree{buildTree: tree, rootNode: tree.root(), dirty: map[*buildTreeNode]bool{}, less: less, newOID: m.nextOID}
		for _, node := range tree.nodes {
			node.oid, err = m.nextOID()
			if err != nil {
				return nil, nil, err
			}
			converted.dirty[node] = true
		}
		// Each retained superblock still addresses its original virtual root.
		converted.rootNode.oid = view.fs.rootNode.oid
		trees = append(trees, converted)
	}
	// Shared and partially shared data is transformed once. Every overlapping
	// owner must agree about the original tweak at each physical sector.
	slices.SortFunc(ranges, func(a, b conversionExtent) int {
		if a.start < b.start {
			return -1
		}
		if a.start > b.start {
			return 1
		}
		return 0
	})
	var unique []conversionExtent
	for _, r := range ranges {
		if len(unique) > 0 {
			last := &unique[len(unique)-1]
			if r.start < last.end {
				if last.crypto+r.start-last.start != r.crypto {
					return nil, nil, corrupt("shared conversion extent tweaks", int64(r.start)*4096)
				}
				last.end = max(last.end, r.end)
				continue
			}
		}
		unique = append(unique, r)
	}
	return trees, unique, nil
}

func (m *mutation) convertData(ranges []conversionExtent, before, after *volumeKeys) error {
	var buffer [128 << 10]byte
	defer clear(buffer[:])
	for _, r := range ranges {
		for at := r.start; at < r.end; {
			if err := m.ctx.Err(); err != nil {
				return err
			}
			count := min(r.end-at, uint64(len(buffer)/4096))
			data := buffer[:count*4096]
			if err := block.ReadFull(m.disk, data, int64(at)*4096); err != nil {
				return err
			}
			if before != nil {
				if err := before.decrypt(data, (r.crypto+at-r.start)*8); err != nil {
					return err
				}
			}
			if after != nil {
				if err := after.encrypt(data, at*8); err != nil {
					return err
				}
			}
			if err := m.write(data, at*4096); err != nil {
				return err
			}
			at += count
		}
	}
	return nil
}

// Rewrite only virtual filesystem metadata, preserving every logical record,
// inode ID and snapshot XID. Physical file/fork extents keep their sharing and
// addresses. Metadata nodes may grow for the completed crypto-state record.
func (m *mutation) convertFilesystem(trees []*cowTree, encrypted bool, key *volumeKeys) error {
	oldNodes := map[uint64]bool{}
	convertedMetadata := map[uint64]bool{}
	for _, r := range m.vmap.all() {
		if le.Uint32(r.value)&1 != 0 {
			if le.Uint64(r.key) != uint64(m.v.snapMetaExt) {
				if err := m.vmap.put(r.key, nil); err != nil {
					return err
				}
			}
			continue
		}
		address := le.Uint64(r.value[8:])
		if convertedMetadata[address] {
			value := bytes.Clone(r.value)
			le.PutUint32(value, 0)
			if encrypted {
				le.PutUint32(value, 4)
			}
			if err := m.vmap.put(r.key, value); err != nil {
				return err
			}
			continue
		}
		object, err := m.v.object(objectMapping{PhysicalAddress(address), le.Uint32(r.value)&4 != 0}, 0)
		if err != nil {
			return err
		}
		if le.Uint32(object[28:]) == 14 {
			oldNodes[address] = true
			if err := m.vmap.put(r.key, nil); err != nil {
				return err
			}
			continue
		}
		if le.Uint32(object[24:])&0xffff != 29 {
			return fmt.Errorf("conversion virtual object: %w", filesystem.ErrUnsupported)
		}
		kind := le.Uint32(object[24:]) &^ uint32(0x10000000)
		flags := uint32(0)
		if encrypted {
			kind |= 0x10000000
			flags = 4
		}
		sealMutationObject(object, le.Uint64(object[8:]), le.Uint64(object[16:]), kind, le.Uint32(object[28:]))
		if encrypted {
			if err := key.encrypt(object, address*8); err != nil {
				return err
			}
		}
		if err := m.write(object, address*4096); err != nil {
			return err
		}
		convertedMetadata[address] = true
		value := bytes.Clone(r.value)
		le.PutUint32(value, flags)
		if err := m.vmap.put(r.key, value); err != nil {
			return err
		}
	}
	for address := range oldNodes {
		if m.history != nil {
			delete(m.history.metadata, address)
		}
		if err := m.retireMetadata(address, true); err != nil {
			return err
		}
		// Retired plaintext inline attributes must not remain exposed as stale
		// virtual metadata in the newly encrypted private output.
		if err := m.write(make([]byte, 4096), address*4096); err != nil {
			return err
		}
	}
	for i, tree := range trees[:len(trees)-1] {
		xid := uint64(m.ownership.snapshots[i].XID)
		for _, node := range tree.nodes {
			address, err := m.allocateMetadata(true)
			if err != nil {
				return err
			}
			node.address = address
			m.history.metadata[address] = true
		}
		for _, node := range tree.nodes {
			data := tree.nodeBytes(node, node == tree.rootNode)
			sealMutationObject(data, node.oid, xid, le.Uint32(data[24:]), 14)
			if encrypted {
				if err := key.encrypt(data, node.address*8); err != nil {
					return err
				}
			}
			if err := m.write(data, node.address*4096); err != nil {
				return err
			}
			value := make([]byte, 16)
			if encrypted {
				le.PutUint32(value, 4)
			}
			le.PutUint32(value[4:], 4096)
			le.PutUint64(value[8:], node.address)
			if err := m.vmap.put(append(buildUint64(node.oid), buildUint64(xid)...), value); err != nil {
				return err
			}
		}
	}
	m.fs = trees[len(trees)-1]
	return nil
}

func convertEncryptionSuperblock(super []byte, encrypted bool) {
	flags := le.Uint64(super[264:]) &^ uint64(9)
	if encrypted {
		flags |= 8
	} else {
		flags |= 1
	}
	le.PutUint64(super[264:], flags)
	le.PutUint64(super[56:], le.Uint64(super[56:])|4) // Completed encryption/key change.
}

func (m *mutation) convertSnapshotSuperblocks(encrypted bool) error {
	for _, snapshot := range m.ownership.snapshots {
		data, err := m.c.object(snapshot.superblock, 13)
		if err != nil {
			return err
		}
		convertEncryptionSuperblock(data, encrypted)
		sealMutationObject(data, le.Uint64(data[8:]), le.Uint64(data[16:]), le.Uint32(data[24:]), le.Uint32(data[28:]))
		if err := m.write(data, uint64(snapshot.superblock)*4096); err != nil {
			return err
		}
	}
	return nil
}

func (m *mutation) convertKeybags(encrypted bool, user, wrapped []byte) error {
	var entries []keybagEntry
	if m.c.keylockerCount != 0 {
		var err error
		entries, err = m.c.keybag(m.ctx, m.c.keylockerStart, m.c.keylockerCount, m.c.id, 0x6b657973)
		if err != nil {
			return err
		}
	}
	if encrypted {
		bag, err := m.newConversionKeybag([]keybagEntry{{id: m.v.id, tag: 3, data: user}}, m.v.id, 0x72656373)
		if err != nil {
			return err
		}
		extent := append(buildUint64(bag), buildUint64(1)...)
		entries = append(entries, keybagEntry{id: m.v.id, tag: 3, data: extent}, keybagEntry{id: m.v.id, tag: 2, data: wrapped})
	} else {
		var retained []keybagEntry
		for _, entry := range entries {
			if entry.id != m.v.id {
				retained = append(retained, entry)
				continue
			}
			if entry.tag == 3 {
				if err := m.space.retire(false, le.Uint64(entry.data), le.Uint64(entry.data[8:])); err != nil {
					return err
				}
			}
		}
		entries = retained
	}
	address, count := uint64(0), uint64(0)
	if len(entries) != 0 {
		var err error
		address, err = m.newConversionKeybag(entries, m.c.id, 0x6b657973)
		if err != nil {
			return err
		}
		count = uint64(conversionKeybagSize(entries) / 4096)
	}
	if m.c.keylockerCount != 0 {
		if err := m.space.retire(false, m.c.keylockerStart, m.c.keylockerCount); err != nil {
			return err
		}
	}
	le.PutUint64(m.nx[1296:], address)
	le.PutUint64(m.nx[1304:], count)
	return nil
}

func conversionKeybagSize(entries []keybagEntry) int {
	size := 48
	for _, entry := range entries {
		size = (size + 24 + len(entry.data) + 15) &^ 15
	}
	return (size + 4095) &^ 4095
}

func (m *mutation) newConversionKeybag(entries []keybagEntry, id [16]byte, kind uint32) (uint64, error) {
	data := make([]byte, conversionKeybagSize(entries))
	if err := encodeBuildKeybag(data, entries, kind); err != nil {
		return 0, err
	}
	count := uint64(len(data) / 4096)
	address, allocated, err := m.space.allocate(count)
	if err != nil {
		return 0, err
	}
	if allocated != count {
		return 0, filesystem.ErrLimit
	}
	sealMutationObject(data, 0, m.xid, kind, 0)
	if err := encryptBuildKeybag(data, id, address); err != nil {
		return 0, err
	}
	return address, m.write(data, address*4096)
}
