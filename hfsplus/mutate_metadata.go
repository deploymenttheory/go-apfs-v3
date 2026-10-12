/*
 * Copyright (c) 2000-2023 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
// SPDX-License-Identifier: APSL-2.0
// Modified 2026-10-12: Go adaptation of hfs_vnop_setattr, hfs_set_bsd_flags,
// hfs_vnop_setxattr/removexattr, getmaxinlineattrsize and attribute extent records.
// Byte slices and unpublished copies replace cnodes, credentials and journals.
// Exact source revision/hashes: docs/sources.json. License: LICENSES/APSL-2.0.txt.
package hfsplus

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"sort"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/finderinfo"
	"github.com/deploymenttheory/go-apfs-v3/internal/metadata"
	"github.com/deploymenttheory/go-apfs-v3/internal/mode"
)

func (m *mutation) editMetadata(c Change, stamp uint32) (uint32, error) {
	if err := metadata.ValidateChange(c); err != nil {
		return 0, err
	}
	item, err := m.lookup(c.Path)
	if errors.Is(err, fs.ErrNotExist) && c.Operation == "touch" {
		if c.NoCreate || c.NoFollow {
			return 0, nil
		}
		parent, name, e := m.destination(c.Path)
		if e != nil {
			return 0, e
		}
		item, err = m.createCatalog(parent, name, false, "", stamp)
	}
	if err != nil {
		return 0, err
	}
	if c.Recursive {
		var targets []*catalogItem
		seen := map[uint32]bool{}
		var walk func(*catalogItem, int) error
		walk = func(r *catalogItem, depth int) error {
			if depth > 256 {
				return filesystem.ErrLimit
			}
			inode, err := m.logical(r)
			if err != nil {
				return err
			}
			if seen[inode.id()] {
				return nil
			}
			if be.Uint16(inode.value[42:])&0170000 == 0120000 && c.Operation != "chown" && !c.NoFollow {
				return nil
			}
			seen[inode.id()] = true
			targets = append(targets, r)
			keys := make([]string, 0, len(m.children[r.id()]))
			for k := range m.children[r.id()] {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if err = walk(m.children[r.id()][k], depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		if err = walk(item, 0); err != nil {
			return 0, err
		}
		c.Recursive = false
		c.NoFollow = true
		for _, r := range targets {
			if err = m.metadataObject(c, r, stamp); err != nil {
				return 0, err
			}
		}
	} else {
		err = m.metadataObject(c, item, stamp)
	}
	if err != nil {
		return 0, err
	}
	inode, err := m.logical(item)
	if err != nil {
		return 0, err
	}
	return inode.id(), nil
}

func (m *mutation) metadataObject(c Change, item *catalogItem, stamp uint32) error {
	if err := m.ctx.Err(); err != nil {
		return err
	}
	if err := m.protectedMetadata(item, true, c.Operation == "chflags"); err != nil {
		return err
	}
	inode, err := m.logical(item)
	if err != nil {
		return err
	}
	value := bytes.Clone(inode.value)
	kind := be.Uint16(value[42:]) & 0170000
	if kind != 0100000 && kind != 0040000 && kind != 0120000 {
		return filesystem.ErrUnsupported
	}
	if kind == 0120000 && !c.NoFollow {
		return filesystem.ErrUnsupported
	}
	switch c.Operation {
	case "chmod":
		if be.Uint16(value[2:])&8 != 0 {
			return filesystem.ErrUnsupported
		}
		program, err := mode.Parse(c.Mode, 0)
		if err != nil {
			return err
		}
		be.PutUint16(value[42:], uint16(program.Apply(uint32(be.Uint16(value[42:])))))
	case "chown":
		if be.Uint16(value[42:])&06000 != 0 {
			return filesystem.ErrUnsupported
		}
		if c.Metadata.UID.State == filesystem.Present {
			be.PutUint32(value[32:], c.Metadata.UID.Value)
		}
		if c.Metadata.GID.State == filesystem.Present {
			be.PutUint32(value[36:], c.Metadata.GID.Value)
		}
	case "chflags":
		flags, err := metadata.Flags(catalogBSDFlags(value), c.Flags)
		if err != nil {
			return err
		}
		setCatalogBSDFlags(value, flags)
	case "touch":
		var reference *filesystem.Metadata
		if c.Reference != "" {
			ref, err := m.lookup(c.Reference)
			if err != nil {
				return err
			}
			ref, err = m.logical(ref)
			if err != nil {
				return err
			}
			reference = &filesystem.Metadata{ModifyTime: filesystem.Observed(time.Unix(int64(be.Uint32(ref.value[16:]))-2082844800, 0)), AccessTime: filesystem.Observed(time.Unix(int64(be.Uint32(ref.value[24:]))-2082844800, 0))}
		}
		patch := metadata.Touch(c, time.Unix(int64(stamp)-2082844800, 0), reference)
		for _, field := range []struct {
			v      filesystem.Observation[time.Time]
			offset int
		}{{patch.ModifyTime, 16}, {patch.AccessTime, 24}} {
			if field.v.State != filesystem.Present {
				continue
			}
			date, err := buildDate(field.v.Value.UTC().Truncate(time.Second))
			if err != nil {
				return err
			}
			be.PutUint32(value[field.offset:], date)
			if field.offset == 16 && date < be.Uint32(value[12:]) {
				be.PutUint32(value[12:], date)
			}
		}

	case "xattr":
		if err = m.changeAttribute(c, inode.id(), value); err != nil {
			return err
		}
		if c.Attribute == filesystem.ResourceFork {
			be.PutUint32(value[16:], stamp)
		}
	}
	be.PutUint32(value[20:], stamp)
	return m.patchCatalog(inode.id(), value)
}

func (m *mutation) attributeRecords(id uint32) ([]treeRecord, error) {
	t := m.trees[8]
	if t == nil {
		return nil, nil
	}
	base := &tree{fork: t.fork, root: be.Uint32(t.header[16:]), total: t.total, nodeSize: t.nodeSize, idOffset: 4}
	var records []treeRecord
	err := base.records(m.ctx, id, func(r treeRecord) error {
		records = append(records, treeRecord{bytes.Clone(r.key), bytes.Clone(r.value)})
		return nil
	})
	return records, err
}

func (m *mutation) attributeTree() (*mutableTree, error) {
	if t := m.trees[8]; t != nil {
		return t, nil
	}
	return nil, fmt.Errorf("HFS attributes-file initialization is unqualified: %w", filesystem.ErrUnsupported)
}

func (m *mutation) changeAttribute(c Change, id uint32, value []byte) error {
	name := c.Attribute
	if name == filesystem.FinderInfo {
		exists := !bytes.Equal(finderInfo(value), make([]byte, 32))
		if (c.DeleteAttribute || c.AttributeMode == "replace") && !exists {
			return fs.ErrNotExist
		}
		if c.AttributeMode == "create" && exists {
			return fs.ErrExist
		}
		data := make([]byte, 32)
		if !c.DeleteAttribute {
			if c.Data.Size() != 32 {
				return fs.ErrInvalid
			}
			if err := block.ReadFull(c.Data, data, 0); err != nil {
				return err
			}
			if be.Uint16(value[42:])&0170000 != 0120000 && string(data[:4]) == "hlnk" {
				return filesystem.ErrUnsupported
			}
			data = finderinfo.HFS(data, uint32(be.Uint16(value[42:])))
		}
		// hfs_vnop_setxattr/removexattr retain document ID, date-added and generation.
		for _, span := range [][2]int{{16, 24}, {28, 32}} {
			copy(data[span[0]:span[1]], value[48+span[0]:48+span[1]])
		}
		if be.Uint16(value[42:])&0170000 == 0120000 {
			copy(data[:8], value[48:56])
		}
		copy(value[48:80], data)
		return nil
	}
	if name == filesystem.ResourceFork {
		if be.Uint16(value[42:])&0170000 != 0100000 || value[41]&0x20 != 0 {
			return filesystem.ErrUnsupported
		}
		exists := be.Uint64(value[168:]) != 0
		if (c.DeleteAttribute || c.AttributeMode == "replace") && !exists {
			return fs.ErrNotExist
		}
		if c.AttributeMode == "create" && exists {
			return fs.ErrExist
		}
		data := c.Data
		if c.DeleteAttribute {
			data = emptySource{}
		}
		return m.replaceFork(id, 255, value[168:248], data)
	}
	records, err := m.attributeRecords(id)
	if err != nil {
		return err
	}
	key := attributeKey(id, name)
	var selected []treeRecord
	var descriptor []byte
	continuations := map[uint32][]byte{}
	others := false
	for _, r := range records {
		if !bytes.Equal(r.key[12:], key[12:]) {
			others = true
			continue
		}
		selected = append(selected, r)
		if be.Uint32(r.value) == 0x20 {
			descriptor = bytes.Clone(r.value[8:])
		}
		if be.Uint32(r.value) == 0x30 {
			continuations[be.Uint32(r.key[8:])] = bytes.Clone(r.value[8:])
		}
	}
	exists := len(selected) != 0
	if (c.DeleteAttribute || c.AttributeMode == "replace") && !exists {
		return fs.ErrNotExist
	}
	if c.AttributeMode == "create" && exists {
		return fs.ErrExist
	}
	t, err := m.attributeTree()
	if err != nil {
		return err
	}
	if descriptor != nil {
		f, err := resolveFork(m.ctx, m.disk, m.v.BlockSize, m.v.BlockCount, descriptor, func() (map[uint32][]byte, error) { return continuations, nil })
		if err != nil {
			return err
		}
		for _, r := range forkRuns(f, m.v.BlockSize) {
			if err = m.mark(r, false); err != nil {
				return err
			}
		}
	}
	for _, r := range selected {
		if err = t.set(r.key, nil, true); err != nil {
			return err
		}
	}
	if !c.DeleteAttribute {
		if c.Data.Size() > math.MaxInt32 {
			return filesystem.ErrLimit
		}
		// Apple's getmaxinlineattrsize: two maximum-size records must fit a node.
		maxInline := (int(t.nodeSize)-14-6)/2 - 268 - 18
		maxInline &^= 1
		if c.Data.Size() <= int64(maxInline) {
			b := make([]byte, 16+(c.Data.Size()+1)&^1)
			be.PutUint32(b, 0x10)
			be.PutUint32(b[12:], uint32(c.Data.Size()))
			if c.Data.Size() != 0 {
				if err = block.ReadFull(c.Data, b[16:16+c.Data.Size()], 0); err != nil {
					return err
				}
			}
			if err = t.set(key, b, false); err != nil {
				return err
			}
		} else {
			blocks := (uint64(c.Data.Size()) + uint64(m.v.BlockSize) - 1) / uint64(m.v.BlockSize)
			runs, err := m.allocate(uint32(blocks), 0)
			if err != nil {
				return err
			}
			if err = m.writePayload(forkFromRuns(m.disk, m.v.BlockSize, blocks*uint64(m.v.BlockSize), runs), c.Data); err != nil {
				return err
			}
			b := make([]byte, 88)
			be.PutUint32(b, 0x20)
			encodeRuns(b[8:], uint64(c.Data.Size()), runs)
			if err = t.set(key, b, false); err != nil {
				return err
			}
			var logical uint32
			for i, r := range runs {
				if i >= 8 && i%8 == 0 {
					b := make([]byte, 72)
					be.PutUint32(b, 0x30)
					for j, x := range runs[i:min(i+8, len(runs))] {
						be.PutUint32(b[8+j*8:], x.start)
						be.PutUint32(b[12+j*8:], x.count)
					}
					k := bytes.Clone(key)
					be.PutUint32(k[8:], logical)
					if err = t.set(k, b, false); err != nil {
						return err
					}
				}
				logical += r.count
			}
		}
	}
	flags := be.Uint16(value[2:])
	if others || !c.DeleteAttribute {
		flags |= 4
	} else {
		flags &^= 4
	}
	be.PutUint16(value[2:], flags)
	return nil
}
