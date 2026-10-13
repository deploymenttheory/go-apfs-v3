/*
 * Copyright (c) 1999-2023 Apple Inc. All rights reserved.
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
// Modified 2026-10-12: Go adaptation of hfs_makelink/createindirectlink and
// hfs_vnop_symlink. Unpublished-copy transactions replace vnodes and rollback.
// Exact revisions/hashes: docs/sources.json. License: LICENSES/APSL-2.0.txt.
package hfsplus

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	linkcommand "github.com/deploymenttheory/go-apfs-v3/internal/link"
	"github.com/deploymenttheory/go-apfs-v3/internal/names"
)

func (m *mutation) linkCatalog(c Change, stamp uint32) (uint32, error) {
	if err := linkcommand.Validate(c); err != nil {
		return 0, err
	}
	var source, inode *catalogItem
	if !c.Symbolic {
		var err error
		source, err = m.lookup(c.Path)
		if err != nil {
			return 0, err
		}
		if err = m.protected(source, true); err != nil {
			return 0, err
		}
		inode, err = m.logical(source)
		if err != nil {
			return 0, err
		}
		if be.Uint16(inode.value[42:])&0170000 != 0100000 {
			return 0, filesystem.ErrUnsupported
		}
		if err = m.initializePrivateDirectory(stamp); err != nil {
			return 0, err
		}
	}
	var parent *catalogItem
	var name string
	target, err := m.lookup(c.Destination)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return 0, err
	}
	if target != nil && target.directory() {
		parent, name = target, path.Base(c.Path)
		name, err = names.Stored(name, "HFS+")
		if err != nil {
			return 0, err
		}
	} else {
		if strings.HasSuffix(c.Destination, "/") {
			return 0, fs.ErrInvalid
		}
		parent, name, err = m.destination(c.Destination)
		if err != nil {
			return 0, err
		}
	}
	existing := m.children[parent.id()][names.HFS(name, m.v.CaseSensitive)]
	if err = m.writableParent(parent); err != nil {
		return 0, err
	}
	if existing != nil {
		if !c.Force {
			return 0, fs.ErrExist
		}
		if existing.directory() {
			return 0, fs.ErrInvalid
		}
		if source != nil && existing.id() == source.id() {
			return 0, fs.ErrExist
		}
		if be.Uint16(existing.value[42:])&0170000 == 0120000 && !c.NoFollow {
			return 0, filesystem.ErrUnsupported
		}
		if err = m.removeCatalog(existing, false, stamp); err != nil {
			return 0, err
		}
	}
	if be.Uint32(m.header[48:]) == 0 {
		return 0, syscall.ENOSPC
	}
	if inode != nil && inode.parent() == m.v.privateID && be.Uint32(inode.value[44:]) >= 32767 { // HFS_LINK_MAX
		return 0, filesystem.ErrLimit
	}
	if c.Symbolic {
		entry, err := m.createCatalogKind(parent, name, 0120000, "", stamp)
		if err != nil {
			return 0, err
		}
		value := bytes.Clone(entry.value)
		if err = m.replaceFork(entry.id(), 0, value[88:168], bytes.NewReader([]byte(c.Path))); err != nil {
			return 0, err
		}
		return entry.id(), m.patchCatalog(entry.id(), value)
	}
	value := bytes.Clone(inode.value)
	first := inode.parent() != m.v.privateID
	var reference uint32
	if first {
		oldParent, oldName := inode.parent(), inode.name()
		reference = inode.id()
		for checked := 0; m.children[m.v.privateID][m.catalogName("iNode"+strconv.FormatUint(uint64(reference), 10))] != nil; checked++ {
			if checked > len(m.children[m.v.privateID]) {
				return 0, filesystem.ErrLimit
			}
			reference, err = m.allocateCNID()
			if err != nil {
				return 0, err
			}
		}
		if err = m.relocateCatalog(inode, m.v.privateID, "iNode"+strconv.FormatUint(uint64(reference), 10), stamp); err != nil {
			return 0, err
		}
		original, err := m.indirectLink(oldParent, oldName, reference, 0, true, stamp)
		if err != nil {
			return 0, err
		}
		be.PutUint16(value[2:], be.Uint16(value[2:])|0x20)
		be.PutUint32(value[4:], original.id())
		be.PutUint32(value[44:], 1)
	} else {
		reference, err = m.linkReference(inode)
		if err != nil {
			return 0, err
		}
	}
	chain := be.Uint16(value[2:])&0x20 != 0
	head := uint32(0)
	if chain {
		head = be.Uint32(value[4:])
	}
	alias, err := m.indirectLink(parent.id(), name, reference, head, chain, stamp)
	if err != nil {
		return 0, err
	}
	if chain {
		old := m.catalog[head]
		if old == nil {
			return 0, bad("hard link chain head")
		}
		previous := bytes.Clone(old.value)
		be.PutUint32(previous[32:], alias.id())
		if err = m.patchCatalog(head, previous); err != nil {
			return 0, err
		}
		be.PutUint32(value[4:], alias.id())
	}
	be.PutUint32(value[44:], be.Uint32(value[44:])+1)
	be.PutUint32(value[20:], stamp)
	return inode.id(), m.patchCatalog(inode.id(), value)
}

// hfs_privatedir_init(FILE_HARDLINKS), from the pinned Apple hfs_link.c.
// Native writable mounts initialize this directory; offline edits must also
// handle original formatted images which have only been mounted read-only.
func (m *mutation) initializePrivateDirectory(stamp uint32) error {
	if m.v.privateID != 0 {
		return nil
	}
	id, err := m.allocateCNID()
	if err != nil {
		return err
	}
	value := make([]byte, 88)
	be.PutUint16(value, 1)
	be.PutUint16(value[2:], 0x10) // kHFSHasFolderCountMask
	be.PutUint32(value[8:], id)
	created := be.Uint32(m.header[16:]) // hfsmp->hfs_itime
	be.PutUint32(value[12:], created)
	be.PutUint16(value[42:], 0040000)
	be.PutUint32(value[44:], 1)
	setCatalogBSDFlags(value, 0x8002) // UF_IMMUTABLE | UF_HIDDEN
	be.PutUint16(value[56:], 0x5000)  // kIsInvisible | kNameLocked
	be.PutUint16(value[58:], 16384)
	be.PutUint16(value[60:], 16384)
	item := &catalogItem{catalogKey(2, privateDirectory), value}
	if err = m.insertCatalog(item, stamp); err != nil {
		return err
	}
	m.v.privateID, m.v.privateCreated = id, created
	return nil
}

func (m *mutation) indirectLink(parent uint32, name string, reference, next uint32, chain bool, stamp uint32) (*catalogItem, error) {
	id, err := m.allocateCNID()
	if err != nil {
		return nil, err
	}
	created := m.v.privateCreated
	if created == 0 {
		created = m.v.rootCreated
	}
	value := indirectLinkRecord(id, reference, created, 0, next, chain)
	item := &catalogItem{catalogKey(parent, name), value}
	return item, m.insertCatalog(item, stamp)
}

// indirectLinkRecord is shared with fresh construction. BSD owner/group slots
// hold sibling CNIDs; the inode alone supplies public ownership and metadata.
func indirectLinkRecord(id, reference, created, previous, next uint32, chain bool) []byte {
	b := make([]byte, 248)
	be.PutUint16(b, 2)
	flags := uint16(2)
	if chain {
		flags |= 0x20
	}
	be.PutUint16(b[2:], flags)
	be.PutUint32(b[8:], id)
	be.PutUint32(b[12:], created)
	be.PutUint32(b[32:], previous)
	be.PutUint32(b[36:], next)
	be.PutUint16(b[42:], 0100444)
	be.PutUint32(b[44:], reference)
	copy(b[48:56], "hlnkhfs+")
	be.PutUint16(b[56:], 0x100)
	setCatalogBSDFlags(b, 2)
	return b
}

func (m *mutation) linkReference(inode *catalogItem) (uint32, error) {
	if !bytes.HasPrefix([]byte(inode.name()), []byte("iNode")) {
		return 0, fmt.Errorf("private inode name: %w", filesystem.ErrCorrupt)
	}
	n, err := strconv.ParseUint(inode.name()[len("iNode"):], 10, 32)
	if err != nil || n == 0 {
		return 0, bad("hard link inode reference")
	}
	return uint32(n), nil
}
