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
// Modified 2026-10-11: bounded offline adaptation of cat_create, cat_rename,
// cat_delete, cat_acquire_cnid, hfs_makenode and hfs_unlink. Unpublished copies
// replace vnodes, credentials, orphan queues and live journal transactions.
// Source revision and hashes: docs/sources.json. License: LICENSES/APSL-2.0.txt.
package hfsplus

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"sort"
	"strings"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/mode"
	"github.com/deploymenttheory/go-apfs-v3/internal/names"
)

type catalogItem struct{ key, value []byte }

func (r *catalogItem) id() uint32               { return be.Uint32(r.value[8:]) }
func (r *catalogItem) parent() uint32           { return be.Uint32(r.key[2:]) }
func (r *catalogItem) directory() bool          { return be.Uint16(r.value) == 1 }
func (r *catalogItem) name() string             { n, _ := unicodeName(r.key[6:]); return n }
func (m *mutation) catalogName(s string) string { return names.HFSStored(s, m.v.CaseSensitive) }

// loadCatalog pairs every record with its thread and verifies the complete
// parent graph. The bounded index owns catalog metadata, never file contents.
func (m *mutation) loadCatalog() error {
	m.catalog = map[uint32]*catalogItem{}
	m.children = map[uint32]map[string]*catalogItem{}
	m.reservedIDs = map[uint32]bool{}
	threads := map[uint32][]byte{}
	err := m.v.catalog.visitLeaves(m.ctx, func(_ uint32, _ []byte, records []treeRecord) error {
		for _, r := range records {
			if len(m.catalog)+len(threads) >= 1<<20 {
				return filesystem.ErrLimit
			}
			kind := be.Uint16(r.value)
			if kind == 3 || kind == 4 {
				id := be.Uint32(r.key[2:])
				if len(r.key) != 8 || be.Uint16(r.key[6:]) != 0 || len(r.value) < 10 || threads[id] != nil {
					return bad("catalog thread identity")
				}
				threads[id] = bytes.Clone(r.value)
				continue
			}
			item := &catalogItem{bytes.Clone(r.key), bytes.Clone(r.value)}
			id, parent := item.id(), item.parent()
			if m.catalog[id] != nil {
				return bad("duplicate catalog identity")
			}
			m.catalog[id] = item
			if m.children[parent] == nil {
				m.children[parent] = map[string]*catalogItem{}
			}
			key := m.catalogName(item.name())
			if m.children[parent][key] != nil {
				return bad("duplicate catalog name")
			}
			m.children[parent][key] = item
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(threads) != len(m.catalog) {
		return bad("catalog thread count")
	}
	root := m.catalog[2]
	if root == nil || !root.directory() || root.parent() != 1 {
		return bad("catalog root")
	}
	var files, directories uint32
	for id, r := range m.catalog {
		if err := m.ctx.Err(); err != nil {
			return err
		}
		if r.directory() {
			if id != 2 {
				directories++
			}
		} else {
			files++
		}
		thread := threads[id]
		if len(thread) < 10 || be.Uint16(thread) != be.Uint16(r.value)+2 || be.Uint32(thread[4:]) != r.parent() || !bytes.Equal(thread[8:], r.key[6:]) {
			return bad("catalog thread disagreement")
		}
		if id != 2 {
			parent := m.catalog[r.parent()]
			if parent == nil || !parent.directory() {
				return bad("catalog parent")
			}
		}
		if r.directory() {
			var folders uint32
			for _, child := range m.children[id] {
				if child.directory() {
					folders++
				}
			}
			if be.Uint32(r.value[4:]) != uint32(len(m.children[id])) || (be.Uint16(r.value[2:])&0x10 != 0 && be.Uint32(r.value[84:]) != folders) {
				return bad("catalog folder counts")
			}
		}
		cursor := id
		for depth := 0; cursor != 2; depth++ {
			if depth >= 256 {
				return filesystem.ErrLimit
			}
			parent := m.catalog[cursor]
			if parent == nil || parent.parent() == cursor {
				return bad("catalog parent cycle")
			}
			cursor = parent.parent()
		}
		m.reservedIDs[id] = true
	}
	if files != be.Uint32(m.header[32:]) || directories != be.Uint32(m.header[36:]) {
		return bad("volume catalog counts")
	}
	if t := m.trees[8]; t != nil {
		base := &tree{fork: t.fork, root: be.Uint32(t.header[16:]), total: t.total, nodeSize: t.nodeSize, idOffset: 4}
		if err = base.visitLeaves(m.ctx, func(_ uint32, _ []byte, records []treeRecord) error {
			for _, r := range records {
				m.reservedIDs[be.Uint32(r.key[4:])] = true
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return m.validateLinks()
}

func (m *mutation) logical(r *catalogItem) (*catalogItem, error) {
	b, err := m.v.resolveLink(m.ctx, r.value)
	if err != nil {
		return nil, err
	}
	inode := m.catalog[be.Uint32(b[8:])]
	if inode == nil {
		return nil, bad("catalog inode")
	}
	return inode, nil
}

func (m *mutation) validateLinks() error {
	aliases := map[uint32]map[uint32]*catalogItem{}
	for _, r := range m.catalog {
		if r.directory() {
			continue
		}
		inode, err := m.logical(r)
		if err != nil {
			return err
		}
		if inode.id() == r.id() {
			continue
		}
		if aliases[inode.id()] == nil {
			aliases[inode.id()] = map[uint32]*catalogItem{}
		}
		aliases[inode.id()][r.id()] = r
	}
	for id, links := range aliases {
		inode := m.catalog[id]
		if be.Uint32(inode.value[44:]) != uint32(len(links)) {
			return bad("hard link count")
		}
		if be.Uint16(inode.value[2:])&0x20 == 0 {
			for _, r := range links {
				if be.Uint16(r.value[2:])&0x20 != 0 {
					return bad("mixed hard link chain")
				}
			}
			continue
		}
		seen := map[uint32]bool{}
		prev, cursor := uint32(0), be.Uint32(inode.value[4:])
		for cursor != 0 {
			r := links[cursor]
			if r == nil || seen[cursor] || be.Uint16(r.value[2:])&0x20 == 0 || be.Uint32(r.value[32:]) != prev {
				return bad("hard link chain")
			}
			seen[cursor] = true
			prev, cursor = cursor, be.Uint32(r.value[36:])
		}
		if len(seen) != len(links) {
			return bad("unreachable hard link alias")
		}
	}
	return nil
}

func catalogPath(path string) ([]string, error) {
	if path == "" || len(path) > 4096 || strings.ContainsRune(path, '\x00') {
		return nil, fs.ErrInvalid
	}
	var parts []string
	for _, s := range strings.Split(path, "/") {
		if s == "" {
			continue
		}
		if s == "." || s == ".." {
			return nil, fs.ErrInvalid
		}
		if _, err := names.Stored(s, "HFS+"); err != nil {
			return nil, err
		}
		parts = append(parts, s)
	}
	if len(parts) > 256 {
		return nil, filesystem.ErrLimit
	}
	return parts, nil
}
func (m *mutation) lookupParts(parts []string) (*catalogItem, error) {
	r := m.catalog[2]
	for _, p := range parts {
		if !r.directory() {
			return nil, fmt.Errorf("path parent is not a directory: %w", fs.ErrInvalid)
		}
		r = m.children[r.id()][names.HFS(p, m.v.CaseSensitive)]
		if r == nil {
			return nil, fs.ErrNotExist
		}
	}
	return r, nil
}
func (m *mutation) lookup(path string) (*catalogItem, error) {
	p, err := catalogPath(path)
	if err != nil {
		return nil, err
	}
	return m.lookupParts(p)
}
func (m *mutation) destination(path string) (*catalogItem, string, error) {
	parts, err := catalogPath(path)
	if err != nil {
		return nil, "", err
	}
	if len(parts) == 0 {
		return nil, "", fs.ErrInvalid
	}
	parent, err := m.lookupParts(parts[:len(parts)-1])
	if err != nil {
		return nil, "", err
	}
	if !parent.directory() {
		return nil, "", fs.ErrInvalid
	}
	name, err := names.Stored(parts[len(parts)-1], "HFS+")
	return parent, name, err
}
func (m *mutation) protected(r *catalogItem, root bool) error {
	return m.protectedMetadata(r, root, false)
}
func (m *mutation) protectedMetadata(r *catalogItem, root, flagsChange bool) error {
	if r == nil {
		return fs.ErrNotExist
	}
	if root && r.id() == 2 {
		return fmt.Errorf("volume root cannot be changed: %w", filesystem.ErrUnsupported)
	}
	for cursor, depth := r, 0; cursor.id() != 2; depth++ {
		if depth >= 256 {
			return filesystem.ErrLimit
		}
		if cursor.id() == m.v.privateID || (cursor.parent() == 2 && cursor.name() == directoryLinks) || (m.journal != nil && (uint64(cursor.id()) == m.journal.infoID || uint64(cursor.id()) == m.journal.fileID)) {
			return fmt.Errorf("filesystem-owned catalog record: %w", filesystem.ErrUnsupported)
		}
		cursor = m.catalog[cursor.parent()]
	}
	record := r.value
	if !r.directory() {
		inode, err := m.logical(r)
		if err != nil {
			return err
		}
		record = inode.value
	}
	flags := uint32(record[40])<<16 | uint32(record[41])
	mask := uint32(0x00060006 | 0x40000000)
	if flagsChange {
		mask &^= 6
	}
	if flags&mask != 0 || be.Uint16(record[2:])&1 != 0 {
		return fmt.Errorf("locked, immutable, append-only or dataless catalog record: %w", filesystem.ErrUnsupported)
	}
	return nil
}
func (m *mutation) writableParent(r *catalogItem) error {
	if err := m.protected(r, false); err != nil {
		return err
	}
	if !r.directory() {
		return fs.ErrInvalid
	}
	if be.Uint16(r.value[2:])&8 != 0 || be.Uint16(r.value[42:])&06000 != 0 {
		return fmt.Errorf("directory ACL or set-ID inheritance requires credential policy: %w", filesystem.ErrUnsupported)
	}
	return nil
}
func catalogThread(r *catalogItem) []byte {
	b := make([]byte, 8+len(r.key)-6)
	be.PutUint16(b, be.Uint16(r.value)+2)
	be.PutUint32(b[4:], r.parent())
	copy(b[8:], r.key[6:])
	return b
}
func (m *mutation) parentChanged(parent uint32, count int, directory bool, stamp uint32) error {
	r := m.catalog[parent]
	if r == nil || !r.directory() {
		return bad("catalog parent mutation")
	}
	b := bytes.Clone(r.value)
	adjust := func(off int, delta int) error {
		n := int64(be.Uint32(b[off:])) + int64(delta)
		if n < 0 || n > math.MaxUint32 {
			return bad("catalog count overflow")
		}
		be.PutUint32(b[off:], uint32(n))
		return nil
	}
	if err := adjust(4, count); err != nil {
		return err
	}
	if directory && be.Uint16(b[2:])&0x10 != 0 {
		if err := adjust(84, count); err != nil {
			return err
		}
	}
	be.PutUint32(b[16:], stamp)
	be.PutUint32(b[20:], stamp)
	generation := be.Uint32(b[76:])
	if generation == 0 {
		generation = 1
	}
	generation++
	if generation == 0 {
		generation = 1
	}
	be.PutUint32(b[76:], generation)
	return m.patchCatalog(parent, b)
}
func (m *mutation) volumeCount(directory bool, delta int) error {
	off := 32
	if directory {
		off = 36
	}
	n := int64(be.Uint32(m.header[off:])) + int64(delta)
	if n < 0 || n > math.MaxUint32 {
		return bad("volume catalog count overflow")
	}
	be.PutUint32(m.header[off:], uint32(n))
	return nil
}
func (m *mutation) allocateCNID() (uint32, error) {
	id := be.Uint32(m.header[64:])
	if id < 16 {
		return 0, bad("next catalog node ID")
	}
	for checked := 0; checked <= len(m.reservedIDs); checked++ {
		if id == math.MaxUint32 {
			return 0, fmt.Errorf("catalog ID wraparound is unqualified: %w", filesystem.ErrUnsupported)
		}
		be.PutUint32(m.header[64:], id+1)
		if !m.reservedIDs[id] {
			m.reservedIDs[id] = true
			return id, nil
		}
		id++
	}
	return 0, filesystem.ErrLimit
}
func (m *mutation) createCatalog(parent *catalogItem, name string, directory bool, permission string, stamp uint32) (*catalogItem, error) {
	if err := m.writableParent(parent); err != nil {
		return nil, err
	}
	key := catalogKey(parent.id(), name)
	if m.children[parent.id()][m.catalogName(storedName(name))] != nil {
		return nil, fs.ErrExist
	}
	id, err := m.allocateCNID()
	if err != nil {
		return nil, err
	}
	size, kind, flags, perm := 248, uint16(2), uint16(0x82), uint32(0100644)
	if directory {
		size, kind, flags, perm = 88, 1, 0x80, 0040755
		if m.v.Format == "HFSX" {
			flags |= 0x10
		}
	}
	if permission != "" {
		p, e := mode.Parse(permission, 022)
		if e != nil {
			return nil, e
		}
		perm = p.Apply(perm)
	}
	if perm&06000 != 0 {
		return nil, fmt.Errorf("set-ID creation requires credential policy: %w", filesystem.ErrUnsupported)
	}
	b := make([]byte, size)
	be.PutUint16(b, kind)
	be.PutUint16(b[2:], flags)
	be.PutUint32(b[8:], id)
	for _, off := range []int{12, 16, 20, 24} {
		be.PutUint32(b[off:], stamp)
	}
	copy(b[32:40], parent.value[32:40])
	be.PutUint16(b[42:], uint16(perm))
	be.PutUint32(b[44:], 1)
	be.PutUint32(b[68:], stamp-2082844800)
	if !directory {
		be.PutUint32(b[76:], 1)
	}
	r := &catalogItem{key, b}
	t := m.trees[4]
	if err = t.set(catalogKey(id, ""), catalogThread(r), false); err != nil {
		return nil, err
	}
	if err = t.set(key, b, false); err != nil {
		return nil, err
	}
	m.catalog[id] = r
	if m.children[parent.id()] == nil {
		m.children[parent.id()] = map[string]*catalogItem{}
	}
	m.children[parent.id()][m.catalogName(r.name())] = r
	if err = m.parentChanged(parent.id(), 1, directory, stamp); err != nil {
		return nil, err
	}
	if err = m.volumeCount(directory, 1); err != nil {
		return nil, err
	}
	return r, nil
}
func (m *mutation) makeDirectory(c Change, stamp uint32) (uint32, error) {
	parts, err := catalogPath(c.Path)
	if err != nil {
		return 0, err
	}
	if len(parts) == 0 {
		if c.Parents {
			return 0, nil
		}
		return 0, fs.ErrExist
	}
	parent := m.catalog[2]
	var changed uint32
	for i, p := range parts {
		name, e := names.Stored(p, "HFS+")
		if e != nil {
			return 0, e
		}
		next := m.children[parent.id()][names.HFS(p, m.v.CaseSensitive)]
		if next != nil {
			if !next.directory() {
				return 0, fs.ErrExist
			}
			if i == len(parts)-1 && !c.Parents {
				return 0, fs.ErrExist
			}
		} else {
			if i < len(parts)-1 && !c.Parents {
				return 0, fs.ErrNotExist
			}
			permission := ""
			if i == len(parts)-1 {
				permission = c.Mode
			}
			next, e = m.createCatalog(parent, name, true, permission, stamp)
			if e != nil {
				return 0, e
			}
			changed = next.id()
		}
		parent = next
	}
	return changed, nil
}
func (m *mutation) eraseCatalog(r *catalogItem, stamp uint32) error {
	t := m.trees[4]
	if err := t.set(r.key, nil, true); err != nil {
		return err
	}
	if err := t.set(catalogKey(r.id(), ""), nil, true); err != nil {
		return err
	}
	delete(m.catalog, r.id())
	delete(m.children[r.parent()], m.catalogName(r.name()))
	if err := m.parentChanged(r.parent(), -1, r.directory(), stamp); err != nil {
		return err
	}
	return m.volumeCount(r.directory(), -1)
}
func (m *mutation) freeAttributes(id uint32) error {
	t := m.trees[8]
	if t == nil {
		return nil
	}
	base := &tree{fork: t.fork, root: be.Uint32(t.header[16:]), total: t.total, nodeSize: t.nodeSize, idOffset: 4}
	var keys [][]byte
	descriptors := map[string][]byte{}
	continuations := map[string]map[uint32][]byte{}
	if err := base.records(m.ctx, id, func(r treeRecord) error {
		keys = append(keys, bytes.Clone(r.key))
		name := string(r.key[12:])
		start := be.Uint32(r.key[8:])
		if be.Uint32(r.value) == 0x20 {
			descriptors[name] = bytes.Clone(r.value[8:])
		}
		if be.Uint32(r.value) == 0x30 {
			if continuations[name] == nil {
				continuations[name] = map[uint32][]byte{}
			}
			continuations[name][start] = bytes.Clone(r.value[8:])
		}
		return nil
	}); err != nil {
		return err
	}
	for name, descriptor := range descriptors {
		f, e := resolveFork(m.ctx, m.disk, m.v.BlockSize, m.v.BlockCount, descriptor, func() (map[uint32][]byte, error) { return continuations[name], nil })
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
		if err := t.set(key, nil, true); err != nil {
			return err
		}
	}
	return nil
}
func (m *mutation) freeFile(r *catalogItem, stamp uint32) error {
	if !r.directory() {
		b := bytes.Clone(r.value)
		for _, kind := range []byte{0, 255} {
			off := 88
			if kind == 255 {
				off = 168
			}
			if err := m.replaceFork(r.id(), kind, b[off:off+80], emptySource{}); err != nil {
				return err
			}
		}
	}
	if err := m.freeAttributes(r.id()); err != nil {
		return err
	}
	return m.eraseCatalog(r, stamp)
}
func (m *mutation) unlinkFile(r *catalogItem, stamp uint32) error {
	inode, err := m.logical(r)
	if err != nil {
		return err
	}
	if inode.id() == r.id() {
		return m.freeFile(r, stamp)
	}
	b := bytes.Clone(inode.value)
	count := be.Uint32(b[44:])
	if count == 0 {
		return bad("hard link count underflow")
	}
	if count > 1 && be.Uint16(b[2:])&0x20 != 0 {
		prev, next := be.Uint32(r.value[32:]), be.Uint32(r.value[36:])
		if be.Uint32(b[4:]) == r.id() {
			be.PutUint32(b[4:], next)
		}
		for _, side := range []struct {
			id     uint32
			offset int
			value  uint32
		}{{prev, 36, next}, {next, 32, prev}} {
			if side.id == 0 {
				continue
			}
			sibling := m.catalog[side.id]
			if sibling == nil {
				return bad("hard link sibling")
			}
			value := bytes.Clone(sibling.value)
			be.PutUint32(value[side.offset:], side.value)
			if err = m.patchCatalog(side.id, value); err != nil {
				return err
			}
		}
	}
	if err = m.freeFile(r, stamp); err != nil {
		return err
	}
	if count == 1 {
		return m.freeFile(inode, stamp)
	}
	be.PutUint32(b[44:], count-1)
	be.PutUint32(b[20:], stamp)
	return m.patchCatalog(inode.id(), b)
}
func (m *mutation) removeCatalog(r *catalogItem, recursive bool, stamp uint32) error {
	if err := m.protected(r, true); err != nil {
		return err
	}
	inode, err := m.logical(r)
	if err != nil {
		return err
	}
	// The hidden inode is protected from direct namespace access, but its flags
	// still govern operations through each public alias.
	flags := uint32(inode.value[40])<<16 | uint32(inode.value[41])
	if flags&(0x00060006|0x40000000) != 0 || be.Uint16(inode.value[2:])&1 != 0 {
		return filesystem.ErrUnsupported
	}
	if err = m.writableParent(m.catalog[r.parent()]); err != nil {
		return err
	}
	if r.directory() {
		if !recursive {
			return fmt.Errorf("directory removal requires -r: %w", fs.ErrInvalid)
		}
		var children []*catalogItem
		for _, child := range m.children[r.id()] {
			children = append(children, child)
		}
		sort.Slice(children, func(i, j int) bool { return bytes.Compare(children[i].key, children[j].key) < 0 })
		for _, child := range children {
			if err = m.removeCatalog(child, true, stamp); err != nil {
				return err
			}
		}
		return m.freeFile(r, stamp)
	}
	return m.unlinkFile(r, stamp)
}
func (m *mutation) moveCatalog(c Change, stamp uint32) (uint32, error) {
	r, err := m.lookup(c.Path)
	if err != nil {
		return 0, err
	}
	if err = m.protected(r, true); err != nil {
		return 0, err
	}
	parent, name, err := m.destination(c.Destination)
	if err != nil {
		return 0, err
	}
	existing := m.children[parent.id()][names.HFS(name, m.v.CaseSensitive)]
	// Ordinary mv into an existing directory retains the source basename.
	if existing != nil && existing.directory() && existing.id() != r.id() {
		parent = existing
		name = strings.ReplaceAll(strings.ReplaceAll(r.name(), "/", ":"), "\x00", "\u2400")
		existing = m.children[parent.id()][m.catalogName(r.name())]
	}
	if err = m.writableParent(parent); err != nil {
		return 0, err
	}
	if err = m.writableParent(m.catalog[r.parent()]); err != nil {
		return 0, err
	}
	for cursor := parent; cursor.id() != 2; cursor = m.catalog[cursor.parent()] {
		if cursor.id() == r.id() {
			return 0, fs.ErrInvalid
		}
	}
	if parent.id() == r.id() {
		return 0, fs.ErrInvalid
	}
	key := catalogKey(parent.id(), name)
	if bytes.Equal(key, r.key) {
		return 0, nil
	}
	if existing != nil && existing.id() != r.id() {
		if c.NoClobber {
			return 0, fs.ErrExist
		}
		if existing.directory() != r.directory() {
			return 0, fs.ErrInvalid
		}
		if existing.directory() && len(m.children[existing.id()]) != 0 {
			return 0, fmt.Errorf("destination directory is not empty: %w", syscall.ENOTEMPTY)
		}
		sourceInode, e := m.logical(r)
		if e != nil {
			return 0, e
		}
		targetInode, e := m.logical(existing)
		if e != nil {
			return 0, e
		}
		if sourceInode.id() == targetInode.id() {
			return 0, nil
		}
		if err = m.removeCatalog(existing, existing.directory(), stamp); err != nil {
			return 0, err
		}
	}
	oldParent, oldKey, oldName := r.parent(), bytes.Clone(r.key), r.name()
	t := m.trees[4]
	// A case-only spelling change compares equal in HFS+. Remove that key before
	// inserting the replacement, as cat_rename does after BTInsert's btExists.
	same := t.compare(oldKey, key) == 0
	if same {
		if err = t.set(oldKey, nil, true); err != nil {
			return 0, err
		}
	}
	if err = t.set(key, r.value, false); err != nil {
		return 0, err
	}
	if !same {
		if err = t.set(oldKey, nil, true); err != nil {
			return 0, err
		}
	}
	delete(m.children[oldParent], m.catalogName(oldName))
	r.key = key
	if m.children[parent.id()] == nil {
		m.children[parent.id()] = map[string]*catalogItem{}
	}
	m.children[parent.id()][m.catalogName(r.name())] = r
	if err = t.set(catalogKey(r.id(), ""), catalogThread(r), false); err != nil {
		return 0, err
	}
	if oldParent != parent.id() {
		if err = m.parentChanged(oldParent, -1, r.directory(), stamp); err != nil {
			return 0, err
		}
		if err = m.parentChanged(parent.id(), 1, r.directory(), stamp); err != nil {
			return 0, err
		}
	}
	inode, err := m.logical(r)
	if err != nil {
		return 0, err
	}
	b := bytes.Clone(inode.value)
	be.PutUint32(b[20:], stamp)
	if oldParent != parent.id() || be.Uint16(b[2:])&0x80 == 0 {
		if inode.directory() || be.Uint16(b[42:])&0170000 == 0100000 {
			be.PutUint16(b[2:], be.Uint16(b[2:])|0x80)
			be.PutUint32(b[68:], stamp-2082844800)
		}
	}
	if err = m.patchCatalog(inode.id(), b); err != nil {
		return 0, err
	}
	return inode.id(), nil
}
func (m *mutation) applyChange(c Change, stamp uint32) (uint32, error) {
	if c.Path == "" {
		return 0, fs.ErrInvalid
	}
	op := c.Operation
	if op == "" {
		op = "cp"
		if c.Data == nil && c.Mode != "" {
			op = "chmod"
		}
	}
	if op == "chown" || op == "chflags" || op == "touch" || op == "xattr" || op == "chmod" {
		c.Operation = op
		return m.editMetadata(c, stamp)
	}
	if c.Metadata != nil || c.Flags != "" || c.Attribute != "" || c.AttributeMode != "" || c.DeleteAttribute || c.NoCreate || c.NoFollow || c.Reference != "" || c.Access || c.Modify {
		return 0, fs.ErrInvalid
	}
	if (op != "mv" && c.Destination != "") || (op != "mkdir" && c.Parents) || (op != "rm" && (c.Recursive || c.Force)) || ((op != "cp" && op != "mv") && c.NoClobber) || (op != "cp" && (c.Name != "" || c.ResourceFork || c.Data != nil)) || ((op == "rm" || op == "mv") && c.Mode != "") {
		return 0, fs.ErrInvalid
	}
	switch op {
	case "mkdir":
		return m.makeDirectory(c, stamp)
	case "mv":
		return m.moveCatalog(c, stamp)
	case "rm":
		r, err := m.lookup(c.Path)
		if errors.Is(err, fs.ErrNotExist) && c.Force {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
		id := r.id()
		return id, m.removeCatalog(r, c.Recursive, stamp)
	case "cp", "chmod":
		if op == "chmod" && c.Mode == "" {
			return 0, fs.ErrInvalid
		}
		if op == "cp" && (c.Data == nil || c.Data.Size() < 0) {
			return 0, fs.ErrInvalid
		}
		r, err := m.lookup(c.Path)
		if err == nil && op == "cp" && r.directory() && c.Name != "" && !c.ResourceFork {
			if _, e := names.Stored(c.Name, "HFS+"); e != nil {
				return 0, e
			}
			c.Path = strings.TrimRight(c.Path, "/") + "/" + c.Name
			r, err = m.lookup(c.Path)
		}
		if errors.Is(err, fs.ErrNotExist) && op == "cp" && !c.ResourceFork {
			parent, name, e := m.destination(c.Path)
			if e != nil {
				return 0, e
			}
			r, err = m.createCatalog(parent, name, false, c.Mode, stamp)
		} else if err == nil && op == "cp" && c.NoClobber {
			return 0, fs.ErrExist
		}
		if err != nil {
			return 0, err
		}
		if err = m.protected(r, true); err != nil {
			return 0, err
		}
		inode, e := m.logical(r)
		if e != nil {
			return 0, e
		}
		if e = m.validateFile(c, uint64(inode.id())); e != nil {
			return 0, e
		}
		return m.modifyFile(c, uint64(inode.id()), stamp)
	default:
		return 0, filesystem.ErrUnsupported
	}
}
