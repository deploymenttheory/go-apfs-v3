/*
 * Copyright (c) 2000-2015 Apple Inc. All rights reserved.
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
// Copyright (c) 1992-1999 Apple Inc. (original B-tree module).
// Modified 2026-10-11: Go adaptation of SearchTree, SplitLeft, DeleteTree,
// CollapseTree, AllocateNode and FreeNode. Byte slices and unpublished storage
// replace buffer-cache blocks, tree path tables, locks and journal callbacks.
// Splits use byte-balanced records without the optional sibling redistribution.
// Source revision and exact upstream hashes: docs/sources.json.
package hfsplus

import (
	"bytes"
	"cmp"
	"fmt"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type nodeMap struct {
	node       uint32
	start, end int
	first      uint32
	data       []byte
}
type mutableTree struct {
	m              *mutation
	id             uint32
	descriptor     int
	fork           *fork
	header         []byte
	nodeSize       uint16
	total, mapBits uint32
	maps           []nodeMap
	compare        func([]byte, []byte) int
}
type treeChild struct {
	key  []byte
	node uint32
}

func extentCompare(a, b []byte) int {
	if n := cmp.Compare(be.Uint32(a[4:]), be.Uint32(b[4:])); n != 0 {
		return n
	}
	if n := cmp.Compare(a[2], b[2]); n != 0 {
		return n
	}
	return cmp.Compare(be.Uint32(a[8:]), be.Uint32(b[8:]))
}
func attributeCompare(a, b []byte) int {
	if n := cmp.Compare(be.Uint32(a[4:]), be.Uint32(b[4:])); n != 0 {
		return n
	}
	// HFS attributes use binary UTF-16 name order before startBlock, unlike
	// catalog names. Comparing bytes preserves unsigned UTF-16 ordering.
	if n := bytes.Compare(a[14:], b[14:]); n != 0 {
		return n
	}
	return cmp.Compare(be.Uint32(a[8:]), be.Uint32(b[8:]))
}

func recordBounds(b []byte, index int) (int, int, error) {
	n := int(be.Uint16(b[10:]))
	if n < 1 || n > (len(b)-14)/2 || index < 0 || index >= n {
		return 0, 0, bad("map record count")
	}
	start, end := int(be.Uint16(b[len(b)-2*(index+1):])), int(be.Uint16(b[len(b)-2*(index+2):]))
	if start < 14 || start > end || end > len(b)-2*(n+1) {
		return 0, 0, bad("map record bounds")
	}
	return start, end, nil
}

func (m *mutation) mutableTree(id uint32, descriptor int) (*mutableTree, error) {
	if t := m.trees[id]; t != nil {
		return t, nil
	}
	f, err := m.v.fileFork(m.ctx, id, 0, m.header[descriptor:descriptor+80])
	if err != nil {
		return nil, err
	}
	base, err := openTree(f, 4)
	if err != nil {
		return nil, err
	}
	if base.total > 1<<18 {
		return nil, filesystem.ErrLimit
	}
	h := make([]byte, base.nodeSize)
	if err = f.read(h, 0); err != nil {
		return nil, err
	}
	if be.Uint16(h[10:]) != 3 || be.Uint16(h[14:]) > 16 {
		return nil, bad("mutable tree header")
	}
	start, end, err := recordBounds(h, 0)
	if err != nil || start != 14 || end-start != 106 {
		return nil, bad("mutable tree header record")
	}
	t := &mutableTree{m: m, id: id, descriptor: descriptor, fork: f, header: h, nodeSize: base.nodeSize, total: base.total, compare: extentCompare}
	if id == 8 {
		t.compare = attributeCompare
	}
	if id != 3 && id != 8 {
		return nil, filesystem.ErrUnsupported
	}
	if be.Uint32(h[52:])&2 == 0 || (id == 8 && be.Uint32(h[52:])&4 == 0) || (id == 3 && be.Uint16(h[34:]) != 10) {
		return nil, fmt.Errorf("HFS mutable tree key profile: %w", filesystem.ErrUnsupported)
	}
	seen := map[uint32]bool{0: true}
	node, b, index := uint32(0), h, 2
	for {
		s, e, er := recordBounds(b, index)
		if er != nil || s == e {
			return nil, bad("empty tree map")
		}
		t.maps = append(t.maps, nodeMap{node, s, e, t.mapBits, b})
		if uint64(t.mapBits)+uint64(e-s)*8 > 1<<24 {
			return nil, filesystem.ErrLimit
		}
		t.mapBits += uint32(e-s) * 8
		next := be.Uint32(b)
		if next == 0 {
			break
		}
		if next >= t.total || seen[next] {
			return nil, bad("tree map cycle")
		}
		seen[next] = true
		node = next
		b = make([]byte, t.nodeSize)
		if er = f.read(b, uint64(node)*uint64(t.nodeSize)); er != nil {
			return nil, er
		}
		if b[8] != 2 || b[9] != 0 || be.Uint16(b[10:]) != 1 {
			return nil, bad("tree map node")
		}
		index = 0
	}
	if t.mapBits < t.total {
		return nil, bad("short tree node map")
	}
	var free uint32
	for i := uint32(0); i < t.total; i++ {
		if !t.used(i) {
			free++
		}
	}
	if free != be.Uint32(h[40:]) {
		return nil, bad("tree free node accounting")
	}
	for id := range seen {
		if !t.used(id) {
			return nil, bad("unallocated tree map")
		}
	}
	if err = t.validate(seen); err != nil {
		return nil, err
	}
	m.trees[id] = t
	return t, nil
}

func (t *mutableTree) used(node uint32) bool {
	for _, m := range t.maps {
		if node >= m.first && node-m.first < uint32(m.end-m.start)*8 {
			return bitmapBit(m.data[m.start:m.end], node-m.first)
		}
	}
	return false
}
func (t *mutableTree) mark(node uint32, used bool) error {
	if node >= t.total || t.used(node) == used {
		return bad("tree node double allocation or free")
	}
	for _, m := range t.maps {
		if node < m.first || node-m.first >= uint32(m.end-m.start)*8 {
			continue
		}
		setBitmapBit(m.data[m.start:m.end], node-m.first, used)
		free := be.Uint32(t.header[40:])
		if used {
			free--
		} else {
			free++
		}
		be.PutUint32(t.header[40:], free)
		return nil
	}
	return bad("tree node outside map")
}
func (t *mutableTree) allocate() (uint32, error) {
	for {
		for i := uint32(1); i < t.total; i++ {
			if !t.used(i) {
				return i, t.mark(i, true)
			}
		}
		if err := t.m.growTree(t); err != nil {
			return 0, err
		}
	}
}

func (t *mutableTree) keyValid(key []byte) bool {
	if t.id == 3 {
		return len(key) == 12 && be.Uint16(key) == 10 && key[3] == 0 && (key[2] == 0 || key[2] == 255)
	}
	if len(key) < 14 || int(be.Uint16(key))+2 != len(key) || key[2] != 0 || key[3] != 0 {
		return false
	}
	_, err := unicodeName(key[12:])
	return err == nil
}

func (t *mutableTree) node(id uint32, height int) ([]byte, []treeRecord, error) {
	if err := t.m.ctx.Err(); err != nil {
		return nil, nil, err
	}
	if id == 0 || id >= t.total || !t.used(id) {
		return nil, nil, bad("unallocated tree child")
	}
	b := make([]byte, t.nodeSize)
	if err := t.fork.read(b, uint64(id)*uint64(t.nodeSize)); err != nil {
		return nil, nil, err
	}
	if int(b[9]) != height || height < 1 || height > 16 || (height == 1 && b[8] != 255) || (height > 1 && b[8] != 0) {
		return nil, nil, bad("mutable tree height or kind")
	}
	r, err := nodeRecords(b, 4)
	if err != nil {
		return nil, nil, err
	}
	for i, record := range r {
		if !t.keyValid(record.key) || (i > 0 && t.compare(r[i-1].key, record.key) >= 0) || (height > 1 && len(record.value) != 4) {
			return nil, nil, bad("mutable tree record order or key")
		}
		if height == 1 && t.id == 3 && len(record.value) != 64 {
			return nil, nil, bad("extent leaf value length")
		}
	}
	return b, r, nil
}

func (t *mutableTree) validate(seen map[uint32]bool) error {
	root, depth := be.Uint32(t.header[16:]), int(be.Uint16(t.header[14:]))
	levels := map[int][]uint32{}
	nodes := map[uint32][2]uint32{}
	var records uint32
	var visit func(uint32, int) ([]byte, error)
	visit = func(id uint32, height int) ([]byte, error) {
		if seen[id] {
			return nil, bad("mutable tree cycle")
		}
		seen[id] = true
		b, r, err := t.node(id, height)
		if err != nil {
			return nil, err
		}
		levels[height] = append(levels[height], id)
		nodes[id] = [2]uint32{be.Uint32(b[4:]), be.Uint32(b)}
		if height == 1 {
			records += uint32(len(r))
		} else {
			for _, item := range r {
				key, er := visit(be.Uint32(item.value), height-1)
				if er != nil {
					return nil, er
				}
				if t.compare(key, item.key) != 0 {
					return nil, bad("mutable tree index boundary")
				}
			}
		}
		return r[0].key, nil
	}
	if root != 0 {
		if _, err := visit(root, depth); err != nil {
			return err
		}
	} else if depth != 0 {
		return bad("empty tree depth")
	}
	for _, ids := range levels {
		for i, id := range ids {
			var before, after uint32
			if i > 0 {
				before = ids[i-1]
			}
			if i+1 < len(ids) {
				after = ids[i+1]
			}
			if nodes[id] != [2]uint32{before, after} {
				return bad("tree sibling chain")
			}
		}
	}
	var first, last uint32
	if leaves := levels[1]; len(leaves) > 0 {
		first, last = leaves[0], leaves[len(leaves)-1]
	}
	if records != be.Uint32(t.header[20:]) || first != be.Uint32(t.header[24:]) || last != be.Uint32(t.header[28:]) || uint32(len(seen)) != t.total-be.Uint32(t.header[40:]) {
		return bad("tree reachability accounting")
	}
	return nil
}

func (t *mutableTree) flush() error {
	for _, m := range t.maps {
		if err := t.m.writeFork(t.fork, m.data, uint64(m.node)*uint64(t.nodeSize)); err != nil {
			return err
		}
	}
	return nil
}

func recordsFit(records []treeRecord, size int) bool {
	n := 14 + 2*(len(records)+1)
	for _, r := range records {
		n += len(r.key) + len(r.value)
	}
	return n <= size
}

func (t *mutableTree) save(id uint32, b []byte, r []treeRecord) error {
	if !recordsFit(r, len(b)) {
		return filesystem.ErrLimit
	}
	// Existing record slices borrow the original node. Keep it alive while
	// serializing the changed node; clearing it would erase retained records.
	b = bytes.Clone(b)
	clear(b[14:])
	be.PutUint16(b[10:], uint16(len(r)))
	off := 14
	for i, item := range r {
		be.PutUint16(b[len(b)-2*(i+1):], uint16(off))
		copy(b[off:], item.key)
		off += len(item.key)
		copy(b[off:], item.value)
		off += len(item.value)
	}
	be.PutUint16(b[len(b)-2*(len(r)+1):], uint16(off))
	return t.m.writeFork(t.fork, b, uint64(id)*uint64(t.nodeSize))
}

func indexRecord(child treeChild) treeRecord {
	b := make([]byte, 4)
	be.PutUint32(b, child.node)
	return treeRecord{bytes.Clone(child.key), b}
}
func childRecords(children []treeChild) []treeRecord {
	var records []treeRecord
	for _, c := range children {
		records = append(records, indexRecord(c))
	}
	return records
}

// change mirrors InsertLevel/DeleteTree propagation. An emptied node is freed,
// its sibling links are repaired and its parent pointer is removed. A changed
// first key propagates upwards; a split adds a new left sibling and index key.
func (t *mutableTree) change(id uint32, height int, key, value []byte, remove bool) ([]treeChild, bool, error) {
	b, r, err := t.node(id, height)
	if err != nil {
		return nil, false, err
	}
	i := sort.Search(len(r), func(i int) bool { return t.compare(r[i].key, key) >= 0 })
	found := i < len(r) && t.compare(r[i].key, key) == 0
	changed := false
	if height == 1 {
		if remove {
			if !found {
				return nil, false, fmt.Errorf("tree record missing: %w", filesystem.ErrCorrupt)
			}
			r = append(r[:i], r[i+1:]...)
			changed = true
		} else if found {
			r[i] = treeRecord{bytes.Clone(key), bytes.Clone(value)}
		} else {
			r = append(r, treeRecord{})
			copy(r[i+1:], r[i:])
			r[i] = treeRecord{bytes.Clone(key), bytes.Clone(value)}
			changed = true
		}
	} else {
		if !found && i > 0 {
			i--
		}
		if i == len(r) {
			i--
		}
		children, delta, er := t.change(be.Uint32(r[i].value), height-1, key, value, remove)
		if er != nil {
			return nil, false, er
		}
		changed = delta
		r = append(append(append([]treeRecord{}, r[:i]...), childRecords(children)...), r[i+1:]...)
	}
	if len(r) == 0 {
		before, after := be.Uint32(b[4:]), be.Uint32(b)
		if before != 0 {
			if err = t.link(before, height, 0, after); err != nil {
				return nil, false, err
			}
		} else if height == 1 {
			be.PutUint32(t.header[24:], after)
		}
		if after != 0 {
			if err = t.link(after, height, 4, before); err != nil {
				return nil, false, err
			}
		} else if height == 1 {
			be.PutUint32(t.header[28:], before)
		}
		clear(b)
		if err = t.m.writeFork(t.fork, b, uint64(id)*uint64(t.nodeSize)); err != nil {
			return nil, false, err
		}
		return nil, changed, t.mark(id, false)
	}
	if recordsFit(r, len(b)) {
		if err = t.save(id, b, r); err != nil {
			return nil, false, err
		}
		return []treeChild{{bytes.Clone(r[0].key), id}}, changed, nil
	}
	// SplitLeft retains the original node as the right sibling. Select a
	// byte-balanced split at a record boundary, then propagate both minima.
	split := 0
	best := int(^uint(0) >> 1)
	for j := 1; j < len(r); j++ {
		if !recordsFit(r[:j], len(b)) || !recordsFit(r[j:], len(b)) {
			continue
		}
		n := 0
		for _, item := range r[:j] {
			n += len(item.key) + len(item.value) + 2
		}
		other := 0
		for _, item := range r[j:] {
			other += len(item.key) + len(item.value) + 2
		}
		difference := n - other
		if difference < 0 {
			difference = -difference
		}
		if difference < best {
			best = difference
			split = j
		}
	}
	if split == 0 {
		return nil, false, filesystem.ErrLimit
	}
	leftID, err := t.allocate()
	if err != nil {
		return nil, false, err
	}
	left := make([]byte, t.nodeSize)
	copy(left[:14], b[:14])
	before := be.Uint32(b[4:])
	be.PutUint32(left, id)
	be.PutUint32(b[4:], leftID)
	if before != 0 {
		if err = t.link(before, height, 0, leftID); err != nil {
			return nil, false, err
		}
	} else if height == 1 {
		be.PutUint32(t.header[24:], leftID)
	}
	if err = t.save(leftID, left, r[:split]); err != nil {
		return nil, false, err
	}
	if err = t.save(id, b, r[split:]); err != nil {
		return nil, false, err
	}
	return []treeChild{{bytes.Clone(r[0].key), leftID}, {bytes.Clone(r[split].key), id}}, changed, nil
}

func (t *mutableTree) link(id uint32, height, off int, value uint32) error {
	b, _, err := t.node(id, height)
	if err != nil {
		return err
	}
	be.PutUint32(b[off:], value)
	return t.m.writeFork(t.fork, b, uint64(id)*uint64(t.nodeSize))
}

func (t *mutableTree) set(key, value []byte, remove bool) error {
	if !t.keyValid(key) || (!remove && len(value)%2 != 0) {
		return bad("mutation key or value")
	}
	root, depth := be.Uint32(t.header[16:]), int(be.Uint16(t.header[14:]))
	if root == 0 {
		if remove {
			return bad("delete from empty tree")
		}
		id, err := t.allocate()
		if err != nil {
			return err
		}
		b := make([]byte, t.nodeSize)
		b[8], b[9] = 255, 1
		if err = t.save(id, b, []treeRecord{{key, value}}); err != nil {
			return err
		}
		be.PutUint16(t.header[14:], 1)
		be.PutUint32(t.header[16:], id)
		be.PutUint32(t.header[20:], 1)
		be.PutUint32(t.header[24:], id)
		be.PutUint32(t.header[28:], id)
	} else {
		children, delta, err := t.change(root, depth, key, value, remove)
		if err != nil {
			return err
		}
		if delta {
			count := be.Uint32(t.header[20:])
			if remove {
				count--
			} else {
				count++
			}
			be.PutUint32(t.header[20:], count)
		}
		switch len(children) {
		case 0:
			be.PutUint16(t.header[14:], 0)
			be.PutUint32(t.header[16:], 0)
		case 1:
			be.PutUint32(t.header[16:], children[0].node)
		case 2:
			if depth >= 16 {
				return filesystem.ErrLimit
			}
			id, er := t.allocate()
			if er != nil {
				return er
			}
			b := make([]byte, t.nodeSize)
			b[9] = byte(depth + 1)
			if er = t.save(id, b, childRecords(children)); er != nil {
				return er
			}
			be.PutUint16(t.header[14:], uint16(depth+1))
			be.PutUint32(t.header[16:], id)
		}
		// Collapse a one-pointer index root, repeatedly if deletion removed
		// more than one level. A one-record leaf remains a leaf.
		for be.Uint16(t.header[14:]) > 1 {
			id := be.Uint32(t.header[16:])
			b, r, er := t.node(id, int(be.Uint16(t.header[14:])))
			if er != nil {
				return er
			}
			if len(r) != 1 {
				break
			}
			be.PutUint32(t.header[16:], be.Uint32(r[0].value))
			be.PutUint16(t.header[14:], be.Uint16(t.header[14:])-1)
			clear(b)
			if er = t.m.writeFork(t.fork, b, uint64(id)*uint64(t.nodeSize)); er != nil {
				return er
			}
			if er = t.mark(id, false); er != nil {
				return er
			}
		}
	}
	if t.id == 3 {
		t.m.v.overflow.root = be.Uint32(t.header[16:])
		t.m.v.overflow.total = t.total
	}
	return t.flush()
}
