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
// Modified 2026-10-13: Go adaptation of hfs_create_attr_btree, getnodecount
// and ExtendBTree. Exclusive unpublished storage replaces vnodes, buffer-cache
// transactions and mounted locks. Pinned source/hashes: docs/sources.json.
package hfsplus

import (
	"fmt"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"math"
)

func (m *mutation) initializeAttributeTree() (*mutableTree, error) {
	const nodeSize = 8192 // ATTRIBUTE_FILE_NODE_SIZE in Apple's hfs_xattr.c
	freeBytes := uint64(be.Uint32(m.header[48:])) * uint64(m.v.BlockSize)
	catalogSize := be.Uint64(m.header[272:])
	catalogClump := uint64(be.Uint32(m.header[280:]))
	wanted := min(max(min(catalogSize/5, 20<<20), catalogClump), freeBytes/10)
	nodes := max(uint64(2), wanted/nodeSize)
	blocks := (nodes*nodeSize + uint64(m.v.BlockSize) - 1) / uint64(m.v.BlockSize)
	size := blocks * uint64(m.v.BlockSize)
	nodes = size / nodeSize
	if nodes > 1<<18 || blocks > math.MaxUint32 {
		return nil, filesystem.ErrLimit
	}
	runs, err := m.allocateMultiple(uint32(blocks), m.v.BlockCount, max(1, nodeSize/m.v.BlockSize))
	if err != nil {
		return nil, err
	}
	fork := forkFromRuns(m.disk, m.v.BlockSize, size, runs)
	zeros := make([]byte, 128<<10)
	for at := uint64(0); at < size; at += uint64(len(zeros)) {
		if err = m.writeFork(fork, zeros[:min(uint64(len(zeros)), size-at)], at); err != nil {
			return nil, err
		}
	}
	descriptor := m.header[352:432]
	be.PutUint32(descriptor[8:], uint32(nodes*nodeSize))
	if err = m.storeExtentRuns(8, 0, descriptor, size, runs); err != nil {
		return nil, err
	}
	h := make([]byte, nodeSize)
	h[8] = 1
	be.PutUint16(h[10:], 3)
	for i, offset := range []uint16{14, 120, 248, nodeSize - 8} {
		be.PutUint16(h[nodeSize-2*(i+1):], offset)
	}
	be.PutUint16(h[32:], nodeSize)
	be.PutUint16(h[34:], 266) // sizeof(HFSPlusAttrKey) - sizeof(keyLength)
	be.PutUint32(h[36:], uint32(nodes))
	be.PutUint32(h[40:], uint32(nodes)-1)
	be.PutUint32(h[46:], uint32(nodes*nodeSize))
	h[50], h[51] = 0xff, 0xbc
	be.PutUint32(h[52:], 6)
	h[248] = 0x80
	t := &mutableTree{m: m, id: 8, descriptor: 352, fork: fork, header: h, nodeSize: nodeSize,
		total: uint32(nodes), mapBits: (nodeSize - 256) * 8, compare: attributeCompare, idOffset: 4}
	t.maps = []nodeMap{{node: 0, start: 248, end: nodeSize - 8, data: h}}
	if err = t.extendNodeMap(1); err != nil {
		return nil, err
	}
	if err = t.flush(); err != nil {
		return nil, err
	}
	m.v.attributeFork = bytesCopy(descriptor)
	m.trees[8] = t
	return t, nil
}

// Apple's ExtendBTree links new map nodes beginning at the previous EOF and
// allocates their own bits. Each map record has two bytes of alignment padding.
func (t *mutableTree) extendNodeMap(oldTotal uint32) error {
	if t.mapBits >= t.total {
		return nil
	}
	node := oldTotal
	for t.mapBits < t.total {
		if node >= t.total {
			return fmt.Errorf("HFS map-node capacity: %w", filesystem.ErrLimit)
		}
		b := make([]byte, t.nodeSize)
		b[8] = 2
		be.PutUint16(b[10:], 1)
		be.PutUint16(b[len(b)-2:], 14)
		be.PutUint16(b[len(b)-4:], t.nodeSize-6)
		last := &t.maps[len(t.maps)-1]
		be.PutUint32(last.data, node)
		t.maps = append(t.maps, nodeMap{node: node, start: 14, end: len(b) - 6, first: t.mapBits, data: b})
		t.mapBits += uint32(len(b)-20) * 8
		node++
	}
	for id := oldTotal; id < node; id++ {
		if err := t.mark(id, true); err != nil {
			return err
		}
	}
	return nil
}
