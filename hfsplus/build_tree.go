/*
 * Copyright (c) 1999-2023 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */
// SPDX-License-Identifier: APSL-2.0
// Modified 2026-10-10: Go adaptation of makehfs volume/B-tree initialization.
// Bounded bulk construction and logical-reader payloads replace device mutation.
// Source revision/hashes: docs/sources.json. License: LICENSES/APSL-2.0.txt.
package hfsplus

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const buildNodeSize = 4096

// buildTree bulk-loads already ordered keys. It uses the header/user/map layout
// of Apple's makehfs.c, with bounded multi-level nodes instead of an empty tree.
// Every unused node and byte is zero; eight spare nodes permit native growth.
func buildTree(records []treeRecord, maxKey uint16, compare byte, variable bool) ([]byte, error) {
	nodes := [][]byte{make([]byte, buildNodeSize)}
	var firstLeaf, lastLeaf uint32
	level := records
	height := byte(1)
	root := uint32(0)
	for len(level) > 0 {
		var parents []treeRecord
		first := len(nodes)
		for len(level) > 0 {
			if len(nodes) >= 16000 {
				return nil, filesystem.ErrLimit
			}
			b := make([]byte, buildNodeSize)
			b[8], b[9] = 0, height
			if height == 1 {
				b[8] = 255
			}
			off, count := 14, 0
			for count < len(level) {
				r := level[count]
				n := len(r.key) + len(r.value)
				if off+n+2*(count+2) > len(b) {
					break
				}
				be.PutUint16(b[len(b)-2*(count+1):], uint16(off))
				copy(b[off:], r.key)
				copy(b[off+len(r.key):], r.value)
				off += n
				count++
			}
			if count == 0 {
				return nil, fmt.Errorf("HFS B-tree record size: %w", filesystem.ErrLimit)
			}
			be.PutUint16(b[10:], uint16(count))
			be.PutUint16(b[len(b)-2*(count+1):], uint16(off))
			id := uint32(len(nodes))
			child := make([]byte, 4)
			be.PutUint32(child, id)
			parents = append(parents, treeRecord{level[0].key, child})
			nodes = append(nodes, b)
			level = level[count:]
		}
		for i := first; i < len(nodes); i++ {
			if i > first {
				be.PutUint32(nodes[i][4:], uint32(i-1))
			}
			if i+1 < len(nodes) {
				be.PutUint32(nodes[i], uint32(i+1))
			}
		}
		if height == 1 {
			firstLeaf, lastLeaf = uint32(first), uint32(len(nodes)-1)
		}
		if len(parents) == 1 {
			root = uint32(first)
			break
		}
		level = parents
		height++
		if height > 16 {
			return nil, filesystem.ErrLimit
		}
	}
	used := len(nodes)
	for range 8 {
		nodes = append(nodes, make([]byte, buildNodeSize))
	}
	h := nodes[0]
	h[8] = 1
	be.PutUint16(h[10:], 3)
	for i, off := range []uint16{14, 120, 248, buildNodeSize - 8} {
		be.PutUint16(h[len(h)-2*(i+1):], off)
	}
	if root != 0 {
		be.PutUint16(h[14:], uint16(height))
	}
	be.PutUint32(h[16:], root)
	be.PutUint32(h[20:], uint32(len(records)))
	be.PutUint32(h[24:], firstLeaf)
	be.PutUint32(h[28:], lastLeaf)
	be.PutUint16(h[32:], buildNodeSize)
	be.PutUint16(h[34:], maxKey)
	be.PutUint32(h[36:], uint32(len(nodes)))
	be.PutUint32(h[40:], uint32(len(nodes)-used))
	be.PutUint32(h[46:], buildNodeSize*8)
	h[51] = compare
	attributes := uint32(2)
	if variable {
		attributes |= 4
	}
	be.PutUint32(h[52:], attributes)
	for i := range used {
		h[248+i/8] |= 0x80 >> (i % 8)
	}
	result := make([]byte, 0, len(nodes)*buildNodeSize)
	for _, b := range nodes {
		result = append(result, b...)
	}
	return result, nil
}
