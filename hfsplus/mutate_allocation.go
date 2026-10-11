/*
 * Copyright (c) 2000-2021 Apple Inc. All rights reserved.
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
// Additional extent adaptation: Copyright (c) 2014-2015 Apple Inc.
// Modified 2026-10-11: bounded Go adaptation of VolumeAllocation bitmap marking
// and hfs_extents extent grouping/coalescing. Private copies replace mounted
// vnodes, reservations, locks, trim and journal transactions. Allocation uses
// deterministic first-fit runs; it does not port Apple's allocation caches.
// Pinned source and hashes: docs/sources.json. License: LICENSES/APSL-2.0.txt.
package hfsplus

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"math"
	"syscall"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

// MutableSource is exclusively owned, unpublished scratch storage. It is NOT
// an in-place write API: after any failure its caller must discard the entire
// copy. imageedit owns this lifecycle for ordinary image-file operations.
type MutableSource interface {
	block.Source
	io.WriterAt
}

type allocationRun struct{ start, count uint32 }
type mutation struct {
	ctx             context.Context
	disk            MutableSource
	v               *Volume
	header          []byte
	bitmap, claimed []byte
	allocation      *fork
	journal         *mutationJournal
	trees           map[uint32]*mutableTree
	overflowUsed    map[string]bool
}

func (m *mutation) write(p []byte, off uint64) error {
	if err := m.ctx.Err(); err != nil {
		return err
	}
	if off > uint64(m.disk.Size()) || uint64(len(p)) > uint64(m.disk.Size())-off {
		return bad("mutation write range")
	}
	n, err := m.disk.WriteAt(p, int64(off))
	if n != len(p) && err == nil {
		err = io.ErrShortWrite
	}
	return err
}

func (m *mutation) writeFork(f *fork, p []byte, off uint64) error {
	if off > f.size || uint64(len(p)) > f.size-off {
		return bad("mutation fork range")
	}
	for len(p) > 0 {
		found := false
		for _, e := range f.extents {
			if off < e.logical || off >= e.logical+e.size {
				continue
			}
			n := min(uint64(len(p)), e.logical+e.size-off)
			if err := m.write(p[:n], e.physical+off-e.logical); err != nil {
				return err
			}
			p = p[n:]
			off += n
			found = true
			break
		}
		if !found {
			return bad("mutation fork hole")
		}
	}
	return nil
}

func bitmapBit(b []byte, index uint32) bool { return b[index/8]&(0x80>>(index%8)) != 0 }
func setBitmapBit(b []byte, index uint32, used bool) {
	if used {
		b[index/8] |= 0x80 >> (index % 8)
	} else {
		b[index/8] &^= 0x80 >> (index % 8)
	}
}

func (m *mutation) claim(f *fork) error {
	for _, e := range f.extents {
		start, n := uint32(e.physical/uint64(m.v.BlockSize)), uint32(e.size/uint64(m.v.BlockSize))
		for i := start; i < start+n; i++ {
			if !bitmapBit(m.bitmap, i) || bitmapBit(m.claimed, i) {
				return bad("unallocated or cross-linked fork")
			}
			setBitmapBit(m.claimed, i, true)
		}
	}
	return m.ctx.Err()
}

// Marking checks old state before changing it, matching BlockMarkAllocated /
// BlockMarkFree. Accounting is in allocation blocks, never logical file bytes.
func (m *mutation) mark(r allocationRun, used bool) error {
	if r.count == 0 || r.start >= m.v.BlockCount || r.count > m.v.BlockCount-r.start {
		return bad("allocation mark range")
	}
	for i := r.start; i < r.start+r.count; i++ {
		if bitmapBit(m.bitmap, i) == used {
			return bad("double allocation or free")
		}
	}
	for i := r.start; i < r.start+r.count; i++ {
		setBitmapBit(m.bitmap, i, used)
	}
	free := be.Uint32(m.header[48:])
	if used {
		if free < r.count {
			return bad("free block accounting")
		}
		free -= r.count
	} else {
		if free > m.v.BlockCount-r.count {
			return bad("free block overflow")
		}
		free += r.count
	}
	be.PutUint32(m.header[48:], free)
	return nil
}

func appendRun(runs []allocationRun, r allocationRun) []allocationRun {
	if r.count == 0 {
		return runs
	}
	if len(runs) > 0 && runs[len(runs)-1].start+runs[len(runs)-1].count == r.start {
		runs[len(runs)-1].count += r.count
		return runs
	}
	return append(runs, r)
}

func forkRuns(f *fork, bs uint32) []allocationRun {
	var runs []allocationRun
	for _, e := range f.extents {
		runs = appendRun(runs, allocationRun{uint32(e.physical / uint64(bs)), uint32(e.size / uint64(bs))})
	}
	return runs
}

// allocate scans each bitmap bit at most once per request. The preferred tail
// extends an existing extent where possible; the remainder uses ascending runs.
func (m *mutation) allocate(count, preferred uint32) ([]allocationRun, error) {
	if count > be.Uint32(m.header[48:]) {
		return nil, fmt.Errorf("HFS+ allocation: %w", syscall.ENOSPC)
	}
	var runs []allocationRun
	remaining := count
	take := func(start, end uint32) error {
		for i := start; i < end && remaining > 0; {
			if err := m.ctx.Err(); err != nil {
				return err
			}
			if bitmapBit(m.bitmap, i) {
				i++
				continue
			}
			first := i
			for i < end && i-first < remaining && !bitmapBit(m.bitmap, i) {
				i++
			}
			r := allocationRun{first, i - first}
			if err := m.mark(r, true); err != nil {
				return err
			}
			runs = appendRun(runs, r)
			remaining -= r.count
			if len(runs) > 1<<17 {
				return filesystem.ErrLimit
			}
		}
		return nil
	}
	if preferred < m.v.BlockCount && remaining > 0 && !bitmapBit(m.bitmap, preferred) {
		end := preferred
		for end < m.v.BlockCount && end-preferred < remaining && !bitmapBit(m.bitmap, end) {
			end++
		}
		if err := take(preferred, end); err != nil {
			return nil, err
		}
	}
	if err := take(0, m.v.BlockCount); err != nil {
		return nil, err
	}
	if remaining != 0 {
		return nil, bad("bitmap free count")
	}
	if len(runs) > 0 {
		last := runs[len(runs)-1]
		be.PutUint32(m.header[52:], (last.start+last.count)%m.v.BlockCount)
	}
	return runs, nil
}

func (m *mutation) resizeRuns(old []allocationRun, blocks uint32) ([]allocationRun, error) {
	var runs []allocationRun
	remaining := blocks
	for _, r := range old {
		keep := min(remaining, r.count)
		runs = appendRun(runs, allocationRun{r.start, keep})
		remaining -= keep
		if keep < r.count {
			if err := m.mark(allocationRun{r.start + keep, r.count - keep}, false); err != nil {
				return nil, err
			}
		}
	}
	if remaining > 0 {
		preferred := m.v.BlockCount
		if len(runs) > 0 {
			last := runs[len(runs)-1]
			preferred = last.start + last.count
		}
		more, err := m.allocate(remaining, preferred)
		if err != nil {
			return nil, err
		}
		for _, r := range more {
			runs = appendRun(runs, r)
		}
	}
	return runs, nil
}

func encodeRuns(descriptor []byte, size uint64, runs []allocationRun) {
	be.PutUint64(descriptor, size)
	clear(descriptor[12:]) // retain the original clump size
	var total uint32
	for i, r := range runs {
		total += r.count
		if i < 8 {
			be.PutUint32(descriptor[16+i*8:], r.start)
			be.PutUint32(descriptor[20+i*8:], r.count)
		}
	}
	be.PutUint32(descriptor[12:], total)
}

func forkFromRuns(source block.Source, bs uint32, size uint64, runs []allocationRun) *fork {
	f := &fork{source: source, size: size}
	var off uint64
	for _, r := range runs {
		n := uint64(r.count) * uint64(bs)
		f.extents = append(f.extents, extent{off, uint64(r.start) * uint64(bs), n})
		off += n
	}
	return f
}

func (m *mutation) growTree(t *mutableTree) error {
	// Reserve eight nodes at a time, rounded to whole allocation blocks. The
	// extents file must remain self-describing in its volume-header descriptor.
	old := forkRuns(t.fork, m.v.BlockSize)
	blocks := be.Uint32(m.header[t.descriptor+12:])
	add := (uint64(t.nodeSize)*8 + uint64(m.v.BlockSize) - 1) / uint64(m.v.BlockSize)
	if add == 0 || add > math.MaxUint32 || uint64(blocks)+add > math.MaxUint32 {
		return filesystem.ErrLimit
	}
	runs, err := m.resizeRuns(old, blocks+uint32(add))
	if err != nil {
		return err
	}
	if len(runs) > 8 {
		return fmt.Errorf("fragmented metadata-file extension: %w", filesystem.ErrUnsupported)
	}
	size := uint64(blocks+uint32(add)) * uint64(m.v.BlockSize)
	newTotal := uint32(size / uint64(t.nodeSize))
	if newTotal > 1<<18 || newTotal > t.mapBits {
		return filesystem.ErrLimit
	}
	f := forkFromRuns(m.disk, m.v.BlockSize, size, runs)
	zeros := make([]byte, t.nodeSize)
	for off := t.fork.size; off < size; off += uint64(len(zeros)) {
		if err = m.writeFork(f, zeros[:min(uint64(len(zeros)), size-off)], off); err != nil {
			return err
		}
	}
	encodeRuns(m.header[t.descriptor:t.descriptor+80], size, runs)
	be.PutUint32(t.header[40:], be.Uint32(t.header[40:])+newTotal-t.total)
	t.total = newTotal
	be.PutUint32(t.header[36:], newTotal)
	t.fork = f
	if t.id == 3 {
		m.v.overflow.fork = f
		m.v.overflow.total = newTotal
	}
	if t.id == 8 {
		m.v.attributeFork = bytesCopy(m.header[352:432])
	}
	return nil
}

func bytesCopy(p []byte) []byte { return append([]byte(nil), p...) }

func (m *mutation) writePayload(f *fork, data block.Source) error {
	if data == nil || data.Size() < 0 || uint64(data.Size()) > f.size {
		return fs.ErrInvalid
	}
	buf := make([]byte, 128<<10)
	for off := int64(0); off < data.Size(); {
		if err := m.ctx.Err(); err != nil {
			return err
		}
		n := min(int64(len(buf)), data.Size()-off)
		if err := block.ReadFull(data, buf[:n], off); err != nil {
			return err
		}
		if err := m.writeFork(f, buf[:n], uint64(off)); err != nil {
			return err
		}
		off += n
	}
	// Initialize the final allocation-block slack after the logical contents.
	if f.size > uint64(data.Size()) {
		clear(buf)
		for off := uint64(data.Size()); off < f.size; {
			n := min(uint64(len(buf)), f.size-off)
			if err := m.writeFork(f, buf[:n], off); err != nil {
				return err
			}
			off += n
		}
	}
	return nil
}
