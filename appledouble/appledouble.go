/*
 * Copyright (c) 2004-2024 Apple, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * @APPLE_LICENSE_HEADER_END@
 */
// SPDX-License-Identifier: APSL-2.0
// Modified 2026-10-09: Go adaptation of copyfile's AppleDouble/ATTR layouts and
// packing sequence. Checked borrowed sections and bounded sequential writes
// replace native descriptors and whole-value allocations. No host policy is
// ported. Pinned source and hashes: docs/sources.json. License: LICENSES/APSL-2.0.txt.
// Source: https://github.com/deploymenttheory/go-apfs-v3/blob/main/appledouble/appledouble.go

// Package appledouble reads and writes serialized AppleDouble metadata. It does
// not select companion files, capture host metadata or apply ACL/quarantine policy.
package appledouble

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const maxHeader = 65536 + 18
const maxAttributes = 4096

var be = binary.BigEndian

// Attribute is an ordered serialized ATTR record. Duplicate names, empty values
// and flags are retained. ACL/quarantine records are opaque serialized bytes,
// which are not interchangeable with a filesystem's raw security attributes.
type Attribute struct {
	Name  []byte
	Flags uint16
	Value block.Source
}

// File borrows its source and all values. FinderInfo always has its fixed slot;
// a zero-length resource slot cannot distinguish absent from empty source forks.
type File struct {
	FinderInfo   [32]byte
	ResourceFork block.Source
	Attributes   []Attribute
	Flags        uint16
	DebugTag     uint32
}

// Decode admits Apple's two-entry FinderInfo/resource-fork layout, with an
// optional ATTR extension. Value data stays in bounded borrowed sections.
// Unknown entry layouts are unsupported; malformed admitted layouts are corrupt.
func Decode(ctx context.Context, source block.Source) (*File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source == nil || source.Size() < 82 {
		return nil, corrupt("header length")
	}
	header := make([]byte, 82)
	if err := block.ReadFull(source, header, 0); err != nil {
		return nil, err
	}
	if be.Uint32(header) != 0x00051607 {
		return nil, corrupt("magic")
	}
	if be.Uint32(header[4:]) != 0x00020000 || be.Uint16(header[24:]) != 2 || be.Uint32(header[26:]) != 9 || be.Uint32(header[38:]) != 2 {
		return nil, fmt.Errorf("AppleDouble entry layout: %w", filesystem.ErrUnsupported)
	}
	finderOffset, finderLength := uint64(be.Uint32(header[30:])), uint64(be.Uint32(header[34:]))
	forkOffset, forkLength := uint64(be.Uint32(header[42:])), uint64(be.Uint32(header[46:]))
	if finderOffset != 50 || finderLength < 32 || finderOffset+finderLength > forkOffset || forkOffset+forkLength > uint64(source.Size()) {
		return nil, corrupt("entry ranges")
	}
	f := &File{}
	copy(f.FinderInfo[:], header[50:82])
	resource, err := block.NewSection(source, int64(forkOffset), int64(forkLength))
	if err != nil {
		return nil, err
	}
	f.ResourceFork = resource
	if finderLength == 32 {
		return f, nil
	}
	if finderLength < 70 {
		return nil, corrupt("ATTR header size")
	}
	header = make([]byte, 120)
	if err = block.ReadFull(source, header, 0); err != nil {
		return nil, err
	}
	if be.Uint32(header[84:]) != 0x41545452 {
		return nil, corrupt("ATTR magic")
	}
	total, start, length := uint64(be.Uint32(header[92:])), uint64(be.Uint32(header[96:])), uint64(be.Uint32(header[100:]))
	count := int(be.Uint16(header[118:]))
	if count > maxAttributes || start > maxHeader {
		return nil, filesystem.ErrLimit
	}
	if start < 120 || start > total || start+length != total || total > finderOffset+finderLength {
		return nil, corrupt("ATTR data ranges")
	}
	if !bytes.Equal(header[104:116], make([]byte, 12)) {
		return nil, fmt.Errorf("AppleDouble reserved fields: %w", filesystem.ErrUnsupported)
	}
	f.Flags = be.Uint16(header[116:])
	f.DebugTag = be.Uint32(header[88:])
	header = make([]byte, start)
	if err = block.ReadFull(source, header, 0); err != nil {
		return nil, err
	}
	cursor := uint64(120)
	type span struct{ start, end uint64 }
	var spans []span
	for i := 0; i < count; i++ {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if cursor+11 > start {
			return nil, corrupt("ATTR record header")
		}
		b := header[cursor:]
		offset, size := uint64(be.Uint32(b)), uint64(be.Uint32(b[4:]))
		n := uint64(b[10])
		next := cursor + (11+n+3)&^3
		// Native copyfile leaves an empty attribute's offset zero. It has no
		// data span and must remain distinguishable from an absent attribute.
		if n < 2 || next > start || b[11+n-1] != 0 || bytes.IndexByte(b[11:11+n-1], 0) >= 0 || (offset < start && (offset != 0 || size != 0)) || offset+size > total {
			return nil, corrupt("ATTR record name or value")
		}
		section, err := block.NewSection(source, int64(offset), int64(size))
		if err != nil {
			return nil, err
		}
		f.Attributes = append(f.Attributes, Attribute{append([]byte(nil), b[11:11+n-1]...), be.Uint16(b[8:]), section})
		if size > 0 {
			spans = append(spans, span{offset, offset + size})
		}
		cursor = next
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	for i := 1; i < len(spans); i++ {
		if spans[i].start < spans[i-1].end {
			return nil, corrupt("overlapping ATTR values")
		}
	}
	return f, nil
}

// Write emits a canonical AppleDouble container, preserving ordered values and
// flags. Padding and header layout may change. All wire-format size checks occur
// before output starts; later source, writer or cancellation errors are returned.
// It does not close caller-owned sources or the destination.
func Write(ctx context.Context, destination io.Writer, file *File) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if file == nil || destination == nil {
		return fmt.Errorf("AppleDouble output: %w", filesystem.ErrCorrupt)
	}
	if len(file.Attributes) > maxAttributes {
		return filesystem.ErrLimit
	}
	start, total := uint64(120), uint64(0)
	for _, a := range file.Attributes {
		if len(a.Name) == 0 || len(a.Name) > 254 || bytes.IndexByte(a.Name, 0) >= 0 || a.Value == nil || a.Value.Size() < 0 {
			return corrupt("attribute name or value")
		}
		start += (11 + uint64(len(a.Name)) + 1 + 3) &^ 3
		if uint64(a.Value.Size()) > math.MaxUint32-total {
			return filesystem.ErrLimit
		}
		total += uint64(a.Value.Size())
	}
	if start > maxHeader || total > math.MaxUint32-start {
		return filesystem.ErrLimit
	}
	total += start
	forkSize := int64(0)
	if file.ResourceFork != nil {
		forkSize = file.ResourceFork.Size()
	}
	if forkSize < 0 {
		return corrupt("resource fork size")
	}
	if uint64(forkSize) > math.MaxUint32-total {
		return filesystem.ErrLimit
	}
	header := make([]byte, start)
	be.PutUint32(header, 0x00051607)
	be.PutUint32(header[4:], 0x00020000)
	copy(header[8:24], "Mac OS X        ")
	be.PutUint16(header[24:], 2)
	be.PutUint32(header[26:], 9)
	be.PutUint32(header[30:], 50)
	be.PutUint32(header[34:], uint32(total-50))
	be.PutUint32(header[38:], 2)
	be.PutUint32(header[42:], uint32(total))
	be.PutUint32(header[46:], uint32(forkSize))
	copy(header[50:82], file.FinderInfo[:])
	be.PutUint32(header[84:], 0x41545452)
	be.PutUint32(header[88:], file.DebugTag)
	be.PutUint32(header[92:], uint32(total))
	be.PutUint32(header[96:], uint32(start))
	be.PutUint32(header[100:], uint32(total-start))
	be.PutUint16(header[116:], file.Flags)
	be.PutUint16(header[118:], uint16(len(file.Attributes)))
	cursor, offset := uint64(120), start
	for _, a := range file.Attributes {
		b := header[cursor:]
		be.PutUint32(b, uint32(offset))
		be.PutUint32(b[4:], uint32(a.Value.Size()))
		be.PutUint16(b[8:], a.Flags)
		b[10] = byte(len(a.Name) + 1)
		copy(b[11:], a.Name)
		cursor += (11 + uint64(len(a.Name)) + 1 + 3) &^ 3
		offset += uint64(a.Value.Size())
	}
	if n, err := destination.Write(header); err != nil {
		return err
	} else if n != len(header) {
		return io.ErrShortWrite
	}
	buffer := make([]byte, 64<<10)
	copyValue := func(source block.Source) error {
		if source == nil {
			return nil
		}
		for offset := int64(0); offset < source.Size(); {
			if err := ctx.Err(); err != nil {
				return err
			}
			b := buffer[:min(int64(len(buffer)), source.Size()-offset)]
			if err := block.ReadFull(source, b, offset); err != nil {
				return err
			}
			if n, err := destination.Write(b); err != nil {
				return err
			} else if n != len(b) {
				return io.ErrShortWrite
			}
			offset += int64(len(b))
		}
		return ctx.Err()
	}
	for _, a := range file.Attributes {
		if err := copyValue(a.Value); err != nil {
			return err
		}
	}
	return copyValue(file.ResourceFork)
}

func corrupt(what string) error { return fmt.Errorf("AppleDouble %s: %w", what, filesystem.ErrCorrupt) }
