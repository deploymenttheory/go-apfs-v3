/*
 * Copyright (c) 2002-2015 Apple Inc. All rights reserved.
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
// Modified 2026-10-12: Go adaptation of calc_checksum, journal_is_clean,
// journal_open geometry and hfs_late_journal_init backing-file checks. Exclusive
// unpublished copies replace mounted devices. Only current, empty internal
// journals are admitted; no replay, relocation, reinitialization or live journal
// writer is ported. Exact pinned sources/hashes: docs/sources.json.
package hfsplus

import (
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const (
	journalHeaderMagic  = 0x4a4e4c78
	journalEndianMagic  = 0x12345678
	journalChecksumSize = 44 // offsetof(journal_header, sequence_num), NOT 48.
)

type mutationJournal struct{ infoID, fileID uint64 }

// JournalInfo describes the current internal journal without replay or repair.
// Reading it needs only the volume header/JIB, not a consistent catalog tree.
type JournalInfo struct {
	InfoBlock     uint32 `json:"infoBlock"`
	Offset        uint64 `json:"offset"`
	Size          uint64 `json:"size"`
	Start         uint64 `json:"start"`
	End           uint64 `json:"end"`
	HeaderSize    uint32 `json:"headerSize"`
	BlockListSize uint32 `json:"blockListSize"`
	Sequence      uint32 `json:"sequence"`
	ByteOrder     string `json:"byteOrder"`
	Pending       bool   `json:"pending"`

	order     binary.ByteOrder
	header    []byte
	blockSize uint64
}

// InspectJournal verifies current journal geometry and its header checksum.
// It never parses the catalog, changes cursors, or changes any input byte.
func InspectJournal(source block.Source) (*JournalInfo, error) {
	if source == nil || source.Size() < 1536 {
		return nil, bad("journal volume header")
	}
	header := make([]byte, 512)
	if err := block.ReadFull(source, header, 1024); err != nil {
		return nil, err
	}
	if (string(header[:2]) != "H+" || be.Uint16(header[2:]) != 4) && (string(header[:2]) != "HX" || be.Uint16(header[2:]) != 5) {
		return nil, bad("journal volume signature/version")
	}
	if be.Uint32(header[4:])&0x2000 == 0 {
		return nil, fmt.Errorf("volume is not journaled: %w", filesystem.ErrUnsupported)
	}
	bs, count := uint64(be.Uint32(header[40:])), uint64(be.Uint32(header[44:]))
	if bs < 512 || bs&(bs-1) != 0 || count == 0 || count > uint64(source.Size())/bs {
		return nil, bad("journal volume allocation geometry")
	}
	return readJournal(source, header, bs, count)
}

// journalChecksum follows Apple's byte-at-a-time calc_checksum. Callers zero
// the checksum field in the original byte order before calculating it.
func journalChecksum(b []byte) uint32 {
	var sum uint32
	for _, v := range b {
		sum = (sum << 8) ^ (sum + uint32(v))
	}
	return ^sum
}

func readJournal(source block.Source, header []byte, bs, count uint64) (*JournalInfo, error) {
	infoBlock := uint64(be.Uint32(header[12:]))
	if infoBlock == 0 || infoBlock >= count {
		return nil, bad("journal info block range")
	}
	info := make([]byte, 180) // packed JournalInfoBlock; preserve all reserved bytes.
	if err := block.ReadFull(source, info, int64(infoBlock*bs)); err != nil {
		return nil, err
	}
	if be.Uint32(info) != 1 { // kJIJournalInFSMask only; no external/need-init/unknown flags.
		return nil, fmt.Errorf("journal must be initialized and internal: %w", filesystem.ErrUnsupported)
	}
	offset, size := be.Uint64(info[36:]), be.Uint64(info[44:])
	volumeSize := count * bs
	if size < 256<<10 || size > 1<<30 || offset%bs != 0 || size%bs != 0 || offset > volumeSize || size > volumeSize-offset || offset < 1536 || offset+size > volumeSize-1024 || (infoBlock*bs < offset+size && offset < (infoBlock+1)*bs) {
		return nil, bad("journal storage geometry")
	}
	h := make([]byte, 48)
	if err := block.ReadFull(source, h, int64(offset)); err != nil {
		return nil, err
	}
	var order binary.ByteOrder
	switch {
	case be.Uint32(h) == journalHeaderMagic:
		order = be
	case binary.LittleEndian.Uint32(h) == journalHeaderMagic:
		order = binary.LittleEndian
	case be.Uint32(h) == 0x4a484452 || binary.LittleEndian.Uint32(h) == 0x4a484452: // OLD_JOURNAL_HEADER_MAGIC
		return nil, fmt.Errorf("old journal header: %w", filesystem.ErrUnsupported)
	default:
		return nil, bad("journal header magic")
	}
	if order.Uint32(h[4:]) != journalEndianMagic {
		return nil, bad("journal byte order")
	}
	checksum := order.Uint32(h[36:])
	clear(h[36:40])
	if journalChecksum(h[:journalChecksumSize]) != checksum {
		return nil, bad("journal header checksum")
	}
	order.PutUint32(h[36:], checksum)
	start, end, headerSize := order.Uint64(h[8:]), order.Uint64(h[16:]), uint64(order.Uint32(h[40:]))
	listSize := uint64(order.Uint32(h[32:]))
	if order.Uint64(h[24:]) != size || headerSize < 512 || headerSize > bs || headerSize&(headerSize-1) != 0 || listSize < 512 || listSize%512 != 0 || listSize > size-headerSize || start < headerSize || start > size || end < headerSize || end > size || start%512 != 0 || end%512 != 0 {
		return nil, bad("journal header geometry")
	}
	byteOrder := "big-endian"
	if order == binary.LittleEndian {
		byteOrder = "little-endian"
	}
	return &JournalInfo{InfoBlock: uint32(infoBlock), Offset: offset, Size: size,
		Start: start, End: end, HeaderSize: uint32(headerSize), BlockListSize: uint32(listSize),
		Sequence: order.Uint32(h[44:]), ByteOrder: byteOrder, Pending: start != end,
		order: order, header: h, blockSize: bs}, nil
}

func (m *mutation) admitJournal() error {
	j, err := readJournal(m.disk, m.header, uint64(m.v.BlockSize), uint64(m.v.BlockCount))
	if err != nil {
		return err
	}
	// Backing files must agree with the header/JIB without Apple's repair,
	// relocation or reinitialization fallback. Their extents already participate
	// in the complete allocation-ownership check, just like other catalog files.
	infoID, err := m.journalFile(".journal_info_block", uint64(j.InfoBlock)*j.blockSize, j.blockSize)
	if err != nil {
		return err
	}
	fileID, err := m.journalFile(".journal", j.Offset, j.Size)
	if err != nil {
		return err
	}
	if infoID == fileID {
		return bad("journal backing identity")
	}
	// journal_is_clean compares the actual cursors. Do not advance them, reset
	// the journal, or discard pending transactions to admit a dirty source.
	if j.Pending {
		return fmt.Errorf("journal requires replay: %w", filesystem.ErrUnsupported)
	}
	m.journal = &mutationJournal{infoID: infoID, fileID: fileID}
	return nil
}

func (m *mutation) journalFile(name string, offset, size uint64) (uint64, error) {
	entry, err := m.v.Lookup(m.ctx, 2, name)
	if err != nil {
		return 0, fmt.Errorf("journal backing file %s: %w", name, err)
	}
	b, err := m.v.catalogRecord(m.ctx, entry.Object)
	if err != nil {
		return 0, err
	}
	if len(b) != 248 || be.Uint16(b) != 2 || be.Uint16(b[42:])&0170000 != 0100000 || uint64(be.Uint32(b[8:])) != entry.Object || b[41]&0x20 != 0 || be.Uint64(b[168:]) != 0 {
		return 0, bad("journal backing file type")
	}
	f, err := m.v.fileFork(m.ctx, be.Uint32(b[8:]), 0, b[88:168])
	if err != nil {
		return 0, err
	}
	if f.size != size || len(f.extents) != 1 || f.extents[0].physical != offset || f.extents[0].size != size {
		return 0, bad("journal backing file location/size")
	}
	return uint64(be.Uint32(b[8:])), nil
}
