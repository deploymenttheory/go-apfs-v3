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
// Modified 2026-10-20: bounded, read-only acquisition measurements. No replay
// or expected filesystem state is computed here. Pinned sources: docs/sources.json.
package fixture

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
)

// journalWindow measures native cursors and unapplied home sectors solely to
// reject missed acquisition windows. It never constructs recovered disk bytes.
type journalWindow struct {
	Offset        uint64 `json:"offset"`
	Size          uint64 `json:"size"`
	Start         uint64 `json:"start"`
	End           uint64 `json:"end"`
	BlockListSize uint32 `json:"blockListSize"`
	HeaderSize    uint32 `json:"headerSize"`
	Sequence      uint32 `json:"sequence"`
}

func journalWindowMatches(s *journalWindow, wanted string, observedEnd uint64, changes int, tail string) bool {
	if s.Start == s.End {
		return false
	}
	if strings.HasSuffix(wanted, "-tail") {
		// The declared committed range can already match home sectors while
		// Apple is writing the next transaction beyond its recorded end.
		// The tail's checksums/sequence and Apple's replay qualify that window.
		return tail == wanted && s.End == observedEnd
	}
	shape := "linear"
	if s.Start > s.End {
		shape = "wrapped"
	}
	return shape == wanted && changes > 0
}

func acquisitionJournalChecksum(b []byte) uint32 {
	var sum uint32
	for _, v := range b {
		sum = sum<<8 ^ (sum + uint32(v))
	}
	return ^sum
}

func measureJournal(path string) (*journalWindow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != 64<<20 {
		return nil, errors.New("journal capture requires a 64 MiB regular raw file")
	}
	header := make([]byte, 512)
	if _, err := f.ReadAt(header, 1024); err != nil {
		return nil, err
	}
	be, le := binary.BigEndian, binary.LittleEndian
	if string(header[:2]) != "H+" && string(header[:2]) != "HX" {
		return nil, errors.New("missing native HFS volume")
	}
	blockSize, infoBlock := uint64(be.Uint32(header[40:])), uint64(be.Uint32(header[12:]))
	if blockSize != 4096 || infoBlock == 0 || infoBlock >= uint64(info.Size())/blockSize {
		return nil, errors.New("invalid native journal information range")
	}
	if _, err := f.ReadAt(header[:180], int64(infoBlock*blockSize)); err != nil {
		return nil, err
	}
	s := &journalWindow{Offset: be.Uint64(header[36:]), Size: be.Uint64(header[44:])}
	if be.Uint32(header) != 1 || s.Offset > uint64(info.Size()) || s.Size > uint64(info.Size())-s.Offset || s.Size < 512 || s.Size > 16<<20 {
		return nil, errors.New("unsupported native journal acquisition geometry")
	}
	if _, err := f.ReadAt(header[:48], int64(s.Offset)); err != nil {
		return nil, err
	}
	if string(header[:4]) != "xLNJ" || le.Uint32(header[4:]) != 0x12345678 || le.Uint64(header[24:]) != s.Size {
		return nil, errors.New("invalid native journal acquisition header")
	}
	s.Start, s.End = le.Uint64(header[8:]), le.Uint64(header[16:])
	s.BlockListSize, s.HeaderSize, s.Sequence = le.Uint32(header[32:]), le.Uint32(header[40:]), le.Uint32(header[44:])
	stored := le.Uint32(header[36:])
	clear(header[36:40])
	if acquisitionJournalChecksum(header[:44]) != stored || s.HeaderSize != 512 || s.BlockListSize < 32 || s.BlockListSize > 1<<20 || uint64(s.BlockListSize) >= s.Size || s.Start < 512 || s.Start > s.Size || s.End < 512 || s.End > s.Size {
		return nil, errors.New("invalid native journal checksum or cursors")
	}
	return s, nil
}

func (s *journalWindow) advance(offset, count uint64) uint64 {
	return uint64(s.HeaderSize) + (offset+count-uint64(s.HeaderSize))%(s.Size-uint64(s.HeaderSize))
}

func (s *journalWindow) read(f io.ReaderAt, offset uint64, size uint32) ([]byte, error) {
	if offset == s.Size {
		offset = uint64(s.HeaderSize)
	}
	if offset < uint64(s.HeaderSize) || offset >= s.Size || uint64(size) > s.Size-uint64(s.HeaderSize) {
		return nil, errors.New("journal acquisition read outside ring")
	}
	b := make([]byte, size)
	n := min(uint64(size), s.Size-offset)
	if _, err := f.ReadAt(b[:n], int64(s.Offset+offset)); err != nil {
		return nil, err
	}
	if n < uint64(size) {
		if _, err := f.ReadAt(b[n:], int64(s.Offset+uint64(s.HeaderSize))); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// measureJournalChanges counts differences from native home blocks; only Apple's
// replay-only operation defines what must be written or discarded.
func measureJournalChanges(path string, s *journalWindow) (int, string, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer func() { _ = f.Close() }()
	le := binary.LittleEndian
	latest := map[int64][]byte{}
	position, consumed := s.Start, uint64(0)
	for position != s.End {
		if consumed >= s.Size-uint64(s.HeaderSize) {
			return 0, "", errors.New("journal acquisition traversal exceeded ring")
		}
		list, err := s.read(f, position, s.BlockListSize)
		if err != nil {
			return 0, "", err
		}
		maximum, count, used, stored, flags := le.Uint16(list), le.Uint16(list[2:]), le.Uint32(list[4:]), le.Uint32(list[8:]), le.Uint32(list[12:])
		clear(list[8:12])
		if acquisitionJournalChecksum(list[:32]) != stored || count < 1 || count > maximum || int(maximum) > len(list)/16-1 || used < s.BlockListSize || uint64(used) > s.Size-uint64(s.HeaderSize)-consumed {
			return 0, "", errors.New("invalid native committed block list during acquisition")
		}
		offset, actual := s.advance(position, uint64(s.BlockListSize)), s.BlockListSize
		for index := 1; index < int(count); index++ {
			record := list[16+index*16:]
			number, length, sum := int64(le.Uint64(record)), le.Uint32(record[8:]), le.Uint32(record[12:])
			if length == 0 || length%512 != 0 || length > used-actual {
				return 0, "", errors.New("invalid native committed payload length")
			}
			payload, err := s.read(f, offset, length)
			if err != nil {
				return 0, "", err
			}
			if number != -1 {
				if number < 0 || number > 64<<20/512 || int64(length) > 64<<20-number*512 || flags&1 != 0 && sum != 0 && acquisitionJournalChecksum(payload) != sum {
					return 0, "", errors.New("invalid native committed payload checksum or range")
				}
				for part := 0; part < int(length); part += 512 {
					latest[number*512+int64(part)] = payload[part : part+512]
				}
			}
			offset, actual = s.advance(offset, uint64(length)), actual+length
		}
		if actual != used {
			return 0, "", errors.New("native committed payload size mismatch")
		}
		consumed += uint64(used)
		position = s.advance(position, uint64(used))
	}
	changes := 0
	home := make([]byte, 512)
	for offset, payload := range latest {
		if _, err := f.ReadAt(home, offset); err != nil {
			return 0, "", err
		}
		if !bytes.Equal(home, payload) {
			changes++
		}
	}
	tail, err := s.read(f, s.End, s.BlockListSize)
	if err != nil {
		return changes, "", err
	}
	maximum, count, used, stored, flags, sequence := le.Uint16(tail), le.Uint16(tail[2:]), le.Uint32(tail[4:]), le.Uint32(tail[8:]), le.Uint32(tail[12:]), le.Uint32(tail[28:])
	clear(tail[8:12])
	if acquisitionJournalChecksum(tail[:32]) != stored || (sequence != s.Sequence && sequence != s.Sequence+1) || flags != 3 || count <= 1 || count > maximum || int(maximum) > len(tail)/16-1 || used < s.BlockListSize || uint64(used) > s.Size-uint64(s.HeaderSize) {
		return changes, "", nil
	}
	offset, actual := s.advance(s.End, uint64(s.BlockListSize)), s.BlockListSize
	kind := "complete-tail"
	for index := 1; index < int(count); index++ {
		record := tail[16+index*16:]
		number, length, sum := int64(le.Uint64(record)), le.Uint32(record[8:]), le.Uint32(record[12:])
		if length == 0 || length%512 != 0 || length > used-actual {
			return changes, "", nil
		}
		payload, err := s.read(f, offset, length)
		if err != nil {
			return 0, "", err
		}
		if number != -1 && sum != 0 && acquisitionJournalChecksum(payload) != sum {
			kind = "incomplete-tail"
		}
		actual += length
		offset = s.advance(offset, uint64(length))
	}
	if actual != used {
		return changes, "", nil
	}
	return changes, kind, nil
}
