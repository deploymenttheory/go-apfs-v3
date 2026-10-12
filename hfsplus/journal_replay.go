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
// Modified 2026-10-12: bounded Go adaptation of replay_journal and journal
// ring reads. Last writes coalesce by 512-byte sector instead of C buckets.
// Header/data checksums and sequence-qualified tail scanning follow Apple.
// Invalid committed records are refused rather than salvaged. Recovery writes
// only an exclusively owned unpublished copy; source hashes and publication
// are managed by imageedit. No live journaling, reset or reinitialization.
// Pinned sources and exact hashes: docs/sources.json.
package hfsplus

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const maxJournalSectors = 1 << 18

// JournalReplayReport records exactly which log region was accepted. End may
// include complete, sequence-qualified transactions beyond the stored cursor.
type JournalReplayReport struct {
	Before          JournalInfo `json:"before"`
	RecoveredEnd    uint64      `json:"recoveredEnd"`
	BlockLists      uint64      `json:"blockLists"`
	Transactions    uint64      `json:"transactions"`
	ExtraBlockLists uint64      `json:"extraBlockLists"`
	Sectors         uint64      `json:"sectors"`
}

type journalRecord struct{ target, offset, size uint64 }
type journalReplay struct {
	j       *JournalInfo
	records []journalRecord
	report  JournalReplayReport
}

func (j *JournalInfo) advance(offset, size uint64) uint64 {
	return uint64(j.HeaderSize) + (offset+size-uint64(j.HeaderSize))%(j.Size-uint64(j.HeaderSize))
}

func (j *JournalInfo) distance(start, end uint64) uint64 {
	return (end + j.Size - uint64(j.HeaderSize) - start) % (j.Size - uint64(j.HeaderSize))
}

func (j *JournalInfo) read(source block.Source, data []byte, offset uint64) error {
	n := min(uint64(len(data)), j.Size-offset)
	if err := block.ReadFull(source, data[:n], int64(j.Offset+offset)); err != nil {
		return err
	}
	if n < uint64(len(data)) {
		return block.ReadFull(source, data[n:], int64(j.Offset+uint64(j.HeaderSize)))
	}
	return nil
}

// planJournal validates the entire selected log before any home block changes.
// The declared committed range is strict. An invalid tail header/sequence is
// the native end-of-log sentinel; incomplete tail payloads discard that whole
// tentative transaction. A full ring without a sentinel is refused.
func planJournal(ctx context.Context, source block.Source) (*journalReplay, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	j, err := InspectJournal(source)
	if err != nil {
		return nil, err
	}
	var volume [512]byte
	if err = block.ReadFull(source, volume[:], 1024); err != nil {
		return nil, err
	}
	if string(volume[8:12]) != "HFSJ" || be.Uint32(volume[4:]) & ^uint32(0x80003500) != 0 {
		return nil, fmt.Errorf("journal recovery requires a current unlocked HFSJ mount profile: %w", filesystem.ErrUnsupported)
	}
	// The native backing-image evidence qualifies 512-byte journal sectors.
	// Larger sectors remain inspectable, without guessing destination units.
	if j.HeaderSize != 512 {
		return nil, fmt.Errorf("journal replay sector profile: %w", filesystem.ErrUnsupported)
	}
	if j.BlockListSize > 1<<20 {
		return nil, filesystem.ErrLimit
	}
	p := &journalReplay{j: j, report: JournalReplayReport{Before: *j, RecoveredEnd: j.End}}
	start, end := j.advance(j.Start, 0), j.advance(j.End, 0)
	p.report.RecoveredEnd = end
	if start == end {
		return p, nil
	}
	declared := j.distance(start, end)
	capacity := j.Size - uint64(j.HeaderSize)
	position, consumed := start, uint64(0)
	var sequence uint32
	list := make([]byte, j.BlockListSize)
	buffer := make([]byte, 64<<10)
	txnIndex, txnOffset := 0, start
	txnReport := p.report
	for consumed < capacity {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		tail := consumed >= declared
		if tail && sequence == 0 {
			break // Native legacy transactions cannot qualify extra records.
		}
		if uint64(len(list)) > capacity-consumed {
			if !tail {
				return nil, bad("journal committed header crosses ring limit")
			}
			break
		}
		if err := j.read(source, list, position); err != nil {
			return nil, err
		}
		stored := j.order.Uint32(list[8:])
		clear(list[8:12])
		nextSequence := j.order.Uint32(list[28:])
		validSequence := sequence == 0 || nextSequence == 0 || nextSequence == sequence || nextSequence == sequence+1
		if journalChecksum(list[:32]) != stored || !validSequence {
			if tail {
				break
			}
			return nil, bad("journal committed block-list checksum/sequence")
		}
		maximum, count := uint64(j.order.Uint16(list)), uint64(j.order.Uint16(list[2:]))
		used, flags := uint64(j.order.Uint32(list[4:])), j.order.Uint32(list[12:])
		if maximum == 0 || maximum > uint64(len(list))/16-1 || count < 1 || count > maximum || used < uint64(len(list)) || used%512 != 0 || used > capacity-consumed || (!tail && used > declared-consumed) {
			return nil, bad("journal block-list geometry")
		}
		if flags & ^uint32(3) != 0 || flags&1 == 0 {
			return nil, fmt.Errorf("journal block-list checksum flags: %w", filesystem.ErrUnsupported)
		}
		if flags&2 != 0 {
			txnIndex, txnOffset, txnReport = len(p.records), position, p.report
		} else if p.report.BlockLists == 0 || (sequence != 0 && nextSequence != sequence) {
			return nil, bad("journal transaction continuation")
		}
		records := make([]journalRecord, 0, count-1)
		offset, actual := j.advance(position, uint64(len(list))), uint64(len(list))
		payloadBad := false
		for i := uint64(1); i < count; i++ {
			info := list[16+i*16 : 32+i*16]
			number, size, checksum := j.order.Uint64(info), uint64(j.order.Uint32(info[8:])), j.order.Uint32(info[12:])
			if size == 0 || size%512 != 0 || size > used-actual {
				return nil, bad("journal block size")
			}
			// -1 is a killed buffer, whose bytes occupy log space but are not
			// written or checksummed by Apple's replay code.
			if number != ^uint64(0) {
				if number > uint64(source.Size())/512 || size > uint64(source.Size())-number*512 {
					return nil, bad("journal destination outside volume")
				}
				target := number * 512
				if target < j.Offset+j.Size && j.Offset < target+size || target < (uint64(j.InfoBlock)+1)*j.blockSize && uint64(j.InfoBlock)*j.blockSize < target+size {
					return nil, bad("journal destination overlaps log or info block")
				}
				var sum uint32
				for done := uint64(0); done < size; {
					if err := ctx.Err(); err != nil {
						return nil, err
					}
					chunk := buffer[:min(uint64(len(buffer)), size-done)]
					if err := j.read(source, chunk, j.advance(offset, done)); err != nil {
						return nil, err
					}
					for _, value := range chunk {
						sum = sum<<8 ^ (sum + uint32(value))
					}
					done += uint64(len(chunk))
				}
				if checksum != 0 && ^sum != checksum {
					payloadBad = true
					break
				}
				records = append(records, journalRecord{target, offset, size})
			}
			offset, actual = j.advance(offset, size), actual+size
		}
		if payloadBad {
			if !tail || j.distance(start, txnOffset) < declared {
				return nil, bad("journal committed payload checksum")
			}
			p.records = p.records[:txnIndex]
			p.report = txnReport
			position = txnOffset
			break
		}
		if actual != used {
			return nil, bad("journal transaction byte accounting")
		}
		if len(p.records)+len(records) > maxJournalSectors {
			return nil, filesystem.ErrLimit
		}
		p.records = append(p.records, records...)
		p.report.BlockLists++
		if flags&2 != 0 {
			p.report.Transactions++
		}
		if tail {
			p.report.ExtraBlockLists++
		}
		sequence = nextSequence
		position, consumed = j.advance(position, used), consumed+used
	}
	if consumed >= capacity {
		return nil, bad("journal replay exhausted ring without end sentinel")
	}
	p.report.RecoveredEnd = position
	return p, nil
}

// ReplayJournal applies native-qualified current internal journal records to an
// exclusively owned UNPUBLISHED copy. It does not repair filesystem trees or
// declare the volume clean. On any error discard the entire copy. imageedit
// adds complete ownership validation and no-overwrite publication.
func ReplayJournal(ctx context.Context, disk MutableSource) (JournalReplayReport, error) {
	p, err := planJournal(ctx, disk)
	if err != nil {
		return JournalReplayReport{}, err
	}
	// Last writes win, including partial overlaps and ring-wrapped payloads.
	// Store log offsets instead of retaining file or journal data in memory.
	sectors := map[uint64]uint64{}
	for _, r := range p.records {
		for off := uint64(0); off < r.size; off += 512 {
			if err := ctx.Err(); err != nil {
				return p.report, err
			}
			sectors[r.target+off] = p.j.advance(r.offset, off)
			if len(sectors) > maxJournalSectors {
				return p.report, filesystem.ErrLimit
			}
		}
	}
	keys := make([]uint64, 0, len(sectors))
	for target := range sectors {
		keys = append(keys, target)
	}
	sort.Slice(keys, func(a, b int) bool { return keys[a] < keys[b] })
	buffer := make([]byte, 64<<10)
	for i := 0; i < len(keys); {
		if err := ctx.Err(); err != nil {
			return p.report, err
		}
		end := i + 1
		for end < len(keys) && end-i < len(buffer)/512 && keys[end] == keys[end-1]+512 && sectors[keys[end]] == p.j.advance(sectors[keys[end-1]], 512) {
			end++
		}
		chunk := buffer[:(end-i)*512]
		if err = p.j.read(disk, chunk, sectors[keys[i]]); err != nil {
			return p.report, err
		}
		if err = journalWrite(disk, chunk, keys[i]); err != nil {
			return p.report, err
		}
		i = end
	}
	p.report.Sectors = uint64(len(keys))
	if p.j.Start != p.report.RecoveredEnd || p.j.End != p.report.RecoveredEnd {
		header := append([]byte(nil), p.j.header...)
		p.j.order.PutUint64(header[8:], p.report.RecoveredEnd)
		p.j.order.PutUint64(header[16:], p.report.RecoveredEnd)
		clear(header[36:40])
		p.j.order.PutUint32(header[36:], journalChecksum(header[:44]))
		if err = ctx.Err(); err != nil {
			return p.report, err
		}
		if err = journalWrite(disk, header, p.j.Offset); err != nil {
			return p.report, err
		}
	}
	return p.report, nil
}

func journalWrite(disk MutableSource, data []byte, offset uint64) error {
	n, err := disk.WriteAt(data, int64(offset))
	if n != len(data) && err == nil {
		return io.ErrShortWrite
	}
	return err
}

// ValidateJournalReplay checks the selected current internal log without
// writing. It does not assert that the unreplayed filesystem graph is valid.
func ValidateJournalReplay(ctx context.Context, source block.Source) (JournalReplayReport, error) {
	p, err := planJournal(ctx, source)
	if err != nil {
		return JournalReplayReport{}, err
	}
	return p.report, nil
}

// RecoverJournal replays an exclusively owned unpublished copy, then validates
// the complete recovered allocation/tree/link graph before marking the primary
// volume header unmounted. It preserves native metadata clocks and history.
// It cannot recover unjournaled file data, repair trees, or salvage bad committed
// transactions. After any failure discard the entire copy.
func RecoverJournal(ctx context.Context, disk MutableSource) (JournalReplayReport, error) {
	report, err := ReplayJournal(ctx, disk)
	if err != nil {
		return report, err
	}
	v, err := Open(disk)
	if err != nil {
		return report, err
	}
	if !v.Journaled {
		return report, fs.ErrInvalid
	}
	m := &mutation{ctx: ctx, disk: readOnlyMutation{disk}, v: v, header: make([]byte, 512), trees: map[uint32]*mutableTree{}}
	if err = block.ReadFull(disk, m.header, 1024); err != nil {
		return report, err
	}
	// Recovery skips only the unmounted-bit requirement. Inconsistent/unknown
	// flags, graph ownership, both structural headers and empty catalog-backed
	// journal checks are exactly the same as ordinary mutation admission.
	if err = m.admitProfile(true); err != nil {
		return report, err
	}
	if err = m.loadCatalog(); err != nil {
		return report, err
	}
	be.PutUint32(m.header[4:], be.Uint32(m.header[4:])|0x100)
	if err = ctx.Err(); err != nil {
		return report, err
	}
	if err = journalWrite(disk, m.header, 1024); err != nil {
		return report, err
	}
	return report, ValidateMutation(ctx, disk)
}
