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
// Modified 2026-10-12: Go adaptation of getbsdattr/catrec_update lock-state
// reconciliation and hfs_set_bsd_flags Finder hidden-bit mirroring.
// Exact source revision/hashes: docs/sources.json. License: LICENSES/APSL-2.0.txt.
package hfsplus

// catalogBSDFlags follows getbsdattr: a file's catalog lock is authoritative
// over BSD immutable bits, and Finder invisibility supplies UF_HIDDEN.
func catalogBSDFlags(record []byte) uint32 {
	flags := uint32(record[40])<<16 | uint32(record[41])
	if be.Uint16(record) == 2 {
		const immutable = uint32(0x20002)
		if be.Uint16(record[2:])&1 == 0 {
			flags &^= immutable
		} else if flags&immutable == 0 {
			flags |= 2
		}
	}
	if be.Uint16(record[56:])&0x4000 != 0 {
		flags |= 0x8000
	}
	return flags
}

// setCatalogBSDFlags includes catrec_update's file lock synchronization.
// Directories retain their unrelated catalog flags.
func setCatalogBSDFlags(record []byte, flags uint32) {
	record[40], record[41] = byte(flags>>16), byte(flags)
	if be.Uint16(record) == 2 {
		stored := be.Uint16(record[2:]) &^ uint16(1)
		if flags&0x20002 != 0 {
			stored |= 1
		}
		be.PutUint16(record[2:], stored)
	}
	record[56] &^= 0x40
	if flags&0x8000 != 0 {
		record[56] |= 0x40
	}
}
