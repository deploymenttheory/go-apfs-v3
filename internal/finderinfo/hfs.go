/*
 * Copyright (c) 2004-2020 Apple Inc. All rights reserved.
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
// Modified 2026-10-10: shared by native readers and workspace edits.
// Originally adapted 2026-10-09: Go adaptation of hfs_zero_hidden_fields and the
// FinderInfo portion of hfs_vnop_getxattr, replacing kernel objects with byte
// slices. Source revision and file hashes: docs/sources.json.
// Source: https://github.com/deploymenttheory/go-apfs-v3/blob/main/internal/finderinfo/hfs.go
// License: LICENSES/APSL-2.0.txt.
// Package finderinfo contains Apple's public FinderInfo value rules.
package finderinfo

import "bytes"

// HFS returns the public HFS+ FinderInfo value after excluding kernel-owned
// document ID, date-added, generation and symlink type/creator fields.
// The caller supplies exactly 32 bytes and a native POSIX object mode.
func HFS(data []byte, mode uint32) []byte {
	info := bytes.Clone(data)
	switch mode & 0170000 {
	case 0100000, 0120000, 0040000:
		clear(info[16:24])
		clear(info[28:32])
	}
	if mode&0170000 == 0120000 {
		clear(info[:8])
	}
	return info
}
