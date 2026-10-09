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
// Modified 2026-10-09: Go adaptation of hfs_zero_hidden_fields and the
// FinderInfo portion of hfs_vnop_getxattr, replacing kernel objects with byte
// slices. Source revision and file hashes: docs/sources.json.
// Source: https://github.com/deploymenttheory/go-apfs-v3/blob/main/hfsplus/finderinfo.go
// License: LICENSES/APSL-2.0.txt.
package hfsplus

import "bytes"

// finderInfo returns the public xattr view. Catalog storage keeps document ID,
// date added and generation count in reserved fields which macOS does not expose
// through this attribute. The source bytes remain untouched for preservation.
func finderInfo(record []byte) []byte {
	info := bytes.Clone(record[48:80])
	mode := be.Uint16(record[42:]) & 0170000
	if mode == 0100000 || mode == 0120000 || mode == 0040000 {
		clear(info[16:24])
		clear(info[28:32])
	}
	if mode == 0120000 {
		clear(info[:8])
	}
	return info
}
