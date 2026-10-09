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
// Modified 2026-10-09: Go adaptation of cat_lookup/cat_resolvelink indirection.
// Source revision and hashes: docs/sources.json. License: LICENSES/APSL-2.0.txt.
package hfsplus

import (
	"context"
	"fmt"
	"strconv"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const privateDirectory = "\x00\x00\x00\x00HFS+ Private Data"
const directoryLinks = ".HFS+ Private Directory Data\r"

func (v *Volume) findPrivateDirectory() error {
	// Read the root record without requiring a clean volume: structural inspection
	// remains possible when logical file operations require journal replay.
	err := v.catalog.records(context.Background(), 1, func(r treeRecord) error {
		if len(r.value) >= 88 && be.Uint16(r.value) == 1 && be.Uint32(r.value[8:]) == 2 {
			v.rootCreated = be.Uint32(r.value[12:])
		}
		return nil
	})
	if err != nil {
		return err
	}
	return v.catalog.records(context.Background(), 2, func(r treeRecord) error {
		if len(r.key) < 8 {
			return bad("private directory key")
		}
		name, err := unicodeName(r.key[6:])
		if err != nil || name != privateDirectory {
			return err
		}
		if v.privateID != 0 || len(r.value) < 88 || be.Uint16(r.value) != 1 {
			return bad("hard link private directory")
		}
		v.privateID, v.privateCreated = be.Uint32(r.value[8:]), be.Uint32(r.value[12:])
		return nil
	})
}

// The Finder type alone is insufficient: TN1150 and Apple's cat_lookup also
// require the creation date to match the root or private metadata directory.
func (v *Volume) resolveLink(ctx context.Context, b []byte) ([]byte, error) {
	if len(b) < 88 {
		return nil, bad("catalog object length")
	}
	if be.Uint16(b) != 2 {
		return b, nil
	}
	if len(b) != 248 {
		return nil, bad("catalog file length")
	}
	created := be.Uint32(b[12:])
	if created != v.rootCreated && (v.privateID == 0 || created != v.privateCreated) {
		return b, nil
	}
	magic := string(b[48:56])
	if magic == "fdrpMACS" && be.Uint16(b[2:])&0x20 != 0 {
		return nil, fmt.Errorf("HFS+ directory hard link: %w", filesystem.ErrUnsupported)
	}
	if magic != "hlnkhfs+" {
		return b, nil
	}
	if v.privateID == 0 || be.Uint32(b[44:]) == 0 {
		return nil, bad("hard link reference")
	}
	name := "iNode" + strconv.FormatUint(uint64(be.Uint32(b[44:])), 10)
	var inode []byte
	err := v.catalog.records(ctx, v.privateID, func(r treeRecord) error {
		if len(r.key) < 8 {
			return bad("inode catalog key")
		}
		n, err := unicodeName(r.key[6:])
		if err != nil || n != name {
			return err
		}
		if inode != nil || len(r.value) != 248 || be.Uint16(r.value) != 2 || string(r.value[48:56]) == "hlnkhfs+" || be.Uint32(r.value[8:]) == 0 {
			return bad("hard link inode record")
		}
		inode = r.value
		return nil
	})
	if err != nil {
		return nil, err
	}
	if inode == nil {
		return nil, bad("dangling hard link reference")
	}
	return inode, nil
}
