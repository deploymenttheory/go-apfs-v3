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
// Modified 2026-10-13: Go adaptation of kauth filesec layouts, canonical disk
// byte order and kauth_acl_inherit for ordinary creation with no initial ACL.
// Bounded owned byte slices replace kernel allocation and vnode discovery.
// Source revision/hashes: docs/sources.json. License: LICENSES/APSL-2.0.txt.

// Package filesec preserves Darwin security records and composes inherited
// ACLs. GUIDs and rights remain opaque; it does not map users or authorize edits.
package filesec

import (
	"encoding/binary"
	"fmt"
	"io/fs"
	"math"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const (
	Attribute = "com.apple.system.Security"
	Magic     = 0x012cc16d
	MaxSize   = 44 + 128*24
	Inherited = 1 << 4
	File      = 1 << 5
	Directory = 1 << 6
	Limit     = 1 << 7
	Only      = 1 << 8
)

var be = binary.BigEndian

// Validate bounds the exact network-order kauth_filesec, including the distinct
// NOACL sentinel and explicit empty ACL. Numeric ownership is separate from the
// opaque owner/group GUIDs. Unknown rights and private flags are retained.
func Validate(value []byte) error {
	if len(value) < 44 || len(value) > MaxSize || be.Uint32(value) != Magic {
		return fmt.Errorf("filesec bounds or magic: %w", filesystem.ErrCorrupt)
	}
	count := be.Uint32(value[36:])
	if count == math.MaxUint32 {
		if len(value) != 44 {
			return fmt.Errorf("filesec NOACL length: %w", filesystem.ErrCorrupt)
		}
		return nil
	}
	if count > 128 || len(value) != 44+int(count)*24 {
		return fmt.Errorf("filesec ACL entry count: %w", filesystem.ErrCorrupt)
	}
	return nil
}

// Inherit composes the ACL for an ordinary new object (initial ACL == NULL in
// kauth_acl_inherit). Only matching ACEs are copied, in native order. New filesec
// owner/group GUIDs default to null through vnode_setattr_fallback; the parent's
// ACL flags and identity GUIDs are not inherited. A nil result means no ACL.
func Inherit(parent []byte, directory bool) ([]byte, error) {
	if len(parent) == 0 {
		return nil, nil
	}
	if err := Validate(parent); err != nil {
		return nil, err
	}
	count := be.Uint32(parent[36:])
	if count == math.MaxUint32 {
		return nil, nil
	}
	match := uint32(File)
	if directory {
		match = Directory
	}
	result := make([]byte, 44)
	be.PutUint32(result, Magic)
	for n := uint32(0); n < count; n++ {
		ace := parent[44+n*24 : 44+(n+1)*24]
		flags := be.Uint32(ace[16:])
		if flags&match == 0 {
			continue
		}
		flags = (flags | Inherited) &^ Only
		if flags&Limit != 0 || !directory {
			flags &^= File | Directory | Limit | Only
		}
		result = append(result, ace...)
		be.PutUint32(result[len(result)-8:], flags)
	}
	if len(result) == 44 {
		return nil, nil
	}
	be.PutUint32(result[36:], uint32((len(result)-44)/24))
	return result, nil
}

// ChownMode follows vnode_authattr's ordinary chown path, including assignment
// of unchanged numeric ownership and superuser calls. A simultaneous explicit
// mode assignment belongs to copy/attribute preservation, not ordinary chown.
func ChownMode(mode uint32) uint32 { return mode &^ 06000 }

func ValidateActor(actor filesystem.Observation[uint32]) error {
	if actor.State != filesystem.Uncaptured && actor.State != filesystem.Present ||
		actor.State == filesystem.Present && actor.Value == math.MaxUint32 {
		return fs.ErrInvalid
	}
	return nil
}

// WriteMode follows Darwin's set-ID write/truncate distinction. An ordinary
// host UID cannot supply the logical actor of an offline image operation.
func WriteMode(mode uint32, actor filesystem.Observation[uint32]) (uint32, error) {
	if err := ValidateActor(actor); err != nil {
		return mode, err
	}
	if mode&06000 == 0 {
		return mode, nil
	}
	if actor.State != filesystem.Present {
		return mode, fmt.Errorf("set-ID write requires an explicit logical UID: %w", filesystem.ErrUnsupported)
	}
	if actor.Value != 0 {
		mode &^= 06000
	}
	return mode, nil
}
