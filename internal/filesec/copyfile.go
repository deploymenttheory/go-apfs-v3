/*
 * Copyright (c) 2004-2024 Apple, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */
// SPDX-License-Identifier: APSL-2.0
// Modified 2026-10-13: bounded Go adaptation of copyfile_security COPYFILE_ACL
// composition. Network-order byte slices replace filesec/acl APIs; numeric
// ownership, process authorization and temporary permission relaxation are
// handled separately. Source revision/hashes: docs/sources.json.
package filesec

import (
	"bytes"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"math"
)

// CopyACL composes COPYFILE_ACL's source direct entries followed by destination
// inherited entries. Source inheritance belongs to its original parent and is
// not copied. Explicit empty ACLs remain distinct from an absent ACL. Numeric
// ownership and mode are supplied separately by cp's setfile operation.
func CopyACL(source, destination []byte) ([]byte, error) {
	for _, value := range [][]byte{source, destination} {
		if value != nil {
			if err := Validate(value); err != nil {
				return nil, err
			}
		}
	}
	hasACL := func(value []byte) bool { return value != nil && be.Uint32(value[36:]) != math.MaxUint32 }
	result := make([]byte, 44)
	be.PutUint32(result, Magic)
	if source != nil {
		copy(result[4:36], source[4:36])
	}
	if !hasACL(source) && !hasACL(destination) {
		if bytes.Equal(result[4:36], make([]byte, 32)) {
			return nil, nil
		}
		be.PutUint32(result[36:], math.MaxUint32)
		return result, nil
	}
	for n, value := range [][]byte{source, destination} {
		if !hasACL(value) {
			continue
		}
		for off := 44; off < len(value); off += 24 {
			inherited := be.Uint32(value[off+16:])&Inherited != 0
			if (n == 0 && inherited) || (n == 1 && !inherited) {
				continue
			}
			if len(result)+24 > MaxSize {
				return nil, filesystem.ErrLimit
			}
			result = append(result, value[off:off+24]...)
		}
	}
	be.PutUint32(result[36:], uint32((len(result)-44)/24))
	return result, nil
}
