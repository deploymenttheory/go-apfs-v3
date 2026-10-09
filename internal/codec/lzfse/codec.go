// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2015-2016, Apple Inc. All rights reserved.
// Copyright (c) 2026 Deployment Theory.

// Package lzfse translates Apple's LZFSE and LZVN decoders. Destinations belong
// to the caller and bound all decoded output. See LICENSE and docs/sources.json.
package lzfse

// Decode decodes a complete LZFSE stream. Discard partial output on error.
func Decode(dst, src []byte) (int, error) {
	d := decoder{dst: dst, src: src}
	err := d.decode()
	return d.n, err
}

// DecodeLZVN decodes a complete raw LZVN stream.
func DecodeLZVN(dst, src []byte) (int, error) {
	d := lzvnDecoder{dst: dst, src: src}
	d.decode()
	if !d.endOfStream || d.in != len(src) {
		return d.out, corrupt("incomplete LZVN stream")
	}
	return d.out, nil
}
