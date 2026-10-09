// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2015-2016, Apple Inc. All rights reserved.
// Copyright (c) 2026 Deployment Theory.
//
// Finite State Entropy coding, after Apple's reference implementation
// (lzfse_fse.h, lzfse_fse.c). See LICENSE in this directory.

package lzfse

import (
	"encoding/binary"
	"math/bits"
)

// FSE is Jarek Duda's tANS: each stream symbol is coded by a state machine
// whose tables are built from a normalised frequency histogram.

// inStream reads an FSE-coded stream backwards, from the end of its payload
// towards its start, holding 56 to 63 bits between refills.
type inStream struct {
	accum      uint64
	accumNBits int32
}

// init primes the stream from the bytes ending at *pos, which must not move
// below start. n is the encoder's final accumNBits, in [-7, 0].
func (s *inStream) init(n int32, src []byte, pos *int, start int) bool {
	if n != 0 {
		if *pos < start+8 {
			return false
		}
		*pos -= 8
		s.accum = binary.LittleEndian.Uint64(src[*pos:])
		s.accumNBits = n + 64
	} else {
		if *pos < start+7 {
			return false
		}
		*pos -= 7
		s.accum = uint64(binary.LittleEndian.Uint32(src[*pos:])) |
			uint64(binary.LittleEndian.Uint16(src[*pos+4:]))<<32 |
			uint64(src[*pos+6])<<48
		s.accumNBits = n + 56
	}
	// The encoder zeroes the bits above those it wrote; anything else is a
	// corrupt stream.
	return s.accumNBits >= 56 && s.accumNBits < 64 && s.accum>>uint(s.accumNBits) == 0
}

// flush refills the accumulator to 56-63 bits from the bytes before *pos.
func (s *inStream) flush(src []byte, pos *int, start int) bool {
	nbits := (63 - s.accumNBits) &^ 7
	p := *pos - int(nbits>>3)
	if p < start {
		return false
	}
	*pos = p
	// The reference loads 8 bytes here. Near the start of the buffer fewer may
	// exist past p, but only the low nbits are kept, so read what is there.
	var incoming uint64
	if p+8 <= len(src) {
		incoming = binary.LittleEndian.Uint64(src[p:])
	} else {
		var tmp [8]byte
		copy(tmp[:], src[p:])
		incoming = binary.LittleEndian.Uint64(tmp[:])
	}
	s.accum = s.accum<<uint(nbits) | maskLSB64(incoming, nbits)
	s.accumNBits += nbits
	return true
}

// pull removes and returns the top n bits.
func (s *inStream) pull(n int32) uint64 {
	s.accumNBits -= n
	result := s.accum >> uint(s.accumNBits)
	s.accum = maskLSB64(s.accum, s.accumNBits)
	return result
}

// maskLSB64 keeps the low n bits of x, for n in [0, 64].
func maskLSB64(x uint64, n int32) uint64 {
	if n >= 64 {
		return x
	}
	return x & (1<<uint(n) - 1)
}

// decoderEntry is one state's row of an FSE symbol decoder table.
type decoderEntry struct {
	k      int8  // bits to read
	symbol uint8 // symbol emitted
	delta  int16 // next-state base
}

// valueDecoderEntry is one state's row of an FSE value decoder table: the
// symbol is a base value plus valueBits extra bits read with the state bits.
type valueDecoderEntry struct {
	totalBits uint8 // state bits + value bits
	valueBits uint8 // extra value bits
	delta     int16 // next-state base
	vbase     int32 // value base
}

// decode reads one symbol at state *state.
func fseDecode(state *uint16, table []decoderEntry, in *inStream) uint8 {
	e := table[*state]
	*state = uint16(e.delta) + uint16(in.pull(int32(e.k)))
	return e.symbol
}

// valueDecode reads one base+extra-bits value at state *state.
func fseValueDecode(state *uint16, table []valueDecoderEntry, in *inStream) int32 {
	e := table[*state]
	stateAndValueBits := uint32(in.pull(int32(e.totalBits)))
	*state = uint16(int32(e.delta) + int32(stateAndValueBits>>e.valueBits))
	return e.vbase + int32(maskLSB64(uint64(stateAndValueBits), int32(e.valueBits)))
}

// clz32 counts leading zero bits, as __builtin_clz.
func clz32(x uint32) int { return bits.LeadingZeros32(x) }

// checkFreq reports whether a frequency table's sum fits nstates.
func checkFreq(freq []uint16, nstates int) bool {
	sum := 0
	for _, f := range freq {
		sum += int(f)
	}
	return sum <= nstates
}

// initDecoderTable builds a symbol decoder table, or reports false when the
// frequencies overrun nstates.
func initDecoderTable(nstates int, freq []uint16, t []decoderEntry) bool {
	nclz := clz32(uint32(nstates))
	sum := 0
	n := 0
	for i, fv := range freq {
		f := int(fv)
		if f == 0 {
			continue
		}
		sum += f
		if sum > nstates {
			return false
		}
		k := clz32(uint32(f)) - nclz
		j0 := (2*nstates)>>uint(k) - f
		for j := range f {
			if j < j0 {
				t[n] = decoderEntry{k: int8(k), symbol: uint8(i), delta: int16((f+j)<<uint(k) - nstates)}
			} else {
				t[n] = decoderEntry{k: int8(k - 1), symbol: uint8(i), delta: int16((j - j0) << uint(k-1))}
			}
			n++
		}
	}
	return true
}

// initValueDecoderTable builds a value decoder table. The caller has checked
// the frequencies fit nstates.
func initValueDecoderTable(nstates int, freq []uint16, vbits []uint8, vbase []int32, t []valueDecoderEntry) {
	nclz := clz32(uint32(nstates))
	n := 0
	for i, fv := range freq {
		f := int(fv)
		if f == 0 {
			continue
		}
		k := clz32(uint32(f)) - nclz
		j0 := (2*nstates)>>uint(k) - f
		for j := range f {
			e := valueDecoderEntry{valueBits: vbits[i], vbase: vbase[i]}
			if j < j0 {
				e.totalBits = uint8(k) + e.valueBits
				e.delta = int16((f+j)<<uint(k) - nstates)
			} else {
				e.totalBits = uint8(k-1) + e.valueBits
				e.delta = int16((j - j0) << uint(k-1))
			}
			t[n] = e
			n++
		}
	}
}
