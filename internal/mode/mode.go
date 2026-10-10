// Package mode translates Apple's setmode/getmode command grammar to Go.
// Adapted from apple-oss-distributions/Libc, gen/FreeBSD/setmode.c,
// revision 71bbe350ab79eef58113991d817ccc6165061a64.
//
// Copyright (c) 1989, 1993, 1994 The Regents of the University of California.
// All rights reserved.
// This code is derived from software contributed to Berkeley by Dave Borman
// at Cray Research, Inc.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//  1. Redistributions of source code must retain the above copyright notice,
//     this list of conditions and the following disclaimer.
//  2. Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//  4. Neither the name of the University nor the names of its contributors may
//     be used to endorse or promote products derived from this software without
//     specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS “AS IS” AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
package mode

import (
	"io/fs"
	"strconv"
	"strings"
)

type instruction struct {
	op        byte
	who, bits uint32
	action    byte
}
type Program struct{ commands []instruction }

// Parse takes an explicit logical umask. It never reads or changes host umask.
func Parse(s string, mask uint32) (Program, error) {
	p := Program{}
	if s == "" || len(s) > 4096 || mask > 0777 {
		return p, fs.ErrInvalid
	}
	mask = ^mask
	add := func(op byte, who, bits uint32, action byte) {
		if op == '=' {
			clear := who
			if clear == 0 {
				clear = 07777
			}
			p.commands = append(p.commands, instruction{op: '-', bits: clear})
			op = '+'
		}
		if op == '+' || op == '-' || op == 'X' {
			if who != 0 {
				bits &= who
			} else {
				bits &= mask
			}
			p.commands = append(p.commands, instruction{op: op, bits: bits})
			return
		}
		filter := ^uint32(0)
		if who == 0 {
			who = 0777
			filter = mask
		}
		p.commands = append(p.commands, instruction{op: op, who: who, bits: filter, action: action})
	}
	if s[0] >= '0' && s[0] <= '9' {
		v, err := strconv.ParseUint(s, 8, 32)
		if err != nil || v > 07777 {
			return p, fs.ErrInvalid
		}
		add('=', 07777, uint32(v), 0)
		return p, nil
	}
	i := 0
	for {
		who := uint32(0)
		for i < len(s) && strings.ContainsRune("augo", rune(s[i])) {
			switch s[i] {
			case 'a':
				who |= 07777
			case 'u':
				who |= 04700
			case 'g':
				who |= 02070
			case 'o':
				who |= 00007
			}
			i++
		}
		for {
			if i >= len(s) || !strings.ContainsRune("+-=", rune(s[i])) {
				return Program{}, fs.ErrInvalid
			}
			op := s[i]
			i++
			perm, x := uint32(0), uint32(0)
			equalDone := false
			for i < len(s) && strings.ContainsRune("rstwXxugo", rune(s[i])) {
				c := s[i]
				i++
				switch c {
				case 'r':
					perm |= 0444
				case 'w':
					perm |= 0222
				case 'x':
					perm |= 0111
				case 'X':
					x = 0111
				case 's':
					if who == 0 || who & ^uint32(0007) != 0 {
						perm |= 06000
					}
				case 't':
					if who == 0 || who & ^uint32(0007) != 0 {
						perm |= 01000
					}
				case 'u', 'g', 'o':
					if perm != 0 {
						add(op, who, perm, 0)
						perm = 0
					}
					if op == '=' {
						equalDone = true
					}
					if op == '+' && x != 0 {
						add('X', who, x, 0)
						x = 0
					}
					add(c, who, 0, op)
				}
			}
			if perm != 0 || (op == '=' && !equalDone) {
				add(op, who, perm, 0)
			}
			if x != 0 {
				add('X', who, x, 0)
			}
			if i == len(s) {
				return p, nil
			}
			if s[i] == ',' {
				i++
				break
			}
		}
	}
}
func (p Program) Apply(original uint32) uint32 {
	result := original
	for _, c := range p.commands {
		switch c.op {
		case '+':
			result |= c.bits
		case '-':
			result &^= c.bits
		case 'X':
			if original&(0040000|0111) != 0 {
				result |= c.bits
			}
		case 'u', 'g', 'o':
			shift := uint(0)
			switch c.op {
			case 'u':
				shift = 6
			case 'g':
				shift = 3
			}
			value := (result >> shift) & 7
			for _, target := range []uint{0, 3, 6} {
				if c.who&(4<<target) == 0 {
					continue
				}
				if c.action == '-' || c.action == '=' {
					clear := value
					if c.action == '=' {
						clear = 7
					}
					result &^= (clear << target) & c.bits
				}
				if c.action == '+' || c.action == '=' {
					result |= (value << target) & c.bits
				}
			}
		}
	}
	return result
}
