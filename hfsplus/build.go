/*
 * Copyright (c) 1999-2023 Apple Inc. All rights reserved.
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
// Modified 2026-10-10: Go adaptation of makehfs volume/B-tree initialization.
// Bounded bulk construction and logical-reader payloads replace device mutation.
// Source revision/hashes: docs/sources.json. License: LICENSES/APSL-2.0.txt.
package hfsplus

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/buildsize"
	"github.com/deploymenttheory/go-apfs-v3/internal/finderinfo"
	"github.com/deploymenttheory/go-apfs-v3/internal/names"
)

// BuildOptions defines a fresh, clean, nonjournaled HFS+ or HFSX volume.
// Capacity is the volume size, rounded up to 4096 bytes; zero sizes it automatically.
// Time supplies the volume construction clock, independently of file timestamps.
// VolumeID is the native eight-byte identifier. A zero value derives it from the
// canonical build records and payload hashes. Source readers must remain immutable.
type BuildOptions struct {
	Name          string
	CaseSensitive bool
	Capacity      int64
	Time          time.Time
	VolumeID      [8]byte
}

type buildObject struct {
	source         uint64
	id             uint32
	node           filesystem.Node
	parent         uint32
	name           string
	entries        []filesystem.DirEntry
	directories    uint32
	aliases        []buildAlias
	firstAlias     uint32
	data, resource buildFork
	finder         []byte
	attrs          []buildAttribute
}
type buildAlias struct {
	parent uint32
	name   string
	id     uint32
}
type buildAttribute struct {
	name   string
	inline []byte
	fork   buildFork
}
type buildFork struct {
	size         int64
	start, count uint32
	source       uint64
	attr         string
	literal      []byte
}
type buildPart struct {
	offset int64
	data   []byte
	fork   *buildFork
}

// Layout borrows its reader. Planning validates names, metadata and geometry;
// Write streams payloads and zero-filled free space without buffering file data.
// The caller owns publication and must discard any output on error.
type Layout struct {
	reader        filesystem.Reader
	options       BuildOptions
	size          int64
	parts         []buildPart
	objects       []*buildObject
	nextID        uint32
	privateID     uint32
	metadataBytes int64
}

func (p *Layout) Size() int64 { return p.size }

// Plan builds a bounded catalog and allocation plan. Native inode numbers are
// freshly assigned; regular-file aliases retain their relationships.
func Plan(ctx context.Context, r filesystem.Reader, o BuildOptions) (*Layout, error) {
	if r == nil || o.Time.IsZero() || o.Capacity < 0 || o.Capacity > 1<<40 {
		return nil, fs.ErrInvalid
	}
	if r.NameRules().Format != "HFS+" {
		return nil, fmt.Errorf("HFS builder requires an HFS logical tree: %w", filesystem.ErrUnsupported)
	}
	name, err := names.Stored(o.Name, "HFS+")
	if err != nil {
		return nil, fmt.Errorf("volume name: %w", err)
	}
	o.Name = name
	if _, err = buildDate(o.Time); err != nil {
		return nil, err
	}
	p := &Layout{reader: r, options: o, nextID: 16}
	seen := map[uint64]*buildObject{}
	entryCount := 0
	var visit func(uint64, uint32, string, int) error
	visit = func(id uint64, parent uint32, name string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entryCount++
		if err := p.reserveMetadata(int64(512 + len(name)*4)); err != nil {
			return err
		}
		if entryCount > 100000 || depth > 256 {
			return filesystem.ErrLimit
		}
		if old := seen[id]; old != nil {
			if old.node.Metadata.Mode.Value&0170000 != 0100000 {
				return fmt.Errorf("nonregular hard link: %w", filesystem.ErrUnsupported)
			}
			if len(old.aliases) == 0 {
				old.firstAlias = p.nextID
				p.nextID++
			}
			old.aliases = append(old.aliases, buildAlias{parent, name, p.nextID})
			p.nextID++
			return nil
		}
		n, err := r.Stat(ctx, id)
		if err != nil {
			return err
		}
		if n.Identity.Object != id {
			return filesystem.ErrCorrupt
		}
		obj := &buildObject{source: id, node: n, parent: parent, name: name, id: p.nextID}
		p.nextID++
		if parent == 1 {
			obj.id = 2
		}
		if err = p.validateObject(ctx, obj); err != nil {
			return fmt.Errorf("%q: %w", name, err)
		}
		seen[id] = obj
		p.objects = append(p.objects, obj)
		if n.Metadata.Mode.Value&0170000 != 0040000 {
			return nil
		}
		err = r.ReadDir(ctx, id, func(e filesystem.DirEntry) error {
			if len(obj.entries) >= 100000 {
				return filesystem.ErrLimit
			}
			stored, err := names.Stored(e.Name, "HFS+")
			if err != nil {
				return err
			}
			// Conversion would change a source's filename: cross-format conversion is explicit future work.
			if stored != e.Name {
				return fmt.Errorf("filename %q requires HFS decomposition: %w", e.Name, filesystem.ErrUnsupported)
			}
			obj.entries = append(obj.entries, e)
			return nil
		})
		if err != nil {
			return err
		}
		sort.Slice(obj.entries, func(i, j int) bool {
			return names.HFS(obj.entries[i].Name, o.CaseSensitive) < names.HFS(obj.entries[j].Name, o.CaseSensitive)
		})
		for i, e := range obj.entries {
			if i > 0 && names.HFS(e.Name, o.CaseSensitive) == names.HFS(obj.entries[i-1].Name, o.CaseSensitive) {
				return fmt.Errorf("HFS filename collision %q: %w", e.Name, filesystem.ErrConflict)
			}
			if names.HFS(e.Name, o.CaseSensitive) == "" || parent == 1 && (names.HFS(e.Name, o.CaseSensitive) == names.HFS(strings.ReplaceAll(privateDirectory, "\x00", "\u2400"), o.CaseSensitive) || e.Name == directoryLinks) {
				return fmt.Errorf("reserved HFS name: %w", filesystem.ErrUnsupported)
			}
			if err = visit(e.Object, obj.id, e.Name, depth+1); err != nil {
				return err
			}
			if seen[e.Object].node.Metadata.Mode.Value&0170000 == 0040000 {
				obj.directories++
			}
		}
		return nil
	}
	if err = visit(r.Root(), 1, name, 0); err != nil {
		return nil, err
	}
	if p.objects[0].node.Metadata.Mode.Value&0170000 != 0040000 {
		return nil, fs.ErrInvalid
	}
	for _, obj := range p.objects {
		if len(obj.aliases) > 0 {
			p.privateID = p.nextID
			p.nextID++
			break
		}
	}
	if err = p.arrange(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Layout) reserveMetadata(n int64) error {
	if n < 0 || n > (64<<20)-p.metadataBytes {
		return filesystem.ErrLimit
	}
	p.metadataBytes += n
	return nil
}

func buildDate(t time.Time) (uint32, error) {
	s := t.Unix() + 2082844800
	if t.Nanosecond() != 0 || s < 2082844800 || s > math.MaxUint32 {
		return 0, fmt.Errorf("HFS timestamp %s must be whole seconds in 1970–2040: %w", t, filesystem.ErrUnsupported)
	}
	return uint32(s), nil
}
func storedName(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, ":", "/"), "\u2400", "\x00")
}
func unicodeBytes(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2+2*len(u))
	be.PutUint16(b, uint16(len(u)))
	for i, c := range u {
		be.PutUint16(b[2+2*i:], c)
	}
	return b
}
func catalogKey(parent uint32, name string) []byte {
	u := unicodeBytes(storedName(name))
	b := make([]byte, 6+len(u))
	be.PutUint16(b, uint16(len(b)-2))
	be.PutUint32(b[2:], parent)
	copy(b[6:], u)
	return b
}
func attributeKey(id uint32, name string) []byte {
	u := unicodeBytes(name)
	b := make([]byte, 12+len(u))
	be.PutUint16(b, uint16(len(b)-2))
	be.PutUint32(b[4:], id)
	copy(b[12:], u)
	return b
}

func (p *Layout) validateObject(ctx context.Context, o *buildObject) error {
	n := o.node
	m := n.Metadata
	if m.Mode.State != filesystem.Present || m.UID.State != filesystem.Present || m.GID.State != filesystem.Present || m.BSDFlags.State != filesystem.Present {
		return fmt.Errorf("uncaptured metadata: %w", filesystem.ErrUnsupported)
	}
	for _, t := range []filesystem.Observation[time.Time]{m.BirthTime, m.ModifyTime, m.ChangeTime, m.AccessTime} {
		if t.State != filesystem.Present {
			return filesystem.ErrUnsupported
		}
		if _, err := buildDate(t.Value); err != nil {
			return err
		}
	}
	if m.Mode.Value > 0177777 || m.BSDFlags.Value & ^uint32(0xff00ff|0x8000) != 0 {
		return filesystem.ErrUnsupported
	}
	kind := m.Mode.Value & 0170000
	switch kind {
	case 0040000:
	case 0100000:
		v, err := p.reader.OpenRawData(ctx, o.source)
		if err != nil {
			return err
		}
		size := v.Size()
		if err = v.Close(); err != nil {
			return err
		}
		if size < 0 || size > 1<<40 {
			return filesystem.ErrLimit
		}
		if n.Compression.State == filesystem.Absent && uint64(size) != n.Size {
			return filesystem.ErrCorrupt
		}
		o.data = buildFork{size: size, source: o.source}
	case 0120000:
		target, err := p.reader.Readlink(ctx, o.source)
		if err != nil {
			return err
		}
		if len(target) == 0 || len(target) > 4096 || strings.ContainsRune(target, 0) {
			return filesystem.ErrUnsupported
		}
		o.data = buildFork{size: int64(len(target)), literal: []byte(target)}
	default:
		return fmt.Errorf("file type %#o: %w", kind, filesystem.ErrUnsupported)
	}
	if n.Compression.State != filesystem.Present && n.Compression.State != filesystem.Absent {
		return filesystem.ErrUnsupported
	}
	if n.Compression.State == filesystem.Present {
		switch n.Compression.Value.Type {
		case 1, 3, 4, 7, 8:
		default:
			return fmt.Errorf("compression type %d: %w", n.Compression.Value.Type, filesystem.ErrUnsupported)
		}
	}
	var attrs []string
	err := p.reader.ListAttributes(ctx, o.source, func(name string) error {
		if len(attrs) >= 4096 {
			return filesystem.ErrLimit
		}
		attrs = append(attrs, name)
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(attrs)
	for i, name := range attrs {
		if i > 0 && attrs[i-1] == name {
			return filesystem.ErrCorrupt
		}
		if !utf8.ValidString(name) || strings.ContainsRune(name, 0) || name == "" || len(utf16.Encode([]rune(name))) > 127 || strings.HasPrefix(name, "com.apple.fs.") {
			return fmt.Errorf("attribute %q: %w", name, filesystem.ErrUnsupported)
		}
		v, err := p.reader.OpenAttribute(ctx, o.source, name)
		if err != nil {
			return err
		}
		size := v.Size()
		if size < 0 || size > 1<<40 {
			return errors.Join(filesystem.ErrLimit, v.Close())
		}
		if err = p.reserveMetadata(int64(512+len(name)*4) + min(size, 1024)); err != nil {
			return errors.Join(err, v.Close())
		}
		a := buildAttribute{name: name, fork: buildFork{size: size, source: o.source, attr: name}}
		if name == filesystem.FinderInfo || size <= 1024 && name != filesystem.ResourceFork {
			if size > 1024 {
				return errors.Join(filesystem.ErrUnsupported, v.Close())
			}
			a.inline = make([]byte, int(size))
			if err = block.ReadFull(v, a.inline, 0); err != nil {
				return errors.Join(err, v.Close())
			}
		}
		if err = v.Close(); err != nil {
			return err
		}
		switch name {
		case filesystem.FinderInfo:
			if size != 32 || !bytes.Equal(a.inline, finderinfo.HFS(a.inline, m.Mode.Value)) {
				return fmt.Errorf("FinderInfo cannot be represented: %w", filesystem.ErrUnsupported)
			}
			if kind == 0100000 && string(a.inline[:8]) == "hlnkhfs+" {
				return fmt.Errorf("FinderInfo is reserved for HFS hard links: %w", filesystem.ErrUnsupported)
			}
			o.finder = a.inline
		case filesystem.ResourceFork:
			if kind != 0100000 || size == 0 {
				return fmt.Errorf("resource fork cannot be represented: %w", filesystem.ErrUnsupported)
			}
			o.resource = a.fork
		default:
			o.attrs = append(o.attrs, a)
		}
	}
	if (m.BSDFlags.Value&0x20 != 0) != (n.Compression.State == filesystem.Present) {
		return filesystem.ErrCorrupt
	}
	return nil
}

func (p *Layout) arrange(ctx context.Context) error {
	// Payloads are contiguous in a new volume. There is no in-place allocator or journal.
	var payloadBlocks uint64
	for _, o := range p.objects {
		for _, f := range []*buildFork{&o.data, &o.resource} {
			payloadBlocks += (uint64(f.size) + 4095) / 4096
		}
		for _, a := range o.attrs {
			if a.inline == nil {
				payloadBlocks += (uint64(a.fork.size) + 4095) / 4096
			}
		}
	}
	// Reserve metadata first after measuring the B-trees with placeholder extents.
	cat, attrs, files, dirs, err := p.records()
	if err != nil {
		return err
	}
	cmp := byte(0xcf)
	if p.options.CaseSensitive {
		cmp = 0xbc
	}
	catalog, err := buildTree(cat, 516, cmp, true)
	if err != nil {
		return err
	}
	attributes, err := buildTree(attrs, 266, 0, true)
	if err != nil {
		return err
	}
	extents, err := buildTree(nil, 10, 0, false)
	if err != nil {
		return err
	}
	metadataBlocks := uint64((len(catalog) + len(attributes) + len(extents)) / 4096)
	needed := payloadBlocks + metadataBlocks + 2
	total := (uint64(p.options.Capacity) + 4095) / 4096
	if total == 0 {
		total = max(uint64(2048), buildsize.AutomaticBlocks(needed, 0, buildsize.HFSPaddingBlocks))
	}
	var bitmapBlocks uint64
	for {
		if total < 2048 || total > 1<<28 {
			return fmt.Errorf("HFS build capacity must be between 8 MiB and 1 TiB: %w", filesystem.ErrLimit)
		}
		bitmapBlocks = ((total+7)/8 + 4095) / 4096
		required := needed + bitmapBlocks
		if p.options.Capacity == 0 {
			required = buildsize.AutomaticBlocks(required, 0, buildsize.HFSPaddingBlocks)
		}
		if required <= total {
			break
		}
		if p.options.Capacity != 0 {
			return fmt.Errorf("capacity requires at least %d bytes: %w", required*4096, filesystem.ErrLimit)
		}
		// The bitmap grows with capacity too. Retain all padding on each retry.
		total = required
	}
	p.size = int64(total * 4096)
	next := uint32(1 + bitmapBlocks)
	alloc := func(data []byte) buildFork {
		f := buildFork{size: int64(len(data)), start: next, count: uint32((len(data) + 4095) / 4096)}
		next += f.count
		return f
	}
	extFork := alloc(extents)
	catFork := alloc(catalog)
	attrFork := alloc(attributes)
	for _, o := range p.objects {
		ff := []*buildFork{&o.data, &o.resource}
		for i := range o.attrs {
			if o.attrs[i].inline == nil {
				ff = append(ff, &o.attrs[i].fork)
			}
		}
		for _, f := range ff {
			if f.size == 0 {
				continue
			}
			f.start = next
			f.count = uint32((f.size + 4095) / 4096)
			next += f.count
			p.parts = append(p.parts, buildPart{offset: int64(f.start) * 4096, fork: f})
		}
	}
	cat, attrs, _, _, err = p.records()
	if err != nil {
		return err
	}
	catalog, err = buildTree(cat, 516, cmp, true)
	if err != nil {
		return err
	}
	attributes, err = buildTree(attrs, 266, 0, true)
	if err != nil {
		return err
	}
	bitmap := make([]byte, bitmapBlocks*4096)
	for i := uint32(0); i < next; i++ {
		bitmap[i/8] |= 0x80 >> (i % 8)
	}
	bitmap[(total-1)/8] |= 0x80 >> ((total - 1) % 8)
	// makehfs leaves bitmap padding clear. CheckVolumeBitMap compares the
	// complete final 1024-bit segment, including bits beyond totalBlocks.
	header := make([]byte, 512)
	copy(header, "H+")
	be.PutUint16(header[2:], 4)
	if p.options.CaseSensitive {
		copy(header, "HX")
		be.PutUint16(header[2:], 5)
	}
	be.PutUint32(header[4:], 0x80000100)
	copy(header[8:], "HFSJ")
	stamp, _ := buildDate(p.options.Time)
	for _, off := range []int{16, 20, 28} {
		be.PutUint32(header[off:], stamp)
	}
	be.PutUint32(header[32:], files)
	be.PutUint32(header[36:], dirs)
	be.PutUint32(header[40:], 4096)
	be.PutUint32(header[44:], uint32(total))
	be.PutUint32(header[48:], uint32(total)-next-1)
	be.PutUint32(header[52:], next)
	be.PutUint32(header[56:], 4096)
	be.PutUint32(header[60:], 4096)
	be.PutUint32(header[64:], p.nextID)
	be.PutUint32(header[68:], 1)
	be.PutUint64(header[72:], 1)
	copy(header[104:], p.options.VolumeID[:])
	putBuildFork(header[112:], buildFork{size: int64(len(bitmap)), start: 1, count: uint32(bitmapBlocks)})
	putBuildFork(header[192:], extFork)
	putBuildFork(header[272:], catFork)
	putBuildFork(header[352:], attrFork)
	for _, off := range []int{192, 272, 352} {
		be.PutUint32(header[off+8:], 8*4096)
	}
	p.parts = append(p.parts, []buildPart{{1024, header, nil}, {4096, bitmap, nil}, {int64(extFork.start) * 4096, extents, nil}, {int64(catFork.start) * 4096, catalog, nil}, {int64(attrFork.start) * 4096, attributes, nil}, {p.size - 1024, header, nil}}...)
	sort.Slice(p.parts, func(i, j int) bool { return p.parts[i].offset < p.parts[j].offset })
	// Stable nonzero IDs bind metadata and contents, not host paths or enumeration.
	if p.options.VolumeID == [8]byte{} {
		h := sha256.New()
		for _, part := range p.parts {
			if part.fork == nil {
				_, _ = h.Write(part.data)
			} else {
				if err = p.copyFork(ctx, h, part.fork); err != nil {
					return err
				}
			}
		}
		copy(header[104:112], h.Sum(nil)[:8])
		header[104] |= 1
	}
	return ctx.Err()
}

func putBuildFork(b []byte, f buildFork) {
	be.PutUint64(b, uint64(f.size))
	be.PutUint32(b[12:], f.count)
	if f.count != 0 {
		be.PutUint32(b[16:], f.start)
		be.PutUint32(b[20:], f.count)
	}
}

func (p *Layout) records() ([]treeRecord, []treeRecord, uint32, uint32, error) {
	var cat, attrs []treeRecord
	var files, dirs uint32
	private := p.privateID
	add := func(id, parent uint32, name string, b []byte) {
		cat = append(cat, treeRecord{catalogKey(parent, name), b})
		t := make([]byte, 8)
		be.PutUint16(t, be.Uint16(b)+2)
		be.PutUint32(t[4:], parent)
		t = append(t, unicodeBytes(storedName(name))...)
		cat = append(cat, treeRecord{catalogKey(id, ""), t})
		if be.Uint16(b) == 1 {
			if id != 2 {
				dirs++
			}
		} else {
			files++
		}
	}
	for _, o := range p.objects {
		b, err := p.objectRecord(o)
		if err != nil {
			return nil, nil, 0, 0, err
		}
		if o.id == 2 && private != 0 {
			be.PutUint32(b[4:], be.Uint32(b[4:])+1)
			if p.options.CaseSensitive {
				be.PutUint32(b[84:], be.Uint32(b[84:])+1)
			}
		}
		if len(o.aliases) > 0 {
			be.PutUint32(b[44:], uint32(len(o.aliases)+1))
			add(o.id, private, fmt.Sprintf("iNode%d", o.id), b)
			aliases := append([]buildAlias{{o.parent, o.name, o.firstAlias}}, o.aliases...)
			// Alias catalog records use their own CNIDs; the private inode owns data.
			for _, a := range aliases {
				link := make([]byte, 248)
				be.PutUint16(link, 2)
				be.PutUint16(link[2:], 2)
				be.PutUint32(link[8:], a.id)
				stamp, _ := buildDate(p.options.Time)
				be.PutUint32(link[12:], stamp)
				link[41] = 2
				be.PutUint16(link[42:], 0100444)
				be.PutUint32(link[44:], o.id)
				copy(link[48:], "hlnkhfs+")
				be.PutUint16(link[56:], 0x100)
				add(a.id, a.parent, a.name, link)
			}
		} else {
			add(o.id, o.parent, o.name, b)
		}
		for _, a := range o.attrs {
			var value []byte
			if a.inline != nil {
				value = make([]byte, 16+(len(a.inline)+1)&^1)
				be.PutUint32(value, 0x10)
				be.PutUint32(value[12:], uint32(len(a.inline)))
				copy(value[16:], a.inline)
			} else {
				value = make([]byte, 88)
				be.PutUint32(value, 0x20)
				putBuildFork(value[8:], a.fork)
			}
			attrs = append(attrs, treeRecord{attributeKey(o.id, a.name), value})
		}
	}
	if private != 0 {
		b := make([]byte, 88)
		be.PutUint16(b, 1)
		be.PutUint32(b[8:], private)
		if p.options.CaseSensitive {
			be.PutUint16(b[2:], 0x10)
		}
		stamp, _ := buildDate(p.options.Time)
		be.PutUint32(b[12:], stamp)
		be.PutUint16(b[42:], 0040700)
		be.PutUint16(b[56:], 0x4000)
		for _, o := range p.objects {
			if len(o.aliases) > 0 {
				be.PutUint32(b[4:], be.Uint32(b[4:])+1)
			}
		}
		add(private, 2, privateDirectory, b)
	}
	sort.Slice(cat, func(i, j int) bool {
		a, b := cat[i].key, cat[j].key
		pa, pb := be.Uint32(a[2:]), be.Uint32(b[2:])
		if pa != pb {
			return pa < pb
		}
		sa, _ := unicodeName(a[6:])
		sb, _ := unicodeName(b[6:]) // keys already use on-disk slash/NUL conventions
		key := func(s string) string {
			return names.HFS(strings.ReplaceAll(strings.ReplaceAll(s, "/", ":"), "\x00", "\u2400"), p.options.CaseSensitive)
		}
		return key(sa) < key(sb)
	})
	sort.Slice(attrs, func(i, j int) bool {
		a, b := attrs[i].key, attrs[j].key
		if be.Uint32(a[4:]) != be.Uint32(b[4:]) {
			return be.Uint32(a[4:]) < be.Uint32(b[4:])
		}
		return bytes.Compare(a[14:], b[14:]) < 0
	})
	return cat, attrs, files, dirs, nil
}

func (p *Layout) objectRecord(o *buildObject) ([]byte, error) {
	m := o.node.Metadata
	dir := m.Mode.Value&0170000 == 0040000
	size := 248
	kind := uint16(2)
	flags := uint16(2)
	if dir {
		size = 88
		kind = 1
		flags = 0
		if p.options.CaseSensitive {
			flags |= 0x10
		}
	}
	b := make([]byte, size)
	be.PutUint16(b, kind)
	be.PutUint32(b[8:], o.id)
	if dir {
		be.PutUint32(b[4:], uint32(len(o.entries)))
		if p.options.CaseSensitive {
			be.PutUint32(b[84:], o.directories)
		}
	}
	for i, t := range []time.Time{m.BirthTime.Value, m.ModifyTime.Value, m.ChangeTime.Value, m.AccessTime.Value} {
		date, err := buildDate(t)
		if err != nil {
			return nil, err
		}
		be.PutUint32(b[12+i*4:], date)
	}
	be.PutUint32(b[32:], m.UID.Value)
	be.PutUint32(b[36:], m.GID.Value)
	b[40] = byte(m.BSDFlags.Value >> 16)
	b[41] = byte(m.BSDFlags.Value)
	be.PutUint16(b[42:], uint16(m.Mode.Value))
	copy(b[48:80], o.finder)
	if m.BSDFlags.Value&0x8000 != 0 {
		be.PutUint16(b[56:], be.Uint16(b[56:])|0x4000)
	}
	if m.Mode.Value&0170000 == 0120000 {
		copy(b[48:], "slnkrhap")
	}
	for _, a := range o.attrs {
		flags |= 4
		if a.name == "com.apple.system.Security" {
			flags |= 8
		}
	}
	if m.BSDFlags.Value&2 != 0 {
		flags |= 1
	}
	be.PutUint16(b[2:], flags)
	be.PutUint32(b[80:], 0x7e)
	if !dir {
		putBuildFork(b[88:], o.data)
		putBuildFork(b[168:], o.resource)
	}
	return b, nil
}

func (p *Layout) copyFork(ctx context.Context, w io.Writer, f *buildFork) error {
	if f.literal != nil {
		return writeBuild(ctx, w, f.literal)
	}
	var v filesystem.Value
	var err error
	if f.attr != "" {
		v, err = p.reader.OpenAttribute(ctx, f.source, f.attr)
	} else {
		v, err = p.reader.OpenRawData(ctx, f.source)
	}
	if err != nil {
		return err
	}
	if v.Size() != f.size {
		return errors.Join(filesystem.ErrConflict, v.Close())
	}
	err = streamBuild(ctx, w, v, f.size)
	return errors.Join(err, v.Close())
}
func streamBuild(ctx context.Context, w io.Writer, r io.ReaderAt, size int64) error {
	buf := make([]byte, 128<<10)
	for off := int64(0); off < size; {
		b := buf[:min(int64(len(buf)), size-off)]
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := block.ReadFull(r, b, off); err != nil {
			return err
		}
		if err := writeBuild(ctx, w, b); err != nil {
			return err
		}
		off += int64(len(b))
	}
	return ctx.Err()
}
func writeBuild(ctx context.Context, w io.Writer, b []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return err
}
func (p *Layout) Write(ctx context.Context, w io.Writer) error {
	if w == nil {
		return fs.ErrInvalid
	}
	zero := make([]byte, 128<<10)
	off := int64(0)
	pad := func(end int64) error {
		if end < off {
			return filesystem.ErrCorrupt
		}
		for off < end {
			b := zero[:min(int64(len(zero)), end-off)]
			if err := writeBuild(ctx, w, b); err != nil {
				return err
			}
			off += int64(len(b))
		}
		return nil
	}
	for _, part := range p.parts {
		if err := pad(part.offset); err != nil {
			return err
		}
		if part.fork != nil {
			if err := p.copyFork(ctx, w, part.fork); err != nil {
				return err
			}
			off += part.fork.size
		} else {
			if err := writeBuild(ctx, w, part.data); err != nil {
				return err
			}
			off += int64(len(part.data))
		}
	}
	return pad(p.size)
}
