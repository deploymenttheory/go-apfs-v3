// Package hfsplus interprets HFS Plus and HFSX structures using Apple TN1150.
// Structural inspection never replays a journal or repairs the input image.
package hfsplus

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

var be = binary.BigEndian

type Volume struct {
	Format         string `json:"format"`
	Name           string `json:"name"`
	VolumeID       string `json:"volumeId"`
	BlockSize      uint32 `json:"blockSize"`
	BlockCount     uint32 `json:"blockCount"`
	FreeBlocks     uint32 `json:"freeBlocks"`
	Attributes     uint32 `json:"attributes"`
	CaseSensitive  bool   `json:"caseSensitive"`
	Journaled      bool   `json:"journaled"`
	Clean          bool   `json:"clean"`
	Files          uint32 `json:"files"`
	Directories    uint32 `json:"directories"`
	source         block.Source
	catalog        *tree
	overflow       *tree
	attributeFork  []byte
	rootCreated    uint32
	privateID      uint32
	privateCreated uint32
}

// Open borrows source and reads its header and catalog root thread.
// Journal replay is not performed.
func Open(source block.Source) (*Volume, error) {
	if source == nil || source.Size() < 1536 {
		return nil, bad("volume header")
	}
	h := make([]byte, 512)
	if err := block.ReadFull(source, h, 1024); err != nil {
		return nil, err
	}
	format := "HFS+"
	switch string(h[:2]) {
	case "H+":
		if be.Uint16(h[2:]) != 4 {
			return nil, bad("volume version")
		}
	case "HX":
		format = "HFSX"
		if be.Uint16(h[2:]) != 5 {
			return nil, bad("volume version")
		}
	default:
		return nil, bad("volume signature")
	}
	bs, count, free := be.Uint32(h[40:]), be.Uint32(h[44:]), be.Uint32(h[48:])
	if bs < 512 || bs&(bs-1) != 0 || count == 0 || uint64(count) > uint64(source.Size())/uint64(bs) || free > count {
		return nil, bad("allocation geometry")
	}
	a := be.Uint32(h[4:])
	v := &Volume{Format: format, BlockSize: bs, BlockCount: count, FreeBlocks: free, Attributes: a, Journaled: a&0x2000 != 0, Clean: a&0x100 != 0 && a&0x4000 == 0, Files: be.Uint32(h[32:]), Directories: be.Uint32(h[36:]), VolumeID: fmt.Sprintf("%X", h[104:112])}
	v.source = source
	// TN1150 requires the extents file to describe itself in the volume header.
	ef, err := openInlineFork(source, bs, count, h[192:272])
	if err != nil {
		return nil, err
	}
	if ef.size != 0 {
		v.overflow, err = openTree(ef, 4)
		if err != nil {
			return nil, err
		}
	}
	f, err := v.fileFork(context.Background(), 4, 0, h[272:352])
	if err != nil {
		return nil, err
	}
	header := make([]byte, 106)
	if err := f.read(header, 0); err != nil {
		return nil, err
	}
	if header[8] != 1 {
		return nil, bad("catalog header node")
	}
	nodeSize := be.Uint16(header[32:])
	root, total := be.Uint32(header[16:]), be.Uint32(header[36:])
	if nodeSize < 512 || nodeSize&(nodeSize-1) != 0 || total == 0 || root >= total || uint64(total)*uint64(nodeSize) > f.size {
		return nil, bad("catalog geometry")
	}
	compare := header[51]
	if compare != 0xbc && compare != 0xcf {
		return nil, fmt.Errorf("HFS catalog comparison %#x: %w", compare, filesystem.ErrUnsupported)
	}
	v.CaseSensitive = compare == 0xbc
	name, err := rootName(f, root, total, nodeSize)
	if err != nil {
		return nil, err
	}
	v.Name = name
	v.catalog = &tree{fork: f, root: root, total: total, nodeSize: nodeSize, idOffset: 2}
	v.attributeFork = append([]byte(nil), h[352:432]...)
	if err := v.findPrivateDirectory(); err != nil {
		return nil, err
	}
	return v, nil
}

type extent struct{ logical, physical, size uint64 }
type fork struct {
	source  block.Source
	size    uint64
	extents []extent
}

func openInlineFork(source block.Source, bs, count uint32, b []byte) (*fork, error) {
	return resolveFork(context.Background(), source, bs, count, b, nil)
}

func (f *fork) read(p []byte, off uint64) error {
	if off > f.size || uint64(len(p)) > f.size-off {
		return bad("fork read range")
	}
	for len(p) > 0 {
		found := false
		for _, e := range f.extents {
			if off < e.logical || off >= e.logical+e.size {
				continue
			}
			n := min(uint64(len(p)), e.logical+e.size-off)
			if err := block.ReadFull(f.source, p[:n], int64(e.physical+off-e.logical)); err != nil {
				return err
			}
			p = p[n:]
			off += n
			found = true
			break
		}
		if !found {
			return bad("fork extent hole")
		}
	}
	return nil
}

func rootName(f *fork, root, total uint32, nodeSize uint16) (string, error) {
	t := &tree{fork: f, root: root, total: total, nodeSize: nodeSize, idOffset: 2}
	name := ""
	err := t.records(context.Background(), 2, func(r treeRecord) error {
		if len(r.key) != 8 || be.Uint16(r.key[6:]) != 0 {
			return nil
		}
		if name != "" || len(r.value) < 10 || be.Uint16(r.value) != 3 {
			return bad("root folder thread")
		}
		var err error
		name, err = unicodeName(r.value[8:])
		return err
	})
	if err != nil {
		return "", err
	}
	if name == "" {
		return "", bad("missing root folder thread")
	}
	return name, nil
}

func bad(what string) error { return fmt.Errorf("HFS+ %s: %w", what, filesystem.ErrCorrupt) }
