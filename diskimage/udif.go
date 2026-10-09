package diskimage

import (
	"bytes"
	"compress/bzip2"
	"compress/zlib"
	"encoding/base64"
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

const maxChunk = 64 << 20

type chunk struct {
	kind                             uint32
	offset, size, stored, storedSize int64
}
type udif struct {
	source block.Source
	size   int64
	chunks []chunk
	mu     sync.Mutex
	cached int
	data   []byte
}

// The UDIF layer exposes the complete logical disk, including all partitions.
// Supported codecs are explicit; unsupported chunks never masquerade as zeros.
func openUDIF(source block.Source, footer []byte) (*udif, error) {
	be := binary.BigEndian
	if be.Uint32(footer[4:]) != 4 || be.Uint32(footer[8:]) != 512 {
		return nil, corrupt("UDIF footer version or size")
	}
	if be.Uint32(footer[60:]) > 1 {
		return nil, fmt.Errorf("segmented UDIF: %w", filesystem.ErrUnsupported)
	}
	po, pl := be.Uint64(footer[216:]), be.Uint64(footer[224:])
	do, dl := be.Uint64(footer[24:]), be.Uint64(footer[32:])
	limit := uint64(source.Size() - 512)
	if po > limit || pl > limit-po || do > limit || dl > limit-do {
		return nil, corrupt("UDIF metadata or data range")
	}
	if pl == 0 || pl > 16<<20 {
		return nil, filesystem.ErrLimit
	}
	sectors := be.Uint64(footer[492:])
	if sectors == 0 || sectors > (1<<40)/512 {
		return nil, filesystem.ErrLimit
	}
	u := &udif{source: source, size: int64(sectors) * 512, cached: -1}
	metadata := make([]byte, pl)
	if err := block.ReadFull(source, metadata, int64(po)); err != nil {
		return nil, err
	}
	// Current support is XML plist. A binary plist is an explicit capability gap.
	if bytes.HasPrefix(metadata, []byte("bplist")) {
		return nil, fmt.Errorf("binary UDIF plist: %w", filesystem.ErrUnsupported)
	}
	blocks, err := blockLists(metadata)
	if err != nil {
		return nil, err
	}
	for _, data := range blocks {
		if len(data) < 204 || string(data[:4]) != "mish" {
			return nil, corrupt("UDIF block list")
		}
		start, count, base := be.Uint64(data[8:]), be.Uint64(data[16:]), be.Uint64(data[24:])
		if start > sectors || count > sectors-start || base > dl {
			return nil, corrupt("UDIF block list range")
		}
		n := uint64(be.Uint32(data[200:]))
		if n > uint64((len(data)-204)/40) {
			return nil, corrupt("UDIF chunk count")
		}
		for j := uint64(0); j < n; j++ {
			v := data[204+j*40 : 204+(j+1)*40]
			kind := be.Uint32(v)
			if kind == 0xffffffff || kind == 0x7ffffffe {
				continue
			}
			rel, length, stored, storedSize := be.Uint64(v[8:]), be.Uint64(v[16:]), be.Uint64(v[24:]), be.Uint64(v[32:])
			if rel > count || length > count-rel {
				return nil, corrupt("UDIF logical chunk range")
			}
			if length == 0 {
				continue
			}
			if kind != 0 && kind != 2 {
				if stored > dl-base || storedSize > dl-base-stored {
					return nil, corrupt("UDIF stored chunk range")
				}
			}
			switch kind {
			case 0, 2:
			case 1:
				if storedSize != length*512 {
					return nil, corrupt("UDIF raw chunk length")
				}
			case 0x80000005, 0x80000006:
				if length*512 > maxChunk || storedSize > maxChunk {
					return nil, filesystem.ErrLimit
				}
			default:
				return nil, fmt.Errorf("UDIF chunk codec %#x: %w", kind, filesystem.ErrUnsupported)
			}
			u.chunks = append(u.chunks, chunk{kind: kind, offset: int64(start+rel) * 512, size: int64(length) * 512, stored: int64(do + base + stored), storedSize: int64(storedSize)})
		}
	}
	if len(u.chunks) == 0 {
		return nil, corrupt("UDIF contains no data chunks")
	}
	sort.Slice(u.chunks, func(i, j int) bool { return u.chunks[i].offset < u.chunks[j].offset })
	for i := 1; i < len(u.chunks); i++ {
		if u.chunks[i].offset < u.chunks[i-1].offset+u.chunks[i-1].size {
			return nil, corrupt("overlapping UDIF chunks")
		}
	}
	return u, nil
}

// Read only Data values directly inside blkx dictionaries. Other plist data
// (checksums, resource forks, signatures) are not interpreted as block lists.
func blockLists(data []byte) ([][]byte, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	type frame struct {
		name, key string
		blkx      bool
	}
	var stack []frame
	var out [][]byte
	for {
		t, err := d.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, corrupt("UDIF XML plist: " + err.Error())
		}
		switch v := t.(type) {
		case xml.StartElement:
			if len(stack) > 64 {
				return nil, filesystem.ErrLimit
			}
			if v.Name.Local == "key" {
				var key string
				if err := d.DecodeElement(&key, &v); err != nil {
					return nil, err
				}
				if len(stack) == 0 || stack[len(stack)-1].name != "dict" {
					return nil, corrupt("plist key outside dictionary")
				}
				stack[len(stack)-1].key = key
				continue
			}
			inside := false
			if len(stack) > 0 {
				p := stack[len(stack)-1]
				inside = p.blkx || (p.key == "blkx" && v.Name.Local == "array")
			}
			if v.Name.Local == "data" {
				var raw string
				if err := d.DecodeElement(&raw, &v); err != nil {
					return nil, err
				}
				if inside && len(stack) > 0 && stack[len(stack)-1].key == "Data" {
					b, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(raw), ""))
					if err != nil {
						return nil, corrupt("UDIF block list base64")
					}
					out = append(out, b)
				}
				continue
			}
			stack = append(stack, frame{name: v.Name.Local, blkx: inside})
		case xml.EndElement:
			if len(stack) == 0 {
				return nil, corrupt("UDIF XML nesting")
			}
			stack = stack[:len(stack)-1]
		}
	}
	if len(stack) != 0 || len(out) == 0 {
		return nil, corrupt("UDIF plist has no blkx data")
	}
	return out, nil
}

func (u *udif) Size() int64 { return u.size }
func (u *udif) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, os.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= u.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(len(p)) > u.size-off {
		p = p[:u.size-off]
	}
	n := 0
	for len(p) > 0 {
		i := sort.Search(len(u.chunks), func(i int) bool { return u.chunks[i].offset+u.chunks[i].size > off })
		length := int64(len(p))
		if i == len(u.chunks) || off < u.chunks[i].offset {
			if i < len(u.chunks) {
				length = min(length, u.chunks[i].offset-off)
			}
			clear(p[:length])
		} else {
			c := u.chunks[i]
			length = min(length, c.offset+c.size-off)
			if err := u.readChunk(i, p[:length], off-c.offset); err != nil {
				return n, err
			}
		}
		n += int(length)
		off += length
		p = p[length:]
	}
	if n < want {
		return n, io.EOF
	}
	return n, nil
}

func (u *udif) readChunk(i int, p []byte, off int64) error {
	c := u.chunks[i]
	switch c.kind {
	case 0, 2:
		clear(p)
		return nil
	case 1:
		return block.ReadFull(u.source, p, c.stored+off)
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.cached != i {
		stored := io.NewSectionReader(u.source, c.stored, c.storedSize)
		var decoded io.Reader
		var closer io.Closer
		if c.kind == 0x80000005 {
			r, err := zlib.NewReader(stored)
			if err != nil {
				return fmt.Errorf("UDIF zlib: %w: %v", filesystem.ErrCorrupt, err)
			}
			decoded, closer = r, r
		} else {
			decoded = bzip2.NewReader(stored)
		}
		b, err := io.ReadAll(io.LimitReader(decoded, c.size+1))
		if closer != nil {
			closeErr := closer.Close()
			if err == nil {
				err = closeErr
			}
		}
		if err != nil {
			return fmt.Errorf("UDIF decompression: %w: %v", filesystem.ErrCorrupt, err)
		}
		if int64(len(b)) != c.size {
			return corrupt("UDIF decoded chunk length")
		}
		u.data, u.cached = b, i
	}
	copy(p, u.data[off:off+int64(len(p))])
	return nil
}
