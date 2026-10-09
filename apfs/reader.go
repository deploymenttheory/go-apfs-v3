package apfs

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"math"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v3/internal/fork"
	"github.com/deploymenttheory/go-apfs-v3/internal/names"
)

var _ filesystem.Reader = (*Volume)(nil)

type inode struct {
	node       filesystem.Node
	stream     uint64
	streamSize uint64
}

func (v *Volume) Root() uint64 { return 2 }

func (v *Volume) Lookup(ctx context.Context, parent uint64, name string) (filesystem.DirEntry, error) {
	return names.Lookup(ctx, v, parent, name, func(s string) string {
		return names.APFS(s, v.CaseSensitive, v.IncompatibleFeatures&9 != 0)
	})
}

func (v *Volume) inode(ctx context.Context, id uint64) (inode, error) {
	var result inode
	found := false
	err := v.records(ctx, id, 3, func(r record) error {
		if found || len(r.key) != 8 || len(r.value) < 92 {
			return corrupt("inode", 0)
		}
		found = true
		b := r.value
		mode := uint32(le.Uint16(b[80:]))
		flags := le.Uint32(b[68:])
		m := filesystem.Metadata{Mode: filesystem.Observed(mode), UID: filesystem.Observed(le.Uint32(b[72:])), GID: filesystem.Observed(le.Uint32(b[76:])), BSDFlags: filesystem.Observed(flags)}
		m.BirthTime = filesystem.Observed(time.Unix(0, int64(le.Uint64(b[16:]))).UTC())
		m.ModifyTime = filesystem.Observed(time.Unix(0, int64(le.Uint64(b[24:]))).UTC())
		m.ChangeTime = filesystem.Observed(time.Unix(0, int64(le.Uint64(b[32:]))).UTC())
		m.AccessTime = filesystem.Observed(time.Unix(0, int64(le.Uint64(b[40:]))).UTC())
		result.node = filesystem.Node{Identity: filesystem.Identity{Volume: v.UUID, Object: id, View: uint64(v.xid)}, Metadata: m}
		if mode&0170000 != 0040000 {
			result.node.Links = filesystem.Observed(le.Uint32(b[56:]))
		}
		result.stream = le.Uint64(b[8:])
		err := extendedFields(b[92:], func(kind byte, data []byte) error {
			if kind == 8 {
				if len(data) != 40 {
					return corrupt("inode data stream", 0)
				}
				result.streamSize = le.Uint64(data)
			}
			return nil
		})
		if err != nil {
			return err
		}
		result.node.Size = result.streamSize
		if flags&0x20 != 0 {
			result.node.Size = le.Uint64(b[84:])
		}
		return nil
	})
	if err == nil && !found {
		err = fs.ErrNotExist
	}
	return result, err
}

func extendedFields(b []byte, yield func(byte, []byte) error) error {
	if len(b) == 0 {
		return nil
	}
	if len(b) < 4 {
		return corrupt("extended field header", 0)
	}
	n := int(le.Uint16(b))
	used := int(le.Uint16(b[2:]))
	pos := 4 + n*4
	// The descriptor array precedes aligned values. Bound every field by the
	// actual record, independently of the declared used-data count.
	if used > len(b)-4 || pos > len(b) {
		return corrupt("extended field table", 0)
	}
	seen := map[byte]bool{}
	for i := 0; i < n; i++ {
		e := b[4+i*4 : 8+i*4]
		length := int(le.Uint16(e[2:]))
		if seen[e[0]] || length > len(b)-pos {
			return corrupt("extended field bounds or duplicate", 0)
		}
		seen[e[0]] = true
		if err := yield(e[0], b[pos:pos+length]); err != nil {
			return err
		}
		pos += (length + 7) &^ 7
		if pos > len(b) {
			return corrupt("extended field alignment", 0)
		}
	}
	return nil
}

func (v *Volume) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	i, err := v.inode(ctx, id)
	if err != nil {
		return filesystem.Node{}, err
	}
	i.node.Compression.State = filesystem.Absent
	if i.node.Metadata.BSDFlags.Value&0x20 != 0 {
		h, err := decmpfs.Inspect(func(name string) (filesystem.Value, error) { return v.OpenAttribute(ctx, id, name) })
		if err != nil {
			return filesystem.Node{}, err
		}
		if h.Size != i.node.Size {
			return filesystem.Node{}, corrupt("compressed logical size", 0)
		}
		i.node.Compression = filesystem.Observed(filesystem.Compression{Type: h.Type})
	}
	if i.node.Metadata.Mode.Value&0170000 == 0120000 {
		target, err := v.Readlink(ctx, id)
		if err != nil {
			return filesystem.Node{}, err
		}
		i.node.Size = uint64(len(target))
	}
	return i.node, nil
}

func (v *Volume) ReadDir(ctx context.Context, id uint64, yield func(filesystem.DirEntry) error) error {
	i, err := v.inode(ctx, id)
	if err != nil {
		return err
	}
	if i.node.Metadata.Mode.Value&0170000 != 0040000 {
		return fmt.Errorf("directory required: %w", fs.ErrInvalid)
	}
	return v.records(ctx, id, 9, func(r record) error {
		offset, length := 10, 0
		if v.IncompatibleFeatures&9 != 0 {
			if len(r.key) < 12 {
				return corrupt("hashed directory key", 0)
			}
			offset = 12
			length = int(le.Uint32(r.key[8:]) & 0x3ff)
		} else {
			if len(r.key) < 10 {
				return corrupt("directory key", 0)
			}
			length = int(le.Uint16(r.key[8:]))
		}
		if length == 0 || offset+length != len(r.key) || len(r.value) < 18 {
			return corrupt("directory record", 0)
		}
		name, err := nativeName(r.key[offset:])
		if err != nil {
			return err
		}
		if strings.Contains(name, "/") || name == "." || name == ".." {
			return corrupt("directory name", 0)
		}
		object := le.Uint64(r.value)
		if object == 0 || object > objectMask {
			return corrupt("directory object", 0)
		}
		return yield(filesystem.DirEntry{Name: name, Object: object})
	})
}

func nativeName(b []byte) (string, error) {
	if len(b) < 2 || b[len(b)-1] != 0 || bytes.IndexByte(b[:len(b)-1], 0) >= 0 || !utf8.Valid(b[:len(b)-1]) {
		return "", corrupt("UTF-8 name", 0)
	}
	return string(b[:len(b)-1]), nil
}

func (v *Volume) OpenData(ctx context.Context, id uint64) (filesystem.Value, error) {
	i, err := v.inode(ctx, id)
	if err != nil {
		return nil, err
	}
	if i.node.Metadata.Mode.Value&0170000 != 0100000 {
		return nil, fmt.Errorf("regular file required: %w", fs.ErrInvalid)
	}
	if i.node.Metadata.BSDFlags.Value&0x20 != 0 {
		value, err := decmpfs.Open(ctx, func(name string) (filesystem.Value, error) { return v.OpenAttribute(ctx, id, name) })
		if err == nil && uint64(value.Size()) != i.node.Size {
			_ = value.Close()
			return nil, corrupt("compressed logical size", 0)
		}
		return v.borrow(value, err)
	}
	return v.stream(ctx, i.stream, i.streamSize)
}

func (v *Volume) OpenRawData(ctx context.Context, id uint64) (filesystem.Value, error) {
	i, err := v.inode(ctx, id)
	if err != nil {
		return nil, err
	}
	if i.node.Metadata.Mode.Value&0170000 != 0100000 {
		return nil, fs.ErrInvalid
	}
	return v.stream(ctx, i.stream, i.streamSize)
}

func (v *Volume) stream(ctx context.Context, id, size uint64) (filesystem.Value, error) {
	if size > math.MaxInt64 {
		return nil, filesystem.ErrLimit
	}
	var extents []fork.Extent
	err := v.records(ctx, id, 8, func(r record) error {
		if len(extents) >= 1<<20 {
			return filesystem.ErrLimit
		}
		if len(r.key) != 16 || len(r.value) != 24 {
			return corrupt("file extent", 0)
		}
		logical, flags, physical := le.Uint64(r.key[8:]), le.Uint64(r.value), le.Uint64(r.value[8:])
		length := flags & 0x00ffffffffffffff
		// Native single-key encrypted extents use flag 1 for crypto_id as a
		// tweak. The 2020 reference predates this flag; qualify it through
		// encrypted native file/clone reads, keeping other encodings explicit.
		if flags>>56 != 0 && (flags>>56 != 1 || !v.Encrypted || v.Flags&8 == 0) {
			return fmt.Errorf("file extent flags %#x: %w", flags>>56, filesystem.ErrUnsupported)
		}
		bs := uint64(v.container.BlockSize)
		if logical > math.MaxInt64 || length == 0 || length%bs != 0 || logical%bs != 0 || physical >= v.container.BlockCount || (physical != 0 && length/bs > v.container.BlockCount-physical) {
			return corrupt("file extent range", 0)
		}
		var data block.Source
		if physical != 0 {
			section, err := block.NewSection(v.container.source, int64(physical*bs), int64(length))
			if err != nil {
				return err
			}
			data = section
			cryptoID := le.Uint64(r.value[16:])
			if v.Encrypted && cryptoID != 0 {
				if cryptoID > math.MaxUint64/(bs/512) || length/512-1 > math.MaxUint64-cryptoID*(bs/512) {
					return corrupt("extent encryption tweak", 0)
				}
				data = &encryptedSource{source: section, keys: v.keys, sector: cryptoID * (bs / 512), ctx: ctx}
			}
		}
		extents = append(extents, fork.Extent{Logical: int64(logical), Length: int64(length), Data: data})
		return nil
	})
	if err != nil {
		return nil, err
	}
	return v.borrow(fork.New(ctx, int64(size), extents))
}

func (v *Volume) attributes(ctx context.Context, id uint64, yield func(string, record) error) error {
	return v.records(ctx, id, 4, func(r record) error {
		if len(r.key) < 10 || len(r.key) != 10+int(le.Uint16(r.key[8:])) {
			return corrupt("attribute key", 0)
		}
		name, err := nativeName(r.key[10:])
		if err != nil {
			return err
		}
		return yield(name, r)
	})
}
func (v *Volume) ListAttributes(ctx context.Context, id uint64, yield func(string) error) error {
	if _, err := v.inode(ctx, id); err != nil {
		return err
	}
	return v.attributes(ctx, id, func(name string, _ record) error { return yield(name) })
}
func (v *Volume) OpenAttribute(ctx context.Context, id uint64, name string) (filesystem.Value, error) {
	var data []byte
	err := v.attributes(ctx, id, func(n string, r record) error {
		if n == name {
			if data != nil {
				return corrupt("duplicate attribute", 0)
			}
			data = bytes.Clone(r.value)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fs.ErrNotExist
	}
	if len(data) < 4 {
		return nil, corrupt("attribute value", 0)
	}
	flags := le.Uint16(data)
	// macOS 27 native captures use 0x11 for large ordinary attributes. The
	// extra bit's write semantics are undocumented; admit this observed stream
	// encoding for reads only, verified against native bytes in acceptance.
	if flags&^uint16(15) != 0 && flags != 0x11 {
		return nil, fmt.Errorf("attribute flags %#x: %w", flags, filesystem.ErrUnsupported)
	}
	switch flags & 3 {
	case 2:
		length := int(le.Uint16(data[2:]))
		if length != len(data)-4 {
			return nil, corrupt("embedded attribute length", 0)
		}
		return v.borrow(fork.Bytes(ctx, data[4:]))
	case 1:
		if len(data) != 52 {
			return nil, corrupt("attribute data stream", 0)
		}
		return v.stream(ctx, le.Uint64(data[4:]), le.Uint64(data[12:]))
	default:
		return nil, corrupt("attribute storage flags", 0)
	}
}
func (v *Volume) Readlink(ctx context.Context, id uint64) (target string, err error) {
	i, err := v.inode(ctx, id)
	if err != nil {
		return "", err
	}
	if i.node.Metadata.Mode.Value&0170000 != 0120000 {
		return "", fs.ErrInvalid
	}
	f, err := v.OpenAttribute(ctx, id, "com.apple.fs.symlink")
	if err != nil {
		return "", err
	}
	defer func() {
		if e := f.Close(); err == nil {
			err = e
		}
	}()
	if f.Size() > 1<<20 {
		return "", filesystem.ErrLimit
	}
	b, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
	if err != nil {
		return "", err
	}
	// Native APFS stores the C-string terminator in the owned symlink EA;
	// readlink and logical st_size exclude it. Keep OpenAttribute byte-exact.
	if len(b) == 0 || b[len(b)-1] != 0 || bytes.IndexByte(b[:len(b)-1], 0) >= 0 {
		return "", corrupt("symlink target", 0)
	}
	return string(b[:len(b)-1]), nil
}
