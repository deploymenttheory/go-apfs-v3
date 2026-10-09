package hfsplus

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"math"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	forkvalue "github.com/deploymenttheory/go-apfs-v3/internal/fork"
)

var _ filesystem.Reader = (*Volume)(nil)

func (v *Volume) Root() uint64 { return 2 }
func (v *Volume) readable(ctx context.Context, id uint64) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if v.catalog == nil || id > math.MaxUint32 {
		return fs.ErrInvalid
	}
	if !v.Clean {
		return fmt.Errorf("HFS+ requires journal replay or recovery: %w", filesystem.ErrUnsupported)
	}
	return nil
}

func (v *Volume) catalogRecord(ctx context.Context, id uint64) ([]byte, error) {
	if err := v.readable(ctx, id); err != nil {
		return nil, err
	}
	var parent uint32
	var name []byte
	found := false
	err := v.catalog.records(ctx, uint32(id), func(r treeRecord) error {
		if len(r.key) != 8 || be.Uint16(r.key[6:]) != 0 {
			return nil
		}
		if found || len(r.value) < 10 || (be.Uint16(r.value) != 3 && be.Uint16(r.value) != 4) {
			return bad("catalog thread")
		}
		found = true
		parent = be.Uint32(r.value[4:])
		name = bytes.Clone(r.value[8:])
		_, err := unicodeName(name)
		return err
	})
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fs.ErrNotExist
	}
	var data []byte
	err = v.catalog.records(ctx, parent, func(r treeRecord) error {
		if len(r.key) < 8 {
			return bad("catalog name key")
		}
		if bytes.Equal(r.key[6:], name) {
			if data != nil || len(r.value) < 88 || (be.Uint16(r.value) != 1 && be.Uint16(r.value) != 2) || be.Uint32(r.value[8:]) != uint32(id) {
				return bad("catalog object")
			}
			data = bytes.Clone(r.value)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, bad("dangling catalog thread")
	}
	if be.Uint16(data) == 2 && len(data) != 248 {
		return nil, bad("catalog file length")
	}
	if be.Uint16(data) == 2 && string(data[48:56]) == "hlnkhfs+" {
		return nil, fmt.Errorf("HFS+ indirect hard link: %w", filesystem.ErrUnsupported)
	}
	return data, nil
}

func (v *Volume) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	b, err := v.catalogRecord(ctx, id)
	if err != nil {
		return filesystem.Node{}, err
	}
	m := filesystem.Metadata{Mode: filesystem.Observed(uint32(be.Uint16(b[42:]))), UID: filesystem.Observed(be.Uint32(b[32:])), GID: filesystem.Observed(be.Uint32(b[36:])), BSDFlags: filesystem.Observed(uint32(b[40])<<16 | uint32(b[41]))}
	// UF_HIDDEN is persisted in Finder's kIsInvisible bit, outside BSDInfo.
	if be.Uint16(b[56:])&0x4000 != 0 {
		m.BSDFlags.Value |= 0x8000
	}
	stamp := func(off int) filesystem.Observation[time.Time] {
		return filesystem.Observed(time.Unix(int64(be.Uint32(b[off:]))-2082844800, 0).UTC())
	}
	m.BirthTime, m.ModifyTime, m.ChangeTime, m.AccessTime = stamp(12), stamp(16), stamp(20), stamp(24)
	n := filesystem.Node{Identity: filesystem.Identity{Volume: v.VolumeID, Object: id}, Metadata: m}
	if be.Uint16(b) == 2 {
		n.Size = be.Uint64(b[88:])
		n.Links = filesystem.Observed(uint32(1))
	}
	if m.BSDFlags.Value&0x20 != 0 {
		return filesystem.Node{}, fmt.Errorf("HFS+ compressed logical size: %w", filesystem.ErrUnsupported)
	}
	return n, nil
}

func (v *Volume) ReadDir(ctx context.Context, id uint64, yield func(filesystem.DirEntry) error) error {
	b, err := v.catalogRecord(ctx, id)
	if err != nil {
		return err
	}
	if be.Uint16(b) != 1 {
		return fs.ErrInvalid
	}
	return v.catalog.records(ctx, uint32(id), func(r treeRecord) error {
		if len(r.key) < 8 || len(r.value) < 2 {
			return bad("catalog directory entry")
		}
		name, err := unicodeName(r.key[6:])
		if err != nil {
			return err
		}
		kind := be.Uint16(r.value)
		if kind == 3 || kind == 4 {
			return nil
		}
		if (kind != 1 && kind != 2) || len(r.value) < 88 || name == "" || name == "." || name == ".." {
			return bad("catalog entry type or name")
		}
		// HFS stores slash where the POSIX interface presents colon.
		name = strings.ReplaceAll(name, "/", ":")
		return yield(filesystem.DirEntry{Name: name, Object: uint64(be.Uint32(r.value[8:]))})
	})
}

func (v *Volume) openFork(ctx context.Context, b []byte) (filesystem.Value, error) {
	f, err := openInlineFork(v.source, v.BlockSize, v.BlockCount, b)
	if err != nil {
		return nil, err
	}
	if f.size > math.MaxInt64 {
		return nil, filesystem.ErrLimit
	}
	extents := make([]forkvalue.Extent, 0, len(f.extents))
	for _, e := range f.extents {
		extents = append(extents, forkvalue.Extent{Logical: int64(e.logical), Physical: int64(e.physical), Length: int64(e.size)})
	}
	return forkvalue.New(ctx, v.source, int64(f.size), extents)
}
func (v *Volume) OpenData(ctx context.Context, id uint64) (filesystem.Value, error) {
	b, err := v.catalogRecord(ctx, id)
	if err != nil {
		return nil, err
	}
	if be.Uint16(b) != 2 || be.Uint16(b[42:])&0170000 != 0100000 {
		return nil, fs.ErrInvalid
	}
	if b[41]&0x20 != 0 {
		return nil, fmt.Errorf("transparent compression: %w", filesystem.ErrUnsupported)
	}
	return v.openFork(ctx, b[88:168])
}

func (v *Volume) attributes(ctx context.Context, id uint64, yield func(string, []byte) error) error {
	if be.Uint64(v.attributeFork) == 0 {
		return ctx.Err()
	}
	f, err := openInlineFork(v.source, v.BlockSize, v.BlockCount, v.attributeFork)
	if err != nil {
		return err
	}
	t, err := openTree(f, 4)
	if err != nil {
		return err
	}
	return t.records(ctx, uint32(id), func(r treeRecord) error {
		if len(r.key) < 14 || len(r.value) < 4 {
			return bad("attribute record")
		}
		name, err := unicodeName(r.key[12:])
		if err != nil {
			return err
		}
		if be.Uint32(r.key[8:]) != 0 {
			return fmt.Errorf("attribute overflow extents: %w", filesystem.ErrUnsupported)
		}
		return yield(name, r.value)
	})
}
func (v *Volume) ListAttributes(ctx context.Context, id uint64, yield func(string) error) error {
	b, err := v.catalogRecord(ctx, id)
	if err != nil {
		return err
	}
	if be.Uint16(b) == 2 && be.Uint64(b[168:]) > 0 {
		if err := yield(filesystem.ResourceFork); err != nil {
			return err
		}
	}
	if !bytes.Equal(finderInfo(b), make([]byte, 32)) {
		if err := yield(filesystem.FinderInfo); err != nil {
			return err
		}
	}
	return v.attributes(ctx, id, func(name string, _ []byte) error { return yield(name) })
}
func (v *Volume) OpenAttribute(ctx context.Context, id uint64, name string) (filesystem.Value, error) {
	b, err := v.catalogRecord(ctx, id)
	if err != nil {
		return nil, err
	}
	if name == filesystem.ResourceFork {
		if be.Uint16(b) != 2 || be.Uint64(b[168:]) == 0 {
			return nil, fs.ErrNotExist
		}
		return v.openFork(ctx, b[168:248])
	}
	if name == filesystem.FinderInfo {
		info := finderInfo(b)
		if bytes.Equal(info, make([]byte, 32)) {
			return nil, fs.ErrNotExist
		}
		return forkvalue.Bytes(ctx, info)
	}
	var data []byte
	err = v.attributes(ctx, id, func(n string, b []byte) error {
		if n != name {
			return nil
		}
		if data != nil {
			return bad("duplicate attribute")
		}
		data = bytes.Clone(b)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, fs.ErrNotExist
	}
	switch be.Uint32(data) {
	case 0x10:
		if len(data) < 16 {
			return nil, bad("inline attribute header")
		}
		size := uint64(be.Uint32(data[12:]))
		if size > uint64(len(data)-16) || uint64(len(data)-16)-size > 1 {
			return nil, bad("inline attribute size")
		}
		return forkvalue.Bytes(ctx, data[16:16+size])
	case 0x20:
		if len(data) != 88 {
			return nil, bad("attribute fork")
		}
		return v.openFork(ctx, data[8:])
	default:
		return nil, fmt.Errorf("attribute storage type: %w", filesystem.ErrUnsupported)
	}
}
func (v *Volume) Readlink(ctx context.Context, id uint64) (target string, err error) {
	b, err := v.catalogRecord(ctx, id)
	if err != nil {
		return "", err
	}
	if be.Uint16(b) != 2 || be.Uint16(b[42:])&0170000 != 0120000 {
		return "", fs.ErrInvalid
	}
	f, err := v.openFork(ctx, b[88:168])
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
	data, err := io.ReadAll(io.NewSectionReader(f, 0, f.Size()))
	if err == nil && (len(data) == 0 || bytes.IndexByte(data, 0) >= 0) {
		return "", bad("symlink target")
	}
	return string(data), err
}
