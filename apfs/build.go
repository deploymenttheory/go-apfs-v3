package apfs

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v3/internal/names"
)

// BuildOptions constructs one unencrypted, normalization-insensitive APFS volume.
// Capacity is container bytes, rounded up to 4096; zero selects automatic sizing.
// Time is an explicit construction clock, independent of captured file times.
// Zero UUIDs derive from the canonical metadata and contents. Source readers must
// remain immutable through planning and writing. No existing disk is modified.
type BuildOptions struct {
	Name                      string
	CaseSensitive             bool
	Capacity                  int64
	Time                      time.Time
	ContainerUUID, VolumeUUID [16]byte
}
type buildAlias struct {
	parent, id uint64
	name       string
}
type buildObject struct {
	source, id uint64
	node       filesystem.Node
	aliases    []buildAlias
	children   uint32
	data       *buildStream
	attrs      []buildAttribute
	target     string
}
type buildStream struct {
	reader                    filesystem.Reader
	id, source, start, blocks uint64
	attribute                 string
	size                      int64
	digest                    [32]byte
}
type buildAttribute struct {
	name   string
	inline []byte
	stream *buildStream
}
type buildPart struct {
	offset int64
	data   []byte
	stream *buildStream
}

// Layout is a bounded immutable container plan borrowing all source readers.
// Write may be called repeatedly. The caller discards partial output on error.
type Layout struct {
	options             ContainerBuildOptions
	volumes             []*volumeLayout
	parts               []buildPart
	size, metadataBytes int64
}

type volumeLayout struct {
	reader     filesystem.Reader
	options    VolumeSpec
	time       time.Time
	group      [16]byte
	grouped    bool
	objects    []*buildObject
	streams    []*buildStream
	nextID     uint64
	budget     *int64
	superblock []byte
	allocated  uint64
}

func (p *Layout) Size() int64 { return p.size }

func Plan(ctx context.Context, r filesystem.Reader, o BuildOptions) (*Layout, error) {
	return PlanContainer(ctx, []VolumeSpec{{Reader: r, Name: o.Name, CaseSensitive: o.CaseSensitive, UUID: o.VolumeUUID}}, ContainerBuildOptions{Capacity: o.Capacity, Time: o.Time, UUID: o.ContainerUUID})
}

func (p *volumeLayout) collect(ctx context.Context) error {
	r, o := p.reader, p.options
	rules := r.NameRules()
	if rules.Format != "APFS" || rules.CaseSensitive != o.CaseSensitive || !rules.NormalizationInsensitive {
		return fmt.Errorf("APFS build requires matching native name rules: %w", filesystem.ErrUnsupported)
	}
	if _, err := names.Stored(o.Name, "APFS"); err != nil {
		return err
	}
	if len(o.Name) > 255 {
		return filesystem.ErrLimit
	}
	seen := map[uint64]*buildObject{}
	entries := 0
	var visit func(uint64, uint64, string, int) error
	visit = func(source, parent uint64, name string, depth int) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		entries++
		if entries > 100000 || depth > 256 {
			return filesystem.ErrLimit
		}
		if err := p.reserve(512 + int64(len(name))*4); err != nil {
			return err
		}
		alias := buildAlias{parent: parent, name: name}
		if old := seen[source]; old != nil {
			if old.node.Metadata.Mode.Value&0170000 != 0100000 {
				return fmt.Errorf("nonregular hard link: %w", filesystem.ErrUnsupported)
			}
			old.aliases = append(old.aliases, alias)
			return nil
		}
		n, err := r.Stat(ctx, source)
		if err != nil {
			return err
		}
		if n.Identity.Object != source {
			return filesystem.ErrCorrupt
		}
		obj := &buildObject{source: source, id: p.nextID, node: n, aliases: []buildAlias{alias}}
		p.nextID++
		if parent == 1 {
			obj.id = 2
			obj.aliases[0].name = "root"
		}
		if err = p.validateObject(ctx, obj); err != nil {
			return fmt.Errorf("%q: %w", name, err)
		}
		seen[source] = obj
		p.objects = append(p.objects, obj)
		if n.Metadata.Mode.Value&0170000 != 0040000 {
			return nil
		}
		var children []filesystem.DirEntry
		err = r.ReadDir(ctx, source, func(e filesystem.DirEntry) error {
			if len(children) >= 100000 {
				return filesystem.ErrLimit
			}
			if _, err := names.Stored(e.Name, "APFS"); err != nil {
				return err
			}
			if err := p.reserve(32 + int64(len(e.Name))*4); err != nil {
				return err
			}
			children = append(children, e)
			return nil
		})
		if err != nil {
			return err
		}
		sort.Slice(children, func(i, j int) bool {
			return names.APFS(children[i].Name, o.CaseSensitive, true) < names.APFS(children[j].Name, o.CaseSensitive, true)
		})
		for i, e := range children {
			if i > 0 && names.APFS(e.Name, o.CaseSensitive, true) == names.APFS(children[i-1].Name, o.CaseSensitive, true) {
				return fmt.Errorf("APFS name collision %q: %w", e.Name, filesystem.ErrConflict)
			}
			if err = visit(e.Object, obj.id, e.Name, depth+1); err != nil {
				return err
			}
		}
		obj.children = uint32(len(children))
		return nil
	}
	if err := visit(r.Root(), 1, "root", 0); err != nil {
		return err
	}
	if p.objects[0].node.Metadata.Mode.Value&0170000 != 0040000 {
		return fs.ErrInvalid
	}
	for _, obj := range p.objects {
		if len(obj.aliases) > 1 {
			for i := range obj.aliases {
				obj.aliases[i].id = p.nextID
				p.nextID++
			}
		}
		for i := range obj.attrs {
			if s := obj.attrs[i].stream; s != nil {
				s.id = p.nextID
				p.nextID++
				p.streams = append(p.streams, s)
			}
		}
		if obj.data != nil {
			obj.data.id = obj.id
			p.streams = append(p.streams, obj.data)
		}
	}
	for _, stream := range p.streams {
		stream.reader = r
	}
	return nil
}

func (p *volumeLayout) fingerprint(ctx context.Context) ([]byte, error) {
	h := sha256.New()
	options, _ := json.Marshal(p.options)
	_, _ = h.Write(options)
	for _, obj := range p.objects {
		meta, _ := json.Marshal(obj.node)
		_, _ = h.Write(meta)
		for _, a := range obj.aliases {
			_, _ = fmt.Fprintf(h, "%d:%d:%d:%s\x00", obj.id, a.parent, a.id, a.name)
		}
		_, _ = h.Write([]byte(obj.target))
		for _, a := range obj.attrs {
			_, _ = h.Write([]byte(a.name))
			_, _ = h.Write([]byte{0})
			_, _ = h.Write(a.inline)
		}
	}
	for _, stream := range p.streams {
		digest := sha256.New()
		if err := copyBuildStream(ctx, digest, stream, false); err != nil {
			return nil, err
		}
		copy(stream.digest[:], digest.Sum(nil))
		_, _ = h.Write(stream.digest[:])
	}
	return h.Sum(nil), ctx.Err()
}

func buildTime(t time.Time) (uint64, error) {
	if t.Unix() < 0 || t.Unix() > math.MaxInt64/1_000_000_000 || t.Unix() == math.MaxInt64/1_000_000_000 && int64(t.Nanosecond()) > math.MaxInt64%1_000_000_000 {
		return 0, fmt.Errorf("APFS timestamp out of nanosecond range: %w", filesystem.ErrUnsupported)
	}
	return uint64(t.UnixNano()), nil
}
func (p *volumeLayout) reserve(n int64) error {
	if n < 0 || n > (64<<20)-*p.budget {
		return filesystem.ErrLimit
	}
	*p.budget += n
	return nil
}
func (p *volumeLayout) validateObject(ctx context.Context, o *buildObject) error {
	n := o.node
	m := n.Metadata
	if m.Mode.State != filesystem.Present || m.UID.State != filesystem.Present || m.GID.State != filesystem.Present || m.BSDFlags.State != filesystem.Present || m.Mode.Value > 0177777 {
		return filesystem.ErrUnsupported
	}
	if m.BSDFlags.Value & ^uint32(0xff00ff|0x8000) != 0 {
		return filesystem.ErrUnsupported
	}
	for _, t := range []filesystem.Observation[time.Time]{m.BirthTime, m.ModifyTime, m.ChangeTime, m.AccessTime} {
		if t.State != filesystem.Present {
			return filesystem.ErrUnsupported
		}
		if _, err := buildTime(t.Value); err != nil {
			return err
		}
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
		o.data = &buildStream{source: o.source, size: size, blocks: uint64(size+4095) / 4096}
	case 0120000:
		target, err := p.reader.Readlink(ctx, o.source)
		if err != nil {
			return err
		}
		if len(target) == 0 || len(target) > 1023 || strings.ContainsRune(target, 0) {
			return filesystem.ErrUnsupported
		}
		o.target = target
	default:
		return filesystem.ErrUnsupported
	}
	if n.Compression.State != filesystem.Present && n.Compression.State != filesystem.Absent {
		return filesystem.ErrUnsupported
	}
	if (m.BSDFlags.Value&0x20 != 0) != (n.Compression.State == filesystem.Present) {
		return filesystem.ErrCorrupt
	}
	if n.Compression.State == filesystem.Present {
		if kind != 0100000 {
			return filesystem.ErrUnsupported
		}
		switch n.Compression.Value.Type {
		case 1, 3, 4, 7, 8:
		default:
			return fmt.Errorf("compression type %d: %w", n.Compression.Value.Type, filesystem.ErrUnsupported)
		}
		if o.data.size != 0 || n.Size > 1<<40 {
			return filesystem.ErrUnsupported
		}
		if err := p.validateCompression(ctx, o); err != nil {
			return err
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
		if name == "com.apple.fs.symlink" && kind == 0120000 {
			continue
		}
		if name == "" || len(name) > 127 || !utf8.ValidString(name) || strings.ContainsRune(name, 0) || strings.HasPrefix(name, "com.apple.fs.") {
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
		if err = p.reserve(512 + int64(len(name)) + min(size, 3802)); err != nil {
			return errors.Join(err, v.Close())
		}
		a := buildAttribute{name: name}
		if (size <= 1024 || name == filesystem.Decmpfs && size <= 3802) && name != filesystem.ResourceFork {
			a.inline = make([]byte, size)
			if err = block.ReadFull(v, a.inline, 0); err != nil {
				return errors.Join(err, v.Close())
			}
		} else {
			a.stream = &buildStream{source: o.source, attribute: name, size: size, blocks: uint64(size+4095) / 4096}
		}
		if err = v.Close(); err != nil {
			return err
		}
		if name == filesystem.FinderInfo && size != 32 {
			return filesystem.ErrUnsupported
		}
		if name == filesystem.ResourceFork && (kind != 0100000 || size == 0) {
			return filesystem.ErrUnsupported
		}
		o.attrs = append(o.attrs, a)
	}
	return nil
}

func (p *volumeLayout) validateCompression(ctx context.Context, o *buildObject) (err error) {
	open := func(name string) (filesystem.Value, error) { return p.reader.OpenAttribute(ctx, o.source, name) }
	h, err := decmpfs.Inspect(open)
	if err != nil {
		return err
	}
	if h.Type != o.node.Compression.Value.Type || h.Size != o.node.Size {
		return filesystem.ErrCorrupt
	}
	v, err := decmpfs.Open(ctx, open)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, v.Close()) }()
	buf := make([]byte, 65536)
	for off := int64(0); off < v.Size(); {
		if err = ctx.Err(); err != nil {
			return err
		}
		b := buf[:min(int64(len(buf)), v.Size()-off)]
		if err = block.ReadFull(v, b, off); err != nil {
			return err
		}
		off += int64(len(b))
	}
	return nil
}

func copyBuildStream(ctx context.Context, out io.Writer, s *buildStream, verify bool) (err error) {
	var v filesystem.Value
	if s.attribute == "" {
		v, err = s.reader.OpenRawData(ctx, s.source)
	} else {
		v, err = s.reader.OpenAttribute(ctx, s.source, s.attribute)
	}
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, v.Close()) }()
	if v.Size() != s.size {
		return filesystem.ErrConflict
	}
	h := sha256.New()
	if verify {
		out = io.MultiWriter(out, h)
	}
	buf := make([]byte, 128<<10)
	for off := int64(0); off < s.size; {
		if err = ctx.Err(); err != nil {
			return err
		}
		b := buf[:min(int64(len(buf)), s.size-off)]
		if err = block.ReadFull(v, b, off); err != nil {
			return err
		}
		n, e := out.Write(b)
		if e != nil {
			return e
		}
		if n != len(b) {
			return io.ErrShortWrite
		}
		off += int64(n)
	}
	if verify && string(h.Sum(nil)) != string(s.digest[:]) {
		return fmt.Errorf("APFS source changed: %w", filesystem.ErrConflict)
	}
	return ctx.Err()
}

func (p *Layout) Write(ctx context.Context, out io.Writer) error {
	if out == nil {
		return fs.ErrInvalid
	}
	zero := make([]byte, 128<<10)
	write := func(b []byte) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, err := out.Write(b)
		if err == nil && n != len(b) {
			err = io.ErrShortWrite
		}
		return err
	}
	var off int64
	padding := func(end int64) error {
		for off < end {
			b := zero[:min(int64(len(zero)), end-off)]
			if err := write(b); err != nil {
				return err
			}
			off += int64(len(b))
		}
		return nil
	}
	for _, part := range p.parts {
		if part.offset < off {
			return filesystem.ErrCorrupt
		}
		if err := padding(part.offset); err != nil {
			return err
		}
		if part.stream != nil {
			if err := copyBuildStream(ctx, out, part.stream, true); err != nil {
				return err
			}
			off += part.stream.size
		} else {
			if err := write(part.data); err != nil {
				return err
			}
			off += int64(len(part.data))
		}
	}
	if off > p.size {
		return filesystem.ErrCorrupt
	}
	if err := padding(p.size); err != nil {
		return err
	}
	return ctx.Err()
}
