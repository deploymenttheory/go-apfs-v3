package imageedit

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/internal/copyfile"
	"github.com/deploymenttheory/go-apfs-v3/internal/edit"
)

type CopyOptions = copyfile.Options
type CopyOmission = copyfile.Omission

// CopyCommand is an ordered library operation; the CLI supplies one command.
// A batch shares managed scratch and publishes one completed image.
type CopyCommand struct {
	Sources     []string
	Destination string
	Options     CopyOptions
}

type CopyDefault struct {
	Path   string   `json:"path"`
	Fields []string `json:"fields"`
}

type CopyReport struct {
	Report
	Copied                int            `json:"copied"`
	Defaulted             []CopyDefault  `json:"defaulted,omitempty"`
	AttributesUnavailable []string       `json:"attributesUnavailable,omitempty"`
	OmittedAttributes     []CopyOmission `json:"omittedAttributes,omitempty"`
}

// Copy uses the same policy and logical tree as sessions. Inputs are streamed
// into owned scratch before disk mutation, including host identity checks at
// value close. All batches remain private until one completed image is published.
func Copy(ctx context.Context, sourcePath, destination string, o Options, sources []string, to string, options CopyOptions) (result CopyReport, err error) {
	return CopyBatch(ctx, sourcePath, destination, o, []CopyCommand{{sources, to, options}})
}

func CopyBatch(ctx context.Context, sourcePath, destination string, o Options, commands []CopyCommand) (result CopyReport, err error) {
	if len(commands) == 0 || len(commands) > 4096 {
		return result, fs.ErrInvalid
	}
	result.Report, err = Edit(ctx, sourcePath, destination, o, func(editor *Editor) error {
		copied, e := editor.Copy(commands)
		result.Copied, result.Defaulted = copied.Copied, copied.Defaulted
		result.AttributesUnavailable, result.OmittedAttributes = copied.AttributesUnavailable, copied.OmittedAttributes
		return e
	})
	return result, err
}

func copyTo(ctx context.Context, view *mutablePartition, isAPFS bool, o Options, commands []CopyCommand) (result CopyReport, err error) {
	if len(commands) == 0 || len(commands) > 4096 {
		return result, fs.ErrInvalid
	}
	var reader filesystem.Reader
	if isAPFS {
		container, e := apfs.Open(view)
		if e != nil {
			return result, e
		}
		reader, e = selectAPFSVolume(container, o.Volume)
		if e != nil {
			return result, e
		}
	} else {
		volume, e := hfsplus.Open(view)
		if e != nil {
			return result, e
		}
		reader = volume
	}
	limits := edit.DefaultLimits()
	// Payload admission follows the validated partition geometry. Traversal
	// and record counts retain independent bounds; payloads stream to disk.
	limits.ValueBytes, limits.TotalBytes = view.Size(), view.Size()
	tree, e := edit.New(ctx, reader, limits)
	if e != nil {
		return result, e
	}
	plan := copyPlan{tree: tree, changed: map[string]bool{}, limits: limits}
	defer func() { err = errors.Join(err, plan.close()) }()
	backend := copyfile.Backend{Tree: tree, Time: o.Time, Umask: 022, Limits: limits, Apply: plan.apply, Own: plan.own,
		CreateMetadata: func(ctx context.Context, dst string, kind uint32) (filesystem.Metadata, error) {
			id, _, err := copyfile.Resolve(ctx, tree, path.Dir(dst), true)
			if err != nil {
				return filesystem.Metadata{}, err
			}
			parent, err := tree.Stat(ctx, id)
			if err != nil {
				return filesystem.Metadata{}, err
			}
			uid := parent.Metadata.UID
			if o.ActorUID.State == filesystem.Present {
				uid = o.ActorUID
			}
			return filesystem.Metadata{Mode: filesystem.Observed(kind), UID: uid, GID: parent.Metadata.GID, BSDFlags: filesystem.Observed(uint32(0)), BirthTime: filesystem.Observed(o.Time), ModifyTime: filesystem.Observed(o.Time), ChangeTime: filesystem.Observed(o.Time), AccessTime: filesystem.Observed(o.Time)}, nil
		},
		Modified: func(ctx context.Context, p string) error { plan.changed[p] = true; return ctx.Err() },
		Omitted:  func(value copyfile.Omission) { result.OmittedAttributes = append(result.OmittedAttributes, value) },
	}
	for _, command := range commands {
		if len(command.Sources) == 0 || command.Destination == "" {
			return result, fs.ErrInvalid
		}
		if err = copyfile.Run(ctx, backend, command.Sources, command.Destination, command.Options); err != nil {
			return result, err
		}
	}
	if err = plan.finish(ctx, &result); err != nil {
		return result, err
	}
	// Fixed batches retain existing mutation limits while larger trees keep
	// a single command publication boundary. Payloads are already immutable.
	for len(plan.changes) > 0 {
		n := min(4096, len(plan.changes))
		batch, err := modify(ctx, view, isAPFS, plan.changes[:n], o.Time, o.Volume, o.ActorUID)
		if err != nil {
			return result, err
		}
		result.VolumeID, result.FreeBlocks, result.Transaction = batch.VolumeID, batch.FreeBlocks, batch.Transaction
		result.Changed = append(result.Changed, batch.Changed...)
		plan.changes = plan.changes[n:]
	}
	return result, nil
}

type copyPlan struct {
	tree    *edit.Tree
	changes []Change
	changed map[string]bool
	payload *os.File
	size    int64
	values  []filesystem.Value
	limits  edit.Limits
}

func (p *copyPlan) own(ctx context.Context, v filesystem.Value, total *int64) (result block.Source, err error) {
	defer func() { err = errors.Join(err, v.Close()) }()
	if v.Size() < 0 {
		return nil, filesystem.ErrCorrupt
	}
	if v.Size() > p.limits.ValueBytes || v.Size() > p.limits.TotalBytes-*total || v.Size() > p.limits.TotalBytes-p.size {
		return nil, filesystem.ErrLimit
	}
	*total += v.Size()
	if p.payload == nil {
		p.payload, err = os.CreateTemp("", ".apfs-copy-data-*")
		if err != nil {
			return nil, err
		}
	}
	start := p.size
	buf := make([]byte, 128<<10)
	for off := int64(0); off < v.Size(); {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		n := min(int64(len(buf)), v.Size()-off)
		if err = block.ReadFull(v, buf[:n], off); err != nil {
			return nil, err
		}
		written, e := p.payload.WriteAt(buf[:n], start+off)
		if e != nil {
			return nil, e
		}
		if int64(written) != n {
			return nil, io.ErrShortWrite
		}
		off += n
	}
	p.size += v.Size()
	return &copyValue{io.NewSectionReader(p.payload, start, v.Size()), v.Size()}, nil
}

func (p *copyPlan) close() error {
	var err error
	for _, value := range p.values {
		err = errors.Join(err, value.Close())
	}
	if p.payload != nil {
		err = errors.Join(err, p.payload.Close(), os.Remove(p.payload.Name()))
	}
	return err
}

func (p *copyPlan) apply(ctx context.Context, change edit.Change) error {
	if err := p.tree.ApplyCommand(ctx, change); err != nil {
		return err
	}
	c := Change{Path: change.Path}
	switch change.Op {
	case edit.CreateDirectory:
		c.Operation = "mkdir"
	case edit.CreateFile, edit.ReplaceFileData:
		c.Operation, c.Data = "cp", change.Data
	case edit.CreateSymlink:
		c = Change{Operation: "ln", Path: change.Target, Destination: change.Path, Symbolic: true}
	case edit.CreateHardLink:
		c = Change{Operation: "ln", Path: change.Path, Destination: change.To}
	case edit.RemoveEntry:
		c.Operation = "rm"
	case edit.SetMetadata, edit.RemoveAttribute:
		// Final values are coalesced below after directory traversal, so
		// parent clocks and copied directory metadata cannot overwrite each other.
		p.changed[change.Path] = true
		return nil
	default:
		return filesystem.ErrUnsupported
	}
	p.changes = append(p.changes, c)
	return nil
}

func (p *copyPlan) finish(ctx context.Context, report *CopyReport) error {
	paths := make([]string, 0, len(p.changed))
	for text := range p.changed {
		paths = append(paths, text)
	}
	sort.Slice(paths, func(i, j int) bool {
		left, right := strings.Count(paths[i], "/"), strings.Count(paths[j], "/")
		if left != right {
			return left > right
		}
		return paths[i] < paths[j]
	})
	seen := map[uint64]bool{}
	for _, text := range paths {
		id, canonical, err := copyfile.Resolve(ctx, p.tree, text, false)
		if err != nil {
			return err
		}
		node, err := p.tree.Stat(ctx, id)
		if err != nil {
			return err
		}
		report.Copied++
		if len(node.MetadataDefaulted) > 0 {
			report.Defaulted = append(report.Defaulted, CopyDefault{canonical, slices.Clone(node.MetadataDefaulted)})
		}
		if node.AttributesUnavailable {
			report.AttributesUnavailable = append(report.AttributesUnavailable, canonical)
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		metadata := node.Metadata
		metadata.ChangeTime = filesystem.Observation[time.Time]{}
		c := Change{Operation: "copy-metadata", Path: canonical, Metadata: &metadata, NoFollow: true, Attributes: map[string]block.Source{}}
		for _, name := range node.AttributesModified {
			if strings.HasPrefix(name, "com.apple.fs.") {
				continue
			}
			value, err := p.tree.OpenAttribute(ctx, id, name)
			if errors.Is(err, fs.ErrNotExist) {
				c.RemoveAttributes = append(c.RemoveAttributes, name)
				continue
			}
			if err != nil {
				return err
			}
			// A tree value may wrap an owned payload. Borrow that immutable
			// source rather than creating another scratch copy.
			c.Attributes[name] = value
			p.values = append(p.values, value)
		}
		p.changes = append(p.changes, c)
	}
	return nil
}

type copyValue struct {
	*io.SectionReader
	size int64
}

func (v *copyValue) Size() int64 { return v.size }
