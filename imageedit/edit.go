// Package imageedit modifies existing filesystem structures in a private disk
// copy and publishes a completed image. Its source is always opened read-only.
package imageedit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/internal/completeoutput"
)

type Options struct {
	Partition int
	Format    string    // UDRO or UDZO; default UDZO
	Time      time.Time // whole seconds; required for the library API
}
type Report struct {
	hfsplus.ChangeReport
	diskimage.RepackReport
}

// Apply streams the complete decoded disk into managed scratch, retaining all
// partitions and unrelated sectors. Changes address one selected HFS partition.
// The new image is flushed and closed before atomic, no-overwrite publication.
// An error before publication leaves the destination absent and source intact.
// Abrupt process death may leave private scratch; source/destination remain safe.
// This is not HFS journal recovery or a universal power-loss durability promise.
func Apply(ctx context.Context, sourcePath, destination string, o Options, changes []hfsplus.Change) (report Report, err error) {
	if sourcePath == "" || destination == "" || len(changes) == 0 {
		return report, fs.ErrInvalid
	}
	if _, e := os.Lstat(destination); e == nil {
		return report, fs.ErrExist
	} else if !errors.Is(e, fs.ErrNotExist) {
		return report, e
	}
	source, err := block.Open(sourcePath)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, source.Close()) }()
	image, err := diskimage.New(source)
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, image.Close()) }()
	if image.Encryption != nil {
		return report, fmt.Errorf("encrypted image modification: %w", filesystem.ErrUnsupported)
	}
	var partition *diskimage.Partition
	for i := range image.Partitions {
		if image.Partitions[i].Index == o.Partition {
			partition = &image.Partitions[i]
			break
		}
	}
	if partition == nil {
		return report, fs.ErrNotExist
	}
	input, err := image.Partition(o.Partition)
	if err != nil {
		return report, err
	}
	// Fail unsupported filesystem/profile admission before copying disk bytes.
	volume, err := hfsplus.Open(input)
	if err != nil {
		return report, err
	}
	if volume.Journaled || !volume.Clean {
		return report, fmt.Errorf("image edits require clean nonjournaled HFS+/HFSX: %w", filesystem.ErrUnsupported)
	}
	if o.Format == "" {
		o.Format = "UDZO"
	}
	if o.Format != "UDRO" && o.Format != "UDZO" {
		return report, filesystem.ErrUnsupported
	}
	// Repack admission verifies source CRCs, complete sector coverage and the
	// supported UDIF resource profile. This pass does not retain output bytes.
	if _, err = diskimage.Repack(ctx, io.Discard, source, "UDRO"); err != nil {
		return report, err
	}
	disk, err := block.Stage(ctx, &decodedDisk{image}, "")
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, disk.Close()) }()
	view := &mutablePartition{disk: disk, offset: partition.Offset, size: partition.Size}
	report.ChangeReport, err = hfsplus.Modify(ctx, view, changes, o.Time)
	if err != nil {
		return report, err
	}
	// Reopen and account every referenced block after mutation, before output.
	if err = hfsplus.ValidateMutation(ctx, view); err != nil {
		return report, err
	}
	if err = disk.Sync(); err != nil {
		return report, err
	}
	err = completeoutput.Publish(ctx, destination, func(out io.Writer) error {
		var e error
		report.RepackReport, e = diskimage.Repack(ctx, out, disk, o.Format)
		return e
	})
	return report, err
}

type decodedDisk struct{ image *diskimage.Image }

func (d *decodedDisk) Size() int64                             { return d.image.Size() }
func (d *decodedDisk) ReadAt(p []byte, off int64) (int, error) { return d.image.ReadAt(p, off) }

type mutablePartition struct {
	disk         *block.Staging
	offset, size int64
}

func (p *mutablePartition) Size() int64 { return p.size }
func (p *mutablePartition) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if len(b) == 0 {
		return 0, nil
	}
	if off >= p.size {
		return 0, io.EOF
	}
	n, e := p.disk.ReadAt(b[:min(int64(len(b)), p.size-off)], p.offset+off)
	if n < len(b) && e == nil {
		e = io.EOF
	}
	return n, e
}
func (p *mutablePartition) WriteAt(b []byte, off int64) (int, error) {
	if off < 0 || off > p.size || int64(len(b)) > p.size-off {
		return 0, fs.ErrInvalid
	}
	return p.disk.WriteAt(b, p.offset+off)
}
