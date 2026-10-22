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

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/internal/completeoutput"
	"github.com/deploymenttheory/go-apfs-v3/internal/filesec"
)

type Options struct {
	ActorUID  filesystem.Observation[uint32] // logical creator/writer, independent of host credentials
	Partition int
	Volume    string    // APFS UUID or HFS volume ID; required when ambiguous
	Format    string    // UDRO or UDZO; default UDZO
	Time      time.Time // whole seconds; required for the library API
	// ImagePassword unlocks the source DMG envelope. Nil means no credential;
	// a non-nil empty slice supplies an explicitly empty password. VolumePassword
	// is a separate APFS credential. Software-encrypted APFS writes remain
	// unsupported, including after successful volume authentication.
	ImagePassword  []byte `json:"-"`
	VolumePassword []byte `json:"-"`
	// Encryption replaces the output envelope password and optionally its AES
	// strength. KeyBits zero retains the encrypted source's strength. Without
	// Encryption or Decrypt, source encryption and its password are preserved
	// using fresh cryptographic randomness. Passwords are borrowed, not modified.
	Encryption *diskimage.EncryptionOptions `json:"-"`
	// Decrypt explicitly removes source envelope encryption from the output.
	Decrypt bool
}
type Change = filesystem.Change

type Report struct {
	VolumeID    string                         `json:"volumeId"`
	Changed     []uint64                       `json:"changed"`
	FreeBlocks  uint64                         `json:"freeBlocks"`
	Transaction uint64                         `json:"transaction,omitempty"`
	Journal     *hfsplus.JournalReplayReport   `json:"journal,omitempty"`
	Checkpoint  *apfs.CheckpointRecoveryReport `json:"checkpoint,omitempty"`
	diskimage.RepackReport
}

// Apply streams the complete decoded disk into managed scratch, retaining all
// partitions and unrelated sectors. Changes address one selected filesystem partition.
// The new image is flushed and closed before atomic, no-overwrite publication.
// An error before publication leaves the destination absent and source intact.
// Abrupt process death may leave private scratch; source/destination remain safe.
// This is not HFS journal recovery or a universal power-loss durability promise.
func Apply(ctx context.Context, sourcePath, destination string, o Options, changes []Change) (Report, error) {
	if len(changes) == 0 {
		return Report{}, fs.ErrInvalid
	}
	return editImage(ctx, sourcePath, destination, o, func(view *mutablePartition, isAPFS bool) (Report, error) {
		return modify(ctx, view, isAPFS, changes, o.Time, o.Volume, o.ActorUID)
	})
}

func modify(ctx context.Context, view *mutablePartition, isAPFS bool, changes []Change, when time.Time, volume string, actor filesystem.Observation[uint32]) (report Report, err error) {
	if actor.State != filesystem.Uncaptured {
		changes = append([]Change(nil), changes...)
		for i := range changes {
			if changes[i].ActorUID.State == filesystem.Uncaptured {
				changes[i].ActorUID = actor
			}
		}
	}
	if isAPFS {
		changed, e := apfs.ModifyVolume(ctx, view, volume, changes, when)
		report.VolumeID, report.Changed, report.FreeBlocks, report.Transaction = changed.VolumeID, changed.Changed, changed.FreeBlocks, changed.Transaction
		return report, e
	}
	changed, e := hfsplus.Modify(ctx, view, changes, when)
	report.VolumeID, report.Changed, report.FreeBlocks = changed.VolumeID, changed.Changed, uint64(changed.FreeBlocks)
	return report, e
}

func editImage(ctx context.Context, sourcePath, destination string, o Options, mutation func(*mutablePartition, bool) (Report, error)) (report Report, err error) {
	if o.Time.IsZero() || o.Time.Nanosecond() != 0 {
		return report, fs.ErrInvalid
	}
	if err := filesec.ValidateActor(o.ActorUID); err != nil {
		return report, err
	}
	return transformImage(ctx, sourcePath, destination, o, nil, mutation)
}

func transformImage(ctx context.Context, sourcePath, destination string, o Options, admission func(block.Source, bool) error, mutation func(*mutablePartition, bool) (Report, error)) (report Report, err error) {
	published := false
	defer func() {
		if published {
			err = completeoutput.AfterPublication(destination, err)
		}
	}()
	if sourcePath == "" || destination == "" || mutation == nil {
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
	var image *diskimage.Image
	if o.ImagePassword != nil {
		image, err = diskimage.NewWithPassword(ctx, source, o.ImagePassword)
	} else {
		image, err = diskimage.New(source)
	}
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, image.Close()) }()
	encryption, err := o.outputEncryption(image.Encryption)
	if err != nil {
		return report, err
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
	var signature [36]byte
	if err = block.ReadFull(input, signature[:], 0); err != nil {
		return report, err
	}
	isAPFS := string(signature[32:36]) == "NXSB"
	validate := hfsplus.ValidateMutation
	if isAPFS {
		validate = apfs.ValidateMutation
	}
	// Admit supported ownership before staging the complete decoded disk.
	if admission == nil {
		admission = func(s block.Source, isAPFS bool) error {
			if isAPFS {
				container, err := apfs.Open(s)
				if err != nil {
					return err
				}
				volume, err := selectAPFSVolume(container, o.Volume)
				if err != nil {
					return err
				}
				if o.VolumePassword != nil {
					unlocked, err := volume.Unlock(ctx, o.VolumePassword)
					if err != nil {
						return err
					}
					if err := unlocked.Close(); err != nil {
						return err
					}
				}
				if volume.Encrypted {
					return fmt.Errorf("software-encrypted APFS image editing: %w", filesystem.ErrUnsupported)
				}
			} else if o.VolumePassword != nil {
				return fmt.Errorf("APFS volume password requires an encrypted APFS volume: %w", fs.ErrInvalid)
			} else if o.Volume != "" {
				volume, err := hfsplus.Open(s)
				if err != nil {
					return err
				}
				if volume.VolumeID != o.Volume {
					return fs.ErrNotExist
				}
			}
			return validate(ctx, s)
		}
	}
	if err = admission(input, isAPFS); err != nil {
		return report, err
	}

	if o.Format == "" {
		o.Format = "UDZO"
	}
	if o.Format != "UDRO" && o.Format != "UDZO" {
		return report, filesystem.ErrUnsupported
	}
	// Repack admission verifies source CRCs, complete sector coverage and the
	// supported UDIF resource profile. This pass does not retain output bytes.
	if _, err = diskimage.RepackWithOptions(ctx, io.Discard, source, diskimage.RepackOptions{Format: "UDRO", SourcePassword: o.ImagePassword, Decrypt: true}); err != nil {
		return report, err
	}
	disk, err := block.Stage(ctx, &decodedDisk{image}, "")
	if err != nil {
		return report, err
	}
	defer func() { err = errors.Join(err, disk.Close()) }()
	view := &mutablePartition{disk: disk, offset: partition.Offset, size: partition.Size}
	report, err = mutation(view, isAPFS)
	if err != nil {
		return report, err
	}
	// Reopen and account all current and pending-free blocks before publication.
	if err = validate(ctx, view); err != nil {
		return report, err
	}

	if err = disk.Sync(); err != nil {
		return report, err
	}
	err = completeoutput.Publish(ctx, destination, func(out io.Writer) error {
		var e error
		report.RepackReport, e = diskimage.RepackWithOptions(ctx, out, disk, diskimage.RepackOptions{Format: o.Format, Encryption: encryption})
		report.SourceEncryption = image.Encryption
		return e
	})
	var outcome *filesystem.PublishedOutputError
	published = err == nil || errors.As(err, &outcome)
	return report, err
}

func selectAPFSVolume(container *apfs.Container, id string) (*apfs.Volume, error) {
	if id == "" && len(container.Volumes) != 1 {
		return nil, fmt.Errorf("select --volume UUID in a multiple-volume APFS container: %w", fs.ErrInvalid)
	}
	for i := range container.Volumes {
		volume := &container.Volumes[i]
		if id == "" || volume.UUID == id {
			return volume, nil
		}
	}
	return nil, fs.ErrNotExist
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
