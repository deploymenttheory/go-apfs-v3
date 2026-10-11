// Package pack constructs filesystem images and repacks complete disks.
// It neither mutates source images nor interprets command-line file operations.
package pack

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
)

type Options struct {
	Volume     VolumeOptions
	Format     string
	Encryption *diskimage.EncryptionOptions
}

// VolumeOptions supplies fresh construction choices. The reader's native format
// selects the engine; filesystem conversion is not implicit. VolumeID belongs to
// HFS; the two UUIDs belong to APFS. Inapplicable identity options are refused.
type VolumeOptions struct {
	Name                      string
	CaseSensitive             bool
	Capacity                  int64
	Time                      time.Time
	VolumeID                  [8]byte
	VolumeUUID, ContainerUUID [16]byte
}

type layout interface {
	Size() int64
	Write(context.Context, io.Writer) error
}
type Report struct {
	Format      string                `json:"format"`
	Filesystem  string                `json:"filesystem"`
	VolumeBytes int64                 `json:"volumeBytes"`
	ImageBytes  int64                 `json:"imageBytes"`
	Encryption  *diskimage.Encryption `json:"encryption,omitempty"`
}

// Write streams a fresh volume through the DMG encoder. The caller owns the
// output and discards it on error. The reader is borrowed and must remain fixed.
// Encrypted output requires an empty io.WriteSeeker and uses fresh randomness.
func Write(ctx context.Context, out io.Writer, r filesystem.Reader, o Options) (Report, error) {
	var report Report
	if out == nil || r == nil {
		return report, fs.ErrInvalid
	}
	if o.Encryption != nil {
		if err := o.Encryption.Validate(); err != nil {
			return report, err
		}
	}
	if o.Format == "" {
		o.Format = "UDZO"
	}
	if o.Format != "UDRO" && o.Format != "UDZO" {
		return report, filesystem.ErrUnsupported
	}
	var plan layout
	var err error
	hint := "Apple_HFS"
	v := o.Volume
	switch r.NameRules().Format {
	case "APFS":
		if v.VolumeID != [8]byte{} {
			return report, fs.ErrInvalid
		}
		hint = "Apple_APFS"
		plan, err = apfs.Plan(ctx, r, apfs.BuildOptions{Name: v.Name, CaseSensitive: v.CaseSensitive, Capacity: v.Capacity, Time: v.Time, VolumeUUID: v.VolumeUUID, ContainerUUID: v.ContainerUUID})
	case "HFS+":
		if v.VolumeUUID != [16]byte{} || v.ContainerUUID != [16]byte{} {
			return report, fs.ErrInvalid
		}
		plan, err = hfsplus.Plan(ctx, r, hfsplus.BuildOptions{Name: v.Name, CaseSensitive: v.CaseSensitive, Capacity: v.Capacity, Time: v.Time, VolumeID: v.VolumeID})
	default:
		return report, filesystem.ErrUnsupported
	}
	if err != nil {
		return report, err
	}
	imageBytes, err := encodeLayout(ctx, out, plan, o.Format, hint, o.Encryption)
	if err != nil {
		return report, err
	}
	report = Report{Format: o.Format, Filesystem: r.NameRules().Format, VolumeBytes: plan.Size(), ImageBytes: imageBytes, Encryption: encryptionInfo(o.Encryption)}
	if report.Filesystem == "HFS+" && o.Volume.CaseSensitive {
		report.Filesystem = "HFSX"
	}
	return report, nil
}

// ContainerOptions packages a fresh APFS container with one or more volumes.
type ContainerOptions struct {
	APFS       apfs.ContainerBuildOptions
	Format     string
	Encryption *diskimage.EncryptionOptions
}

type ContainerReport struct {
	Format         string                `json:"format"`
	VolumeCount    int                   `json:"volumeCount"`
	ContainerBytes int64                 `json:"containerBytes"`
	ImageBytes     int64                 `json:"imageBytes"`
	Encryption     *diskimage.Encryption `json:"encryption,omitempty"`
}

// WriteContainer streams one fresh APFS container through the DMG encoder.
// It borrows every immutable reader through completion. Discard output on error.
// Encrypted output requires an empty io.WriteSeeker and uses fresh randomness.
func WriteContainer(ctx context.Context, out io.Writer, volumes []apfs.VolumeSpec, o ContainerOptions) (ContainerReport, error) {
	var report ContainerReport
	if out == nil {
		return report, fs.ErrInvalid
	}
	if o.Encryption != nil {
		if err := o.Encryption.Validate(); err != nil {
			return report, err
		}
	}
	if o.Format == "" {
		o.Format = "UDZO"
	}
	if o.Format != "UDRO" && o.Format != "UDZO" {
		return report, filesystem.ErrUnsupported
	}
	plan, err := apfs.PlanContainer(ctx, volumes, o.APFS)
	if err != nil {
		return report, err
	}
	n, err := encodeLayout(ctx, out, plan, o.Format, "Apple_APFS", o.Encryption)
	if err != nil {
		return report, err
	}
	return ContainerReport{Format: o.Format, VolumeCount: len(volumes), ContainerBytes: plan.Size(), ImageBytes: n, Encryption: encryptionInfo(o.Encryption)}, nil
}

// CreateContainer uses the same no-overwrite publication contract as Create.
func CreateContainer(ctx context.Context, path string, volumes []apfs.VolumeSpec, o ContainerOptions) (report ContainerReport, err error) {
	err = publish(ctx, path, func(out io.Writer) error { report, err = WriteContainer(ctx, out, volumes, o); return err })
	return report, err
}

func encodeLayout(ctx context.Context, out io.Writer, plan layout, format, hint string, encryption *diskimage.EncryptionOptions) (int64, error) {
	if encryption != nil {
		seeker, ok := out.(io.WriteSeeker)
		if !ok {
			return 0, fmt.Errorf("encrypted output requires a seekable destination: %w", fs.ErrInvalid)
		}
		return diskimage.Encrypt(ctx, seeker, *encryption, func(w io.Writer) error {
			_, err := encodeLayout(ctx, w, plan, format, hint, nil)
			return err
		})
	}
	input, producer := io.Pipe()
	done := make(chan error, 1)
	go func() { err := plan.Write(ctx, producer); _ = producer.CloseWithError(err); done <- err }()
	counter := &countWriter{out: out}
	err := diskimage.EncodeVolume(ctx, counter, input, plan.Size(), format, hint)
	_ = input.CloseWithError(err)
	return counter.count, errors.Join(err, <-done)
}

type countWriter struct {
	out   io.Writer
	count int64
}

func (w *countWriter) Write(b []byte) (int, error) {
	n, err := w.out.Write(b)
	w.count += int64(n)
	return n, err
}

// Create publishes a completed image at a new path without replacing an existing
// entry. A sibling temporary file keeps failures unpublished. The hard-link
// publication is atomic and refuses an existing file, directory or symlink.
// Power-loss directory durability is outside this fresh-output contract.
func Create(ctx context.Context, path string, r filesystem.Reader, o Options) (report Report, err error) {
	err = publish(ctx, path, func(out io.Writer) error {
		report, err = Write(ctx, out, r, o)
		return err
	})
	return report, err
}

// publish is shared by fresh filesystem builds and sector-preserving repacks.
func publish(ctx context.Context, path string, write func(io.Writer) error) (err error) {
	if _, e := os.Lstat(path); e == nil {
		return fs.ErrExist
	} else if !errors.Is(e, fs.ErrNotExist) {
		return e
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".apfs-pack-*")
	if err != nil {
		return err
	}
	temporary := f.Name()
	closed := false
	published := false
	defer func() {
		if !closed {
			err = errors.Join(err, f.Close())
		}
		removeErr := os.Remove(temporary)
		if !published && !errors.Is(removeErr, fs.ErrNotExist) {
			err = errors.Join(err, removeErr)
		}
	}()
	err = write(f)
	if err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	err = f.Close()
	closed = true
	if err != nil {
		return err
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	err = os.Link(temporary, path)
	published = err == nil
	return err
}

func encryptionInfo(o *diskimage.EncryptionOptions) *diskimage.Encryption {
	if o == nil {
		return nil
	}
	return &diskimage.Encryption{Version: 2, Cipher: "AES-CBC", KeyBits: o.KeyBits, BlockSize: 512}
}
