// Package pack constructs new filesystem images from immutable logical readers.
// It neither mutates source images nor interprets command-line file operations.
package pack

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
)

type Options struct {
	Volume hfsplus.BuildOptions
	Format string
}
type Report struct {
	Format      string `json:"format"`
	Filesystem  string `json:"filesystem"`
	VolumeBytes int64  `json:"volumeBytes"`
	ImageBytes  int64  `json:"imageBytes"`
}

// Write streams a fresh volume through the DMG encoder. The caller owns the
// output and discards it on error. The reader is borrowed and must remain fixed.
func Write(ctx context.Context, out io.Writer, r filesystem.Reader, o Options) (Report, error) {
	var report Report
	if out == nil {
		return report, fs.ErrInvalid
	}
	if o.Format == "" {
		o.Format = "UDZO"
	}
	if o.Format != "UDRO" && o.Format != "UDZO" {
		return report, filesystem.ErrUnsupported
	}
	layout, err := hfsplus.Plan(ctx, r, o.Volume)
	if err != nil {
		return report, err
	}
	input, producer := io.Pipe()
	done := make(chan error, 1)
	go func() { err := layout.Write(ctx, producer); _ = producer.CloseWithError(err); done <- err }()
	counter := &countWriter{out: out}
	err = diskimage.Encode(ctx, counter, input, layout.Size(), o.Format)
	_ = input.CloseWithError(err)
	err = errors.Join(err, <-done)
	if err != nil {
		return report, err
	}
	report = Report{Format: o.Format, Filesystem: "HFS+", VolumeBytes: layout.Size(), ImageBytes: counter.count}
	if o.Volume.CaseSensitive {
		report.Filesystem = "HFSX"
	}
	return report, nil
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
	if _, e := os.Lstat(path); e == nil {
		return report, fs.ErrExist
	} else if !errors.Is(e, fs.ErrNotExist) {
		return report, e
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".apfs-pack-*")
	if err != nil {
		return report, err
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
	report, err = Write(ctx, f, r, o)
	if err != nil {
		return report, err
	}
	if err = f.Sync(); err != nil {
		return report, err
	}
	err = f.Close()
	closed = true
	if err != nil {
		return report, err
	}
	if err = ctx.Err(); err != nil {
		return report, err
	}
	err = os.Link(temporary, path)
	published = err == nil
	return report, err
}
