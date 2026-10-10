package pack

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
)

type RepackReport struct {
	diskimage.RepackReport
	ImageBytes int64 `json:"imageBytes"`
}

// Repack converts a complete raw/UDIF image into a new DMG without changing
// any decoded sectors. It owns a read-only source file. Publication has the same
// no-overwrite and completed-file contract as Create. Filesystem construction
// options and passwords are deliberately absent from this operation.
func Repack(ctx context.Context, sourcePath, destination string, format string) (report RepackReport, err error) {
	info, err := os.Stat(sourcePath)
	if err != nil {
		return report, err
	}
	if !info.Mode().IsRegular() {
		return report, fs.ErrInvalid
	}
	source, err := block.Open(sourcePath)
	if err != nil {
		return report, err
	}
	closed := false
	defer func() {
		if !closed {
			err = errors.Join(err, source.Close())
		}
	}()
	err = publish(ctx, destination, func(out io.Writer) error {
		counter := &countWriter{out: out}
		var e error
		report.RepackReport, e = diskimage.Repack(ctx, counter, source, format)
		report.ImageBytes = counter.count
		closeErr := source.Close()
		closed = true
		return errors.Join(e, closeErr)
	})
	return report, err
}
