package native

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"syscall"
)

const (
	unreservedPressureChunk = 512 << 10
	unreservedPressureBound = 256 << 20
)

// fillUnreservedPressure follows the retained native Capture.fill geometry:
// independent zero-filled 512 KiB files, each written exclusively and synced.
// Unlike the capture, every partial final file is retained and accounted for
// until the protected allocation succeeds, then its cleanup must also succeed.
func (v *Verifier) fillUnreservedPressure(ctx context.Context, directory string) ([]string, error) {
	if err := v.Vol.Mkdir(directory, 0o755); err != nil {
		return nil, fmt.Errorf("create pressure directory %q: %w", directory, err)
	}
	chunk := make([]byte, unreservedPressureChunk)
	var files []string
	synced := 0
	for i := 0; i < unreservedPressureBound/unreservedPressureChunk; i++ {
		if err := ctx.Err(); err != nil {
			return nil, fmt.Errorf("fill pressure directory %q: %w", directory, err)
		}
		filename := filepath.Join(directory, fmt.Sprintf("%05d", i))
		err := v.Vol.WriteFile(filename, chunk, true)
		written := err == nil
		operation := "write"
		if written {
			files = append(files, filename)
			err = v.Vol.Fullfsync(filename)
			operation = "sync"
		}
		if err == nil {
			synced++
			continue
		}
		if !errors.Is(err, syscall.ENOSPC) {
			return nil, fmt.Errorf("%s pressure file %q: %w", operation, filename, err)
		}
		// WriteFile may fail before creating an inode or after a partial
		// write. A failed sync must still have the fully written file.
		stat, statErr := v.Vol.Lstat(filename)
		switch {
		case !written && errors.Is(statErr, fs.ErrNotExist):
			// Explicitly confirmed absent; there is no file to unlink.
		case statErr != nil:
			return nil, fmt.Errorf("stat exhausted pressure file %q: %w", filename, statErr)
		case stat.Kind != "file" || stat.Size < 0 || stat.Size > int64(len(chunk)) || (written && stat.Size != int64(len(chunk))):
			return nil, fmt.Errorf("exhausted pressure file %q has unexpected kind %q or size %d", filename, stat.Kind, stat.Size)
		case !written:
			files = append(files, filename)
		}
		if synced == 0 {
			return nil, fmt.Errorf("pressure at %q reached ENOSPC before any complete synced file", directory)
		}
		return files, nil
	}
	return nil, fmt.Errorf("native allocation pressure at %q did not reach ENOSPC within %d bytes", directory, unreservedPressureBound)
}

func (v *Verifier) releaseUnreservedPressure(directory string, files []string) error {
	// Unlink small inodes in creation order without introducing the large
	// truncate-to-zero transition. The clean close/reopen and later real
	// allocations, rather than these calls alone, establish durable release.
	for _, filename := range files {
		if err := v.Vol.Remove(filename); err != nil {
			return fmt.Errorf("unlink pressure file %q: %w", filename, err)
		}
	}
	if err := v.Vol.Rmdir(directory); err != nil {
		return fmt.Errorf("remove pressure directory %q: %w", directory, err)
	}
	return nil
}
