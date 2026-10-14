package block

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"testing"
)

func TestStagingPreservesZerosAndIsolatesChanges(t *testing.T) {
	for _, size := range []int{0, 17, 3*(128<<10) + 17} {
		original := make([]byte, size)
		if size > 17 {
			copy(original[128<<10:], "disk metadata")
		}
		directory := t.TempDir()
		stage, err := Stage(context.Background(), bytes.NewReader(original), directory)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { stage.Close() })
		path := stage.file.Name()
		info, err := os.Stat(path)
		if err != nil || info.Size() != int64(size) {
			t.Fatal("scratch length", info, err)
		}
		got := make([]byte, size)
		if err = ReadFull(stage, got, 0); err != nil || !bytes.Equal(got, original) {
			t.Fatal("staging changed disk bytes", err)
		}
		if size > 0 {
			if _, err = stage.WriteAt([]byte{0x5a}, int64(size-1)); err != nil {
				t.Fatal(err)
			}
			if err = stage.Sync(); err != nil {
				t.Fatal(err)
			}
			if err = ReadFull(stage, got, 0); err != nil || got[size-1] != 0x5a || original[size-1] != 0 {
				t.Fatal("writing a zero range did not isolate the change", err)
			}
		}
		if err = stage.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err = os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatal("closed staging retained scratch", err)
		}
	}
}

type interruptedStagingSource struct {
	cancel context.CancelFunc
	fail   error
}

func (s interruptedStagingSource) Size() int64 { return 3 * (128 << 10) }
func (s interruptedStagingSource) ReadAt(p []byte, off int64) (int, error) {
	if off > 0 {
		return 0, s.fail
	}
	clear(p)
	p[0] = 0x5a
	if s.cancel != nil {
		s.cancel()
	}
	return len(p), nil
}

func TestStagingDiscardsInterruptedCopy(t *testing.T) {
	readFailure := errors.New("source read failed")
	for _, failure := range []error{readFailure, context.Canceled} {
		ctx, cancel := context.WithCancel(context.Background())
		source := interruptedStagingSource{fail: readFailure}
		if failure == context.Canceled {
			source.cancel = cancel
		}
		directory := t.TempDir()
		stage, err := Stage(ctx, source, directory)
		cancel()
		if stage != nil || !errors.Is(err, failure) {
			t.Fatal("interrupted staging result", stage, err)
		}
		files, err := os.ReadDir(directory)
		if err != nil || len(files) != 0 {
			t.Fatal("interrupted staging retained partial disk", files, err)
		}
	}
}

// Two distant nonzero bytes exercise large unwritten ranges without retaining
// a disk-sized buffer. This also models metadata near the end of an empty disk.
type sparseStagingSource struct{ size int64 }

func (s sparseStagingSource) Size() int64 { return s.size }
func (s sparseStagingSource) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, os.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= s.size {
		return 0, io.EOF
	}
	n := int(min(int64(len(p)), s.size-off))
	clear(p[:n])
	for _, position := range []int64{0, s.size - 1} {
		if position >= off && position-off < int64(n) {
			p[position-off] = 0x5a
		}
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func BenchmarkStageSparseDisk(b *testing.B) {
	source := sparseStagingSource{size: 64 << 20}
	directory := b.TempDir()
	b.SetBytes(source.Size())
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		stage, err := Stage(context.Background(), source, directory)
		if err != nil {
			b.Fatal(err)
		}
		if err = stage.Close(); err != nil {
			b.Fatal(err)
		}
	}
}
