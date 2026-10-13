package apfs_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type sparseMutationFile struct {
	*os.File
	size, offset int64
}

func (f *sparseMutationFile) Size() int64 { return f.size }
func (f *sparseMutationFile) Write(b []byte) (int, error) {
	var err error
	if bytes.Count(b, []byte{0}) == len(b) {
		err = f.Truncate(f.offset + int64(len(b)))
	} else {
		var n int
		n, err = f.WriteAt(b, f.offset)
		if err == nil && n != len(b) {
			err = io.ErrShortWrite
		}
	}
	if err != nil {
		return 0, err
	}
	f.offset += int64(len(b))
	return len(b), nil
}

func multipleVolumeInput(t *testing.T, quota int64) *sparseMutationFile {
	t.Helper()
	reader, options, _ := buildInput(t)
	layout, err := apfs.PlanContainer(context.Background(), []apfs.VolumeSpec{
		{Reader: reader, Name: "Untouched", Reserve: 8 << 20},
		{Reader: reader, Name: "Edited", Quota: quota},
	}, apfs.ContainerBuildOptions{Time: options.Time, Capacity: 768 << 20})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Create(filepath.Join(t.TempDir(), "owned.raw"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	disk := &sparseMutationFile{File: f, size: layout.Size()}
	if err = layout.Write(context.Background(), disk); err != nil {
		t.Fatal(err)
	}
	if err = apfs.ValidateMutation(context.Background(), disk); err != nil {
		t.Fatal(err)
	}
	return disk
}

func TestMultipleVolumeMutationRequiresSelectionAndPreservesOtherIdentity(t *testing.T) {
	ctx := context.Background()
	disk := multipleVolumeInput(t, 0)
	before, err := apfs.Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Unix(1749283750, 0)
	changes := []apfs.Change{{Path: "/file", Data: bytes.NewReader([]byte("Selected volume changed"))}}
	if _, err = apfs.Modify(ctx, disk, changes, when); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal("ambiguous selection", err)
	}
	if _, err = apfs.ModifyVolume(ctx, disk, "unknown", changes, when); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("unknown UUID", err)
	}
	id, err := before.Volumes[0].Lookup(ctx, 2, "file")
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := before.Volumes[0].Stat(ctx, id.Object)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = apfs.ModifyVolume(ctx, disk, before.Volumes[1].UUID, changes, when); err != nil {
		t.Fatal(err)
	}
	if err = apfs.ValidateMutation(ctx, disk); err != nil {
		t.Fatal(err)
	}
	after, err := apfs.Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	for i, expected := range []string{"original payload", "Selected volume changed"} {
		v := &after.Volumes[i]
		entry, err := v.Lookup(ctx, 2, "file")
		if err != nil {
			t.Fatal(err)
		}
		value, err := v.OpenData(ctx, entry.Object)
		if err != nil {
			t.Fatal(err)
		}
		got, err := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
		value.Close()
		if err != nil || string(got) != expected {
			t.Fatal(i, string(got), err)
		}
		if v.UUID != before.Volumes[i].UUID {
			t.Fatal("volume identity changed")
		}
		if i == 0 {
			node, err := v.Stat(ctx, entry.Object)
			if err != nil || entry.Object != id.Object || node.Metadata != metadata.Metadata {
				t.Fatal("untouched metadata changed", err)
			}
		}
	}
}

func TestMultipleVolumeQuotaRefusesGrowth(t *testing.T) {
	disk := multipleVolumeInput(t, 64<<10)
	container, err := apfs.Open(disk)
	if err != nil {
		t.Fatal(err)
	}
	_, err = apfs.ModifyVolume(context.Background(), disk, container.Volumes[1].UUID,
		[]apfs.Change{{Path: "/file", Data: bytes.NewReader(make([]byte, 128<<10))}}, time.Unix(1749283750, 0))
	if !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal("quota", err)
	}
}
