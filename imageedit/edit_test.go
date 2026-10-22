package imageedit_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

var clock = time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)

func fixture(t *testing.T, formats ...string) string {
	t.Helper()
	ctx := context.Background()
	root := t.TempDir()
	format := "HFS+"
	if len(formats) != 0 {
		format = formats[0]
	}
	names := filesystem.NameRules{Format: format, NormalizationInsensitive: true}
	switch format {
	case "HFSX":
		names.Format, names.CaseSensitive = "HFS+", true
	case "APFSX":
		names.Format, names.CaseSensitive = "APFS", true
	}
	s, e := session.Create(ctx, filepath.Join(root, "session"), session.Options{Names: names, Time: &clock})
	if e != nil {
		t.Fatal(e)
	}
	defer s.Close()
	host := filepath.Join(root, "host")
	if e = os.WriteFile(host, []byte("existing"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = s.Copy(ctx, []string{host}, "/file", session.CopyOptions{FromHost: true}); e != nil {
		t.Fatal(e)
	}
	source := filepath.Join(root, "source.dmg")
	if _, e = pack.Create(ctx, source, s, pack.Options{Volume: pack.VolumeOptions{Name: "Keep", Time: clock, Capacity: 16 << 20, CaseSensitive: names.CaseSensitive}}); e != nil {
		t.Fatal(e)
	}
	return source
}
func TestExistingImageOutputPreservesSourceAndIsReproducible(t *testing.T) {
	ctx := context.Background()
	source := fixture(t)
	original, e := os.ReadFile(source)
	if e != nil {
		t.Fatal(e)
	}
	for _, format := range []string{"UDRO", "UDZO"} {
		var previous [32]byte
		for repeat := 0; repeat < 2; repeat++ {
			out := filepath.Join(t.TempDir(), "edited.dmg")
			report, e := imageedit.Apply(ctx, source, out, imageedit.Options{Format: format, Time: clock}, []hfsplus.Change{{Path: "/FILE", Data: bytes.NewReader(bytes.Repeat([]byte("growth"), 40000))}, {Path: "/file", Mode: "0755"}})
			if e != nil {
				t.Fatal(e)
			}
			img, e := diskimage.Open(out)
			if e != nil {
				t.Fatal(e)
			}
			p, e := img.Partition(0)
			if e != nil {
				t.Fatal(e)
			}
			v, e := hfsplus.Open(p)
			if e != nil {
				t.Fatal(e)
			}
			if report.VolumeID != v.VolumeID || v.Name != "Keep" {
				t.Fatal("filesystem identity changed")
			}
			if e = hfsplus.ValidateMutation(ctx, p); e != nil {
				t.Fatal(e)
			}
			img.Close()
			encoded, e := os.ReadFile(out)
			if e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256(encoded)
			if repeat > 0 && sum != previous {
				t.Fatal("nonreproducible mutation")
			}
			previous = sum
			if _, e = imageedit.Apply(ctx, source, out, imageedit.Options{Time: clock}, []hfsplus.Change{{Path: "/file", Mode: "0600"}}); !errors.Is(e, fs.ErrExist) {
				t.Fatal("overwrote destination", e)
			}
		}
	}
	after, e := os.ReadFile(source)
	if e != nil || !bytes.Equal(after, original) {
		t.Fatal("source changed", e)
	}
	for _, change := range []hfsplus.Change{{Path: "/absent", Mode: "0755"}, {Path: "/file", Data: brokenInput{}}, {Path: "/file", Data: hugeInput{}}, {Path: "/created-failure", Data: brokenInput{}}, {Path: "/created-full", Data: hugeInput{}}} {
		out := filepath.Join(t.TempDir(), "failed.dmg")
		if _, e = imageedit.Apply(ctx, source, out, imageedit.Options{Time: clock}, []hfsplus.Change{change}); e == nil {
			t.Fatal("bad transaction succeeded")
		}
		if _, e = os.Lstat(out); !errors.Is(e, fs.ErrNotExist) {
			t.Fatal("failed output published", e)
		}
	}
}

func TestSelectedPartitionRetainsEveryOutsideByte(t *testing.T) {
	ctx := context.Background()
	image, err := diskimage.Open(fixture(t))
	if err != nil {
		t.Fatal(err)
	}
	volume := make([]byte, image.Size())
	if _, err = io.ReadFull(io.NewSectionReader(image, 0, image.Size()), volume); err != nil {
		t.Fatal(err)
	}
	image.Close()
	const start = 32 * 512
	end := start + len(volume)
	// Nonzero bytes surround the selected filesystem, including an opaque
	// partition and unused sectors. None may be altered by a filesystem edit.
	disk := bytes.Repeat([]byte("outside!"), (end+32*512)/8)
	clear(disk[:4*512])
	copy(disk, "ER")
	be := binary.BigEndian
	be.PutUint16(disk[2:], 512)
	be.PutUint32(disk[4:], uint32(len(disk)/512))
	for n, p := range []struct {
		start, size int
		kind        string
	}{{512, 3 * 512, "Apple_partition_map"}, {start, len(volume), "Apple_HFS"}, {end + 8*512, 8 * 512, "Apple_Free"}} {
		e := disk[(n+1)*512 : (n+2)*512]
		copy(e, "PM")
		be.PutUint32(e[4:], 3)
		be.PutUint32(e[8:], uint32(p.start/512))
		be.PutUint32(e[12:], uint32(p.size/512))
		copy(e[48:], p.kind)
	}
	copy(disk[start:end], volume)
	source := filepath.Join(t.TempDir(), "partitioned.raw")
	if err = os.WriteFile(source, disk, 0600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"UDRO", "UDZO"} {
		out := filepath.Join(t.TempDir(), "edited.dmg")
		if _, err = imageedit.Apply(ctx, source, out, imageedit.Options{Partition: 2, Format: format, Time: clock}, []hfsplus.Change{{Path: "/file", Data: bytes.NewReader(bytes.Repeat([]byte("growth"), 30000))}}); err != nil {
			t.Fatal(err)
		}
		got, err := diskimage.Open(out)
		if err != nil {
			t.Fatal(err)
		}
		decoded := make([]byte, got.Size())
		if _, err = io.ReadFull(io.NewSectionReader(got, 0, got.Size()), decoded); err != nil {
			t.Fatal(err)
		}
		got.Close()
		if len(decoded) != len(disk) || !bytes.Equal(decoded[:start], disk[:start]) || !bytes.Equal(decoded[end:], disk[end:]) {
			t.Fatal("partition map, other partition or unused sectors changed")
		}
		if bytes.Equal(decoded[start:end], disk[start:end]) {
			t.Fatal("selected filesystem was not edited")
		}
	}
}

type brokenInput struct{}

func (brokenInput) Size() int64                       { return 8192 }
func (brokenInput) ReadAt([]byte, int64) (int, error) { return 0, io.ErrUnexpectedEOF }

type hugeInput struct{ brokenInput }

func (hugeInput) Size() int64 { return 1 << 40 }

// Abrupt exit while replacing contents must not expose a partial destination.
// It intentionally leaves only private scratch, which the parent removes.
func TestInterruptedImageTransaction(t *testing.T) {
	if os.Getenv("APFS_EDIT_INTERRUPT_CHILD") == "1" {
		changes := []imageedit.Change{{Operation: "mkdir", Path: "/created"}, {Path: "/created/payload", Data: interruptedInput{}}}
		_, _ = imageedit.Apply(context.Background(), os.Getenv("APFS_EDIT_SOURCE"), os.Getenv("APFS_EDIT_DESTINATION"), imageedit.Options{Time: clock}, changes)
		os.Exit(99)
	}
	for _, format := range []string{"HFS+", "APFS"} {
		t.Run(format, func(t *testing.T) {
			source := fixture(t, format)
			before, _ := os.ReadFile(source)
			root := t.TempDir()
			out := filepath.Join(root, "edited.dmg")
			command := exec.Command(os.Args[0], "-test.run=^TestInterruptedImageTransaction$")
			command.Env = append(os.Environ(), "APFS_EDIT_INTERRUPT_CHILD=1", "APFS_EDIT_FILESYSTEM="+format, "APFS_EDIT_SOURCE="+source, "APFS_EDIT_DESTINATION="+out, "TMPDIR="+root, "TMP="+root, "TEMP="+root)
			err := command.Run()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 17 {
				t.Fatal("child did not stop in mutation", err)
			}
			if _, e := os.Lstat(out); !errors.Is(e, fs.ErrNotExist) {
				t.Fatal("interrupted transaction published", e)
			}
			after, _ := os.ReadFile(source)
			if !bytes.Equal(before, after) {
				t.Fatal("interruption changed source")
			}
		})
	}
}

type interruptedInput struct{}

func (interruptedInput) Size() int64 { return 1 << 20 }
func (interruptedInput) ReadAt(p []byte, off int64) (int, error) {
	if off > 0 {
		os.Exit(17)
	}
	clear(p)
	return len(p), nil
}
