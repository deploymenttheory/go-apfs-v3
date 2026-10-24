package imageedit_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

// The ordinary Go builder admits 100,000 entries. Two subsequent public edits
// make a valid larger source without weakening that builder's own limits.
// Copy must still touch only its small source/destination paths.
func TestImageCopyBesideLargeUnrelatedCatalogRetainsLazyAdmission(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	seed := filepath.Join(root, "seed.raw")
	layout, err := hfsplus.Plan(ctx, largeCopyVolume{}, hfsplus.BuildOptions{Name: "LazyCopy", Time: clock, Capacity: 128 << 20})
	if err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(seed)
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(layout.Write(ctx, file), file.Close()); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source.dmg")
	if _, err := imageedit.Apply(ctx, seed, source, imageedit.Options{Time: clock, Format: "UDZO"}, []imageedit.Change{
		{Path: "/Unrelated/extra-a", Data: strings.NewReader("")},
		{Path: "/Unrelated/extra-b", Data: strings.NewReader("")},
	}); err != nil {
		t.Fatal("prepare independently valid large source", err)
	}
	before := largeCopyFileDigest(t, source)
	output := filepath.Join(root, "copied.dmg")
	report, err := imageedit.Edit(ctx, source, output, imageedit.Options{Time: clock, Format: "UDZO"}, func(editor *imageedit.Editor) error {
		if _, err := editor.Apply([]imageedit.Change{{Operation: "mkdir", Path: "/target"}}); err != nil {
			return err
		}
		_, err := editor.Copy([]imageedit.CopyCommand{{Sources: []string{"/source"}, Destination: "/target/copied", Options: imageedit.CopyOptions{Preserve: true}}})
		return err
	})
	if err != nil {
		t.Fatal("small public COPY scanned or refused the unrelated large catalog", err)
	}
	if len(report.MetadataOmissions) != 0 {
		t.Fatal("unrelated objects became COPY outcomes", report.MetadataOmissions)
	}
	reader := cloneImageReader(t, output, "HFS+")
	if got := cloneImageValue(t, reader, "/target/copied", ""); !bytes.Equal(got, []byte("small source")) {
		t.Fatal("copied data differs", got)
	}
	count := 0
	id, err := filesystem.Lookup(ctx, reader, "/Unrelated")
	if err != nil {
		t.Fatal(err)
	}
	if err := reader.ReadDir(ctx, id, func(filesystem.DirEntry) error { count++; return nil }); err != nil || count != 99999 {
		t.Fatal("unrelated entries changed", count, err)
	}
	if after := largeCopyFileDigest(t, source); after != before {
		t.Fatal("public COPY changed its original source")
	}
}

func largeCopyFileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	h := sha256.New()
	_, readErr := io.Copy(h, f)
	if err := errors.Join(readErr, f.Close()); err != nil {
		t.Fatal(err)
	}
	return [32]byte(h.Sum(nil))
}

type largeCopyVolume struct{}

func (largeCopyVolume) Root() uint64 { return 2 }
func (largeCopyVolume) NameRules() filesystem.NameRules {
	return filesystem.NameRules{Format: "HFS+", NormalizationInsensitive: true}
}
func (largeCopyVolume) Stat(_ context.Context, id uint64) (filesystem.Node, error) {
	mode := uint32(0100644)
	if id == 2 || id == 3 {
		mode = 0040755
	}
	size := uint64(0)
	if id == 4 {
		size = uint64(len("small source"))
	}
	return filesystem.Node{Identity: filesystem.Identity{Volume: "synthetic-lazy-copy", Object: id}, Size: size, Links: filesystem.Observed(uint32(1)), Compression: filesystem.Observation[filesystem.Compression]{State: filesystem.Absent}, Metadata: filesystem.Metadata{Mode: filesystem.Observed(mode), UID: filesystem.Observed(uint32(0)), GID: filesystem.Observed(uint32(0)), BSDFlags: filesystem.Observed(uint32(0)), BirthTime: filesystem.Observed(clock), ModifyTime: filesystem.Observed(clock), ChangeTime: filesystem.Observed(clock), AccessTime: filesystem.Observed(clock)}}, nil
}
func (largeCopyVolume) ReadDir(_ context.Context, id uint64, yield func(filesystem.DirEntry) error) error {
	if id == 2 {
		for _, e := range []filesystem.DirEntry{{Name: "Unrelated", Object: 3}, {Name: "source", Object: 4}} {
			if err := yield(e); err != nil {
				return err
			}
		}
		return nil
	}
	if id != 3 {
		return fs.ErrInvalid
	}
	for i := range 99997 {
		if err := yield(filesystem.DirEntry{Name: fmt.Sprintf("f%05d", i), Object: uint64(100 + i)}); err != nil {
			return err
		}
	}
	return nil
}
func (largeCopyVolume) Lookup(_ context.Context, id uint64, name string) (filesystem.DirEntry, error) {
	if id == 2 {
		if name == "Unrelated" {
			return filesystem.DirEntry{Name: name, Object: 3}, nil
		}
		if name == "source" {
			return filesystem.DirEntry{Name: name, Object: 4}, nil
		}
	}
	if id == 3 && strings.HasPrefix(name, "f") {
		i, err := strconv.Atoi(name[1:])
		if err == nil && i >= 0 && i < 99997 {
			return filesystem.DirEntry{Name: name, Object: uint64(100 + i)}, nil
		}
	}
	return filesystem.DirEntry{}, fs.ErrNotExist
}
func (v largeCopyVolume) OpenData(ctx context.Context, id uint64) (filesystem.Value, error) {
	return v.OpenRawData(ctx, id)
}
func (largeCopyVolume) OpenRawData(_ context.Context, id uint64) (filesystem.Value, error) {
	data := ""
	if id == 4 {
		data = "small source"
	}
	return largeCopyValue{strings.NewReader(data)}, nil
}
func (largeCopyVolume) ListAttributes(context.Context, uint64, func(string) error) error { return nil }
func (largeCopyVolume) OpenAttribute(context.Context, uint64, string) (filesystem.Value, error) {
	return nil, fs.ErrNotExist
}
func (largeCopyVolume) Readlink(context.Context, uint64) (string, error) { return "", fs.ErrInvalid }

type largeCopyValue struct{ *strings.Reader }

func (largeCopyValue) Close() error { return nil }
