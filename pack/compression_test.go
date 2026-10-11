package pack_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

func openBuilt(t *testing.T, path, format string) filesystem.Reader {
	t.Helper()
	image, err := diskimage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { image.Close() })
	section, err := image.Partition(0)
	if err != nil {
		t.Fatal(err)
	}
	if format == "APFS" {
		c, err := apfs.Open(section)
		if err != nil {
			t.Fatal(err)
		}
		return &c.Volumes[0]
	}
	v, err := hfsplus.Open(section)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestCompressionPreservesLinksMetadataAndIndependentForks(t *testing.T) {
	for _, format := range []string{"APFS", "HFS+"} {
		t.Run(format, func(t *testing.T) {
			ctx := context.Background()
			s, o := inputFormat(t, format)
			if _, err := s.Link(ctx, "/file", "/alias", session.LinkOptions{}); err != nil {
				t.Fatal(err)
			}
			small := bytes.Repeat([]byte("small file"), 100)
			large := bytes.Repeat([]byte("large file"), 20000)
			for name, data := range map[string][]byte{"small": small, "large": large, "resource": large, "empty": nil} {
				path := filepath.Join(t.TempDir(), name)
				if err := os.WriteFile(path, data, 0600); err != nil {
					t.Fatal(err)
				}
				if _, err := s.Copy(ctx, []string{path}, "/"+name, session.CopyOptions{FromHost: true}); err != nil {
					t.Fatal(err)
				}
			}
			fork := []byte("independent resource bytes")
			for _, name := range []string{"small", "large"} {
				if _, err := s.ReplaceResourceFork(ctx, "/"+name, bytes.NewReader(fork)); err != nil {
					t.Fatal(err)
				}
			}
			id, err := filesystem.Lookup(ctx, s, "/file")
			if err != nil {
				t.Fatal(err)
			}
			before, err := s.Stat(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			o.FileCompression = "zlib"
			o.ScratchDir = t.TempDir()
			path := filepath.Join(t.TempDir(), "compressed.dmg")
			report, err := pack.Create(ctx, path, s, o)
			if err != nil {
				t.Fatal(err)
			}
			if entries, _ := os.ReadDir(o.ScratchDir); len(entries) != 0 {
				t.Fatal("scratch leaked", entries)
			}
			got := openBuilt(t, path, format)
			fileID, err := filesystem.Lookup(ctx, got, "/file")
			if err != nil {
				t.Fatal(err)
			}
			aliasID, err := filesystem.Lookup(ctx, got, "/alias")
			if err != nil || fileID != aliasID {
				t.Fatal("hard link split", err)
			}
			compressed, err := got.Stat(ctx, fileID)
			if err != nil || compressed.Compression.State != filesystem.Present {
				t.Fatal(compressed, err)
			}
			metadata := compressed.Metadata
			metadata.BSDFlags.Value &^= 32
			if !reflect.DeepEqual(metadata, before.Metadata) {
				t.Fatal("metadata changed", metadata, before.Metadata)
			}
			for _, name := range []string{"small", "large"} {
				id, err := filesystem.Lookup(ctx, got, "/"+name)
				if err != nil {
					t.Fatal(err)
				}
				node, err := got.Stat(ctx, id)
				if err != nil {
					t.Fatal(err)
				}
				if node.Compression.State != filesystem.Absent || node.Metadata.BSDFlags.Value&32 != 0 {
					t.Fatal("fork admission", name, node)
				}
				value, err := got.OpenAttribute(ctx, id, filesystem.ResourceFork)
				if err != nil {
					t.Fatal(err)
				}
				b := make([]byte, value.Size())
				_, err = value.ReadAt(b, 0)
				value.Close()
				if err != nil || !bytes.Equal(b, fork) {
					t.Fatal("independent fork changed", err)
				}
			}
			seen := map[string]string{}
			for _, result := range report.Compression {
				seen[result.Path] = result.Reason
			}
			if seen["/small"] != "independent-resource-fork" || seen["/large"] != "independent-resource-fork" || seen["/empty"] != "empty-file" || len(report.Compression) != 5 {
				t.Fatal(report.Compression)
			}
			var repeat bytes.Buffer
			if _, err = pack.Write(ctx, &repeat, s, o); err != nil {
				t.Fatal(err)
			}
			original, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, repeat.Bytes()) {
				t.Fatal("compression is not deterministic", err)
			}
			o.FileCompression = "none"
			decodedPath := filepath.Join(t.TempDir(), "decompressed.dmg")
			if _, err = pack.Create(ctx, decodedPath, got, o); err != nil {
				t.Fatal(err)
			}
			decoded := openBuilt(t, decodedPath, format)
			decodedID, err := filesystem.Lookup(ctx, decoded, "/file")
			if err != nil {
				t.Fatal(err)
			}
			node, err := decoded.Stat(ctx, decodedID)
			if err != nil || node.Compression.State != filesystem.Absent || node.Metadata.BSDFlags.Value&32 != 0 {
				t.Fatal(node, err)
			}
			if _, err = decoded.OpenAttribute(ctx, decodedID, filesystem.Decmpfs); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("decmpfs survived explicit removal", err)
			}
			v, err := decoded.OpenData(ctx, decodedID)
			if err != nil {
				t.Fatal(err)
			}
			b := make([]byte, v.Size())
			_, err = v.ReadAt(b, 0)
			v.Close()
			if err != nil || !bytes.Equal(b, bytes.Repeat([]byte("payload"), 2000)) {
				t.Fatal("logical bytes changed", err)
			}
		})
	}
}

type changingLogicalReader struct {
	filesystem.Reader
	opens int
}

func (r *changingLogicalReader) OpenData(ctx context.Context, id uint64) (filesystem.Value, error) {
	r.opens++
	if r.opens > 1 {
		return nil, filesystem.ErrConflict
	}
	return r.Reader.OpenData(ctx, id)
}

func TestCompressionSourceChangeAndOutputFailureStayUnpublished(t *testing.T) {
	s, o := inputFormat(t, "APFS")
	o.FileCompression = "zlib"
	o.ScratchDir = t.TempDir()
	ctx := context.Background()
	destination := filepath.Join(t.TempDir(), "out.dmg")
	changing := &changingLogicalReader{Reader: s}
	if _, err := pack.Create(ctx, destination, changing, o); !errors.Is(err, filesystem.ErrConflict) {
		t.Fatal(err)
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("source change published output", err)
	}
	for _, writer := range []io.Writer{failureWriter{io.ErrClosedPipe}, shortWriter{}} {
		if _, err := pack.Write(ctx, writer, s, o); err == nil {
			t.Fatal("output failure accepted")
		}
		if entries, _ := os.ReadDir(o.ScratchDir); len(entries) != 0 {
			t.Fatal("encoded scratch leaked", entries)
		}
	}
	o.FileCompression = "unknown"
	var output bytes.Buffer
	if _, err := pack.Write(ctx, &output, s, o); !errors.Is(err, os.ErrInvalid) || output.Len() != 0 {
		t.Fatal(err)
	}
}

func TestContainerCompressionBorrowsInputsAndCleansScratch(t *testing.T) {
	ctx := context.Background()
	source, o := inputFormat(t, "APFS")
	inputs := []apfs.VolumeSpec{{Reader: source, Name: "First"}, {Reader: source, Name: "Second"}}
	options := pack.ContainerOptions{APFS: apfs.ContainerBuildOptions{Time: o.Volume.Time}, FileCompression: "zlib", ScratchDir: t.TempDir()}
	path := filepath.Join(t.TempDir(), "container.dmg")
	report, err := pack.CreateContainer(ctx, path, inputs, options)
	if err != nil {
		t.Fatal(err)
	}
	if inputs[0].Reader != source || inputs[1].Reader != source {
		t.Fatal("mutated borrowed volume specifications")
	}
	if len(report.Compression) != 2 || report.Compression[0].Volume != "First" || report.Compression[1].Volume != "Second" {
		t.Fatal(report)
	}
	image, err := diskimage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	section, err := image.Partition(0)
	if err != nil {
		t.Fatal(err)
	}
	container, err := apfs.Open(section)
	if err != nil {
		t.Fatal(err)
	}
	for i := range container.Volumes {
		volume := &container.Volumes[i]
		id, err := filesystem.Lookup(ctx, volume, "/file")
		if err != nil {
			t.Fatal(err)
		}
		node, err := volume.Stat(ctx, id)
		if err != nil || node.Compression.State != filesystem.Present {
			t.Fatal(node, err)
		}
	}
	if entries, _ := os.ReadDir(options.ScratchDir); len(entries) != 0 {
		t.Fatal("multi-volume scratch leaked", entries)
	}
	if err = source.Verify(ctx); err != nil {
		t.Fatal("source session changed", err)
	}
}
