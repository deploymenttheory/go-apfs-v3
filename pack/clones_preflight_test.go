package pack_test

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

type cloneBytesValue struct{ *bytes.Reader }

func (cloneBytesValue) Close() error { return nil }

type compressedCloneSource struct {
	filesystem.Reader
	attributes map[uint64][]byte
	dataGroup  bool
}

func (r compressedCloneSource) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	node, err := r.Reader.Stat(ctx, id)
	if _, found := r.attributes[id]; found && err == nil {
		node.Metadata.BSDFlags.Value |= 32
		node.Compression = filesystem.Observed(filesystem.Compression{Type: 3})
		node.CloneStreams = &filesystem.CloneStreams{Attributes: map[string]string{filesystem.Decmpfs: "declared-encoded-stream"}}
		if r.dataGroup {
			node.CloneStreams = &filesystem.CloneStreams{Data: "declared-raw-stream"}
		}
	}
	return node, err
}

func (r compressedCloneSource) OpenRawData(ctx context.Context, id uint64) (filesystem.Value, error) {
	if _, found := r.attributes[id]; found {
		return cloneBytesValue{bytes.NewReader(nil)}, nil
	}
	return r.Reader.OpenRawData(ctx, id)
}

func (r compressedCloneSource) ListAttributes(ctx context.Context, id uint64, yield func(string) error) error {
	if err := r.Reader.ListAttributes(ctx, id, yield); err != nil {
		return err
	}
	if _, found := r.attributes[id]; found {
		return yield(filesystem.Decmpfs)
	}
	return nil
}

func (r compressedCloneSource) OpenAttribute(ctx context.Context, id uint64, name string) (filesystem.Value, error) {
	if value, found := r.attributes[id]; found && name == filesystem.Decmpfs {
		return cloneBytesValue{bytes.NewReader(value)}, nil
	}
	return r.Reader.OpenAttribute(ctx, id, name)
}

func TestCompressionCannotEraseConflictingOriginalClonePayloads(t *testing.T) {
	ctx := context.Background()
	for _, identical := range []bool{false, true} {
		s, options := inputFormat(t, "APFS")
		payload := bytes.Repeat([]byte("data"), 32)
		if _, err := s.ReplaceData(ctx, "/file", bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Copy(ctx, []string{"/file"}, "/independent", session.CopyOptions{}); err != nil {
			t.Fatal(err)
		}
		reader := compressedCloneSource{Reader: s, attributes: map[uint64][]byte{}}
		for i, path := range []string{"/file", "/independent"} {
			id, err := s.LookupPath(ctx, path, true)
			if err != nil {
				t.Fatal(err)
			}
			var encoded bytes.Buffer
			level := zlib.BestCompression
			if i == 0 && !identical {
				level = zlib.NoCompression
			}
			writer, err := zlib.NewWriterLevel(&encoded, level)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write(payload); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			header := make([]byte, 16)
			binary.LittleEndian.PutUint32(header, 0x636d7066)
			binary.LittleEndian.PutUint32(header[4:], 3)
			binary.LittleEndian.PutUint64(header[8:], uint64(len(payload)))
			reader.attributes[id] = append(header, encoded.Bytes()...)
		}
		for _, policy := range []string{"none", "zlib"} {
			options.FileCompression = policy
			var out bytes.Buffer
			report, err := pack.Write(ctx, &out, reader, options)
			if identical {
				if err != nil || len(report.Clones) == 0 {
					t.Fatal("validated source lineage was lost", policy, report.Clones, err)
				}
			} else if !errors.Is(err, filesystem.ErrCorrupt) || out.Len() != 0 || len(report.Clones) != 0 {
				t.Fatal("storage transform erased a false original group", policy, report.Clones, out.Len(), err)
			}
		}
	}
}

func TestCompressionCannotEraseConflictingDataStreamDescriptors(t *testing.T) {
	ctx := context.Background()
	s, options := inputFormat(t, "APFS")
	if _, err := s.Copy(ctx, []string{"/file"}, "/independent", session.CopyOptions{}); err != nil {
		t.Fatal(err)
	}
	reader := compressedCloneSource{Reader: s, attributes: map[uint64][]byte{}, dataGroup: true}
	for i, path := range []string{"/file", "/independent"} {
		payload := bytes.Repeat([]byte("data"), 32*(i+1))
		if _, err := s.ReplaceData(ctx, path, bytes.NewReader(payload)); err != nil {
			t.Fatal(err)
		}
		id, _ := s.LookupPath(ctx, path, true)
		var encoded bytes.Buffer
		writer := zlib.NewWriter(&encoded)
		if _, err := writer.Write(payload); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		header := make([]byte, 16)
		binary.LittleEndian.PutUint32(header, 0x636d7066)
		binary.LittleEndian.PutUint32(header[4:], 3)
		binary.LittleEndian.PutUint64(header[8:], uint64(len(payload)))
		reader.attributes[id] = append(header, encoded.Bytes()...)
	}
	if _, err := apfs.Plan(ctx, reader, apfs.BuildOptions{Name: "Conflicting Descriptors", Time: options.Volume.Time}); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal("original builder did not reject incompatible descriptors", err)
	}
	options.FileCompression = "none"
	var output bytes.Buffer
	if report, err := pack.Write(ctx, &output, reader, options); !errors.Is(err, filesystem.ErrCorrupt) || output.Len() != 0 || len(report.Clones) != 0 {
		t.Fatal("compression erased incompatible original descriptors", output.Len(), report.Clones, err)
	}
}

type publicationRaceSource struct {
	filesystem.Reader
	destination string
	reads       map[uint64]int
	created     bool
}

type publicationRaceValue struct {
	filesystem.Value
	read func() error
}

func (v publicationRaceValue) ReadAt(data []byte, offset int64) (int, error) {
	if len(data) != 0 {
		if err := v.read(); err != nil {
			return 0, err
		}
	}
	return v.Value.ReadAt(data, offset)
}

func (r *publicationRaceSource) OpenRawData(ctx context.Context, id uint64) (filesystem.Value, error) {
	value, err := r.Reader.OpenRawData(ctx, id)
	if err != nil {
		return nil, err
	}
	return publicationRaceValue{Value: value, read: func() error {
		r.reads[id]++
		// Original-group preflight and layout fingerprinting precede the
		// streamed image. Compete for its final name during the latter read.
		if r.reads[id] == 3 && !r.created {
			r.created = true
			return os.WriteFile(r.destination, []byte("competing destination"), 0600)
		}
		return nil
	}}, nil
}

func TestPackUnpublishedCloneOutcomesDisappearAfterLatePublicationConflict(t *testing.T) {
	ctx := context.Background()
	for _, container := range []bool{false, true} {
		s, options := inputFormat(t, "APFS")
		if _, err := s.Copy(ctx, []string{"/file"}, "/clone", session.CopyOptions{Clone: true}); err != nil {
			t.Fatal(err)
		}
		directory := t.TempDir()
		path := filepath.Join(directory, "output.dmg")
		reader := &publicationRaceSource{Reader: s, destination: path, reads: map[uint64]int{}}
		var outcomes []pack.CloneOutcome
		var err error
		if container {
			report, failure := pack.CreateContainer(ctx, path, []apfs.VolumeSpec{{Reader: reader, Name: "Clones"}}, pack.ContainerOptions{APFS: apfs.ContainerBuildOptions{Time: options.Volume.Time}})
			outcomes, err = report.Clones, failure
		} else {
			report, failure := pack.Create(ctx, path, reader, options)
			outcomes, err = report.Clones, failure
		}
		if !reader.created || !errors.Is(err, fs.ErrExist) || len(outcomes) != 0 {
			t.Fatal("unpublished clone outcomes leaked", container, outcomes, err)
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != "competing destination" {
			t.Fatal("competing destination changed", err)
		}
		if files, _ := os.ReadDir(directory); len(files) != 1 {
			t.Fatal("unpublished temporary output leaked", files)
		}
	}
}

var _ io.ReaderAt = publicationRaceValue{}
