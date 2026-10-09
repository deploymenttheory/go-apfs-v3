package acceptance_test

import (
	"context"
	"encoding/binary"
	"io"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
	"github.com/deploymenttheory/go-apfs-v3/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v3/internal/fork"
)

// FuzzCompressionCodecs mutates genuine native payloads, so entropy decoders
// receive valid starting states rather than only random invalid magic bytes.
// Compatibility is asserted by TestNativeFileCompression; this checks bounded
// decoding and panic freedom. No second fixture generator or codec oracle exists.
func FuzzCompressionCodecs(f *testing.F) {
	ctx := context.Background()
	image, err := diskimage.Open("testdata/compression/macos-27/apfs.dmg")
	if err != nil {
		f.Fatal(err)
	}
	defer image.Close()
	report, err := inspect.Image(ctx, image)
	if err != nil {
		f.Fatal(err)
	}
	var reader filesystem.Reader
	for _, p := range report.Partitions {
		if p.APFS != nil && len(p.APFS.Volumes) == 1 {
			reader = &p.APFS.Volumes[0]
		}
	}
	if reader == nil {
		f.Fatal("missing native APFS seed volume")
	}
	for _, path := range []string{"type-03", "type-07", "type-12", "type-14", "type-16"} {
		id, err := filesystem.LookupExact(ctx, reader, "Fixture/"+path)
		if err != nil {
			f.Fatal(err)
		}
		a, err := reader.OpenAttribute(ctx, id, filesystem.Decmpfs)
		if err != nil {
			f.Fatal(err)
		}
		data, err := io.ReadAll(io.NewSectionReader(a, 0, a.Size()))
		_ = a.Close()
		if err != nil || len(data) < 16 {
			f.Fatal("native seed attribute", err)
		}
		kind := binary.LittleEndian.Uint32(data[4:])
		size := binary.LittleEndian.Uint64(data[8:])
		payload := data[16:]
		if kind&1 == 0 {
			r, err := reader.OpenAttribute(ctx, id, filesystem.ResourceFork)
			if err != nil {
				f.Fatal(err)
			}
			var offsets [8]byte
			if _, err := r.ReadAt(offsets[:], 0); err != nil {
				f.Fatal(err)
			}
			start, end := binary.LittleEndian.Uint32(offsets[:]), binary.LittleEndian.Uint32(offsets[4:])
			if end <= start || end-start > 3802-16 {
				f.Fatal("native seed block outside attribute budget")
			}
			payload = make([]byte, end-start)
			if _, err := r.ReadAt(payload, int64(start)); err != nil {
				f.Fatal(err)
			}
			_ = r.Close()
			size = min(size, 65536)
			kind-- // Same codec payload, bounded inline storage for fuzzing.
		}
		f.Add(kind, uint32(size), payload)
	}
	f.Fuzz(func(t *testing.T, kind, size uint32, payload []byte) {
		if size > 65536 || len(payload) > 3802-16 {
			return
		}
		attribute := make([]byte, 16, 16+len(payload))
		copy(attribute, "fpmc")
		binary.LittleEndian.PutUint32(attribute[4:], kind)
		binary.LittleEndian.PutUint64(attribute[8:], uint64(size))
		attribute = append(attribute, payload...)
		v, err := decmpfs.Open(ctx, func(name string) (filesystem.Value, error) {
			if name != filesystem.Decmpfs {
				return nil, filesystem.ErrCorrupt
			}
			return fork.Bytes(ctx, attribute)
		})
		if err != nil {
			return
		}
		defer v.Close()
		_, _ = io.Copy(io.Discard, io.NewSectionReader(v, 0, v.Size()))
	})
}
