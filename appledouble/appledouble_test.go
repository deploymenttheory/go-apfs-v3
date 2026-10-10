package appledouble

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"os"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func nativeSample(t testing.TB) []byte {
	t.Helper()
	data, err := os.ReadFile("../acceptance/testdata/preservation/macos-27/apfs-example.txt.appledouble")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDecodeRejectsDamagedNativeRanges(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func([]byte) []byte
		want error
	}{
		{"truncated", func(b []byte) []byte { return b[:70] }, filesystem.ErrCorrupt},
		{"fork beyond source", func(b []byte) []byte { be.PutUint32(b[42:], math.MaxUint32); return b }, filesystem.ErrCorrupt},
		{"name outside header", func(b []byte) []byte { b[130] = 255; return b }, filesystem.ErrCorrupt},
		{"header budget", func(b []byte) []byte { be.PutUint32(b[96:], math.MaxUint32); return b }, filesystem.ErrLimit},
		{"attribute before data", func(b []byte) []byte { be.PutUint32(b[120:], 1); return b }, filesystem.ErrCorrupt},
		{"overlapping attributes", func(b []byte) []byte { be.PutUint32(b[152:], be.Uint32(b[120:])); return b }, filesystem.ErrCorrupt},
		{"unsupported layout", func(b []byte) []byte { be.PutUint16(b[24:], 3); return b }, filesystem.ErrUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(context.Background(), bytes.NewReader(tc.edit(nativeSample(t))))
			if !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
		})
	}
}

func TestOrderedEmptyAndDuplicateSerializedAttributes(t *testing.T) {
	input := &File{Flags: 7, DebugTag: 23, Attributes: []Attribute{
		{Name: []byte("duplicate"), Flags: 3, Value: bytes.NewReader([]byte("first"))},
		{Name: []byte("duplicate"), Value: bytes.NewReader(nil)},
		{Name: []byte("com.apple.acl.text"), Value: bytes.NewReader([]byte("opaque serialized policy bytes"))},
	}}
	var buffer bytes.Buffer
	if err := Write(context.Background(), &buffer, input); err != nil {
		t.Fatal(err)
	}
	got, err := Decode(context.Background(), bytes.NewReader(buffer.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Attributes) != 3 || got.Flags != 7 || got.DebugTag != 23 {
		t.Fatal("lost ordered attributes or flags")
	}
	for i, a := range got.Attributes {
		want := input.Attributes[i]
		b, err := io.ReadAll(io.NewSectionReader(a.Value, 0, a.Value.Size()))
		if err != nil {
			t.Fatal(err)
		}
		expected, err := io.ReadAll(io.NewSectionReader(want.Value, 0, want.Value.Size()))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a.Name, want.Name) || a.Flags != want.Flags || !bytes.Equal(b, expected) {
			t.Fatal("serialized value changed")
		}
	}
}

type virtualSource struct {
	size  int64
	calls int
}

func (s *virtualSource) Size() int64                       { return s.size }
func (s *virtualSource) ReadAt([]byte, int64) (int, error) { s.calls++; return 0, io.ErrUnexpectedEOF }

type shortWriter struct{}

func (shortWriter) Write(b []byte) (int, error) { return len(b) - 1, nil }

func TestWriteLimitsCancellationAndIOFailures(t *testing.T) {
	source := &virtualSource{size: 1 << 32}
	var output bytes.Buffer
	if err := Write(context.Background(), &output, &File{ResourceFork: source}); !errors.Is(err, filesystem.ErrLimit) || source.calls != 0 || output.Len() != 0 {
		t.Fatal("oversized fork started output", err)
	}
	source.size = 1
	if err := Write(context.Background(), io.Discard, &File{ResourceFork: source}); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if err := Write(context.Background(), shortWriter{}, &File{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Write(ctx, &output, &File{}); !errors.Is(err, context.Canceled) || output.Len() != 0 {
		t.Fatal(err)
	}
	if _, err := Decode(ctx, bytes.NewReader(nativeSample(t))); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(nativeSample(f))
	f.Add([]byte("not AppleDouble"))
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := Decode(context.Background(), bytes.NewReader(data))
		if err != nil {
			return
		}
		if err = Write(context.Background(), io.Discard, decoded); err != nil {
			t.Fatalf("admitted invalid borrowed values: %v", err)
		}
	})
}
