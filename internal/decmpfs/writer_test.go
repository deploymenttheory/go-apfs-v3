package decmpfs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/internal/fork"
)

func TestEncodedBoundariesAndRandomReads(t *testing.T) {
	for _, size := range []int{1, 3801, 3802, 65535, 65536, 65537, 3*65536 + 17} {
		t.Run(fmtSize(size), func(t *testing.T) {
			plain := bytes.Repeat([]byte("shared transparent file compression\n"), size/len("shared transparent file compression\n")+1)[:size]
			// Include an incompressible block in an otherwise compressible file.
			if size > 2*blockSize {
				for i := 0; i < blockSize; i += 32 {
					sum := sha256.Sum256([]byte(fmtSize(i)))
					copy(plain[blockSize+i:], sum[:])
				}
			}
			file, err := os.Create(filepath.Join(t.TempDir(), "resource"))
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			encoded, err := Encode(context.Background(), bytes.NewReader(plain), file, true)
			if err != nil {
				t.Fatal(err)
			}
			if size == 1 {
				if encoded.Reason != "not-smaller" {
					t.Fatal(encoded)
				}
				return
			}
			if encoded.Reason != "" || encoded.LogicalSHA256 != sha256.Sum256(plain) {
				t.Fatal(encoded, err)
			}
			resource, err := os.ReadFile(file.Name())
			if err != nil {
				t.Fatal(err)
			}
			value, err := Open(context.Background(), attributes(context.Background(), encoded.Attribute, resource))
			if err != nil {
				t.Fatal(err)
			}
			defer value.Close()
			for _, off := range []int{size - 1, size / 2, 0, min(size-1, 65535), min(size-1, 65536)} {
				b := make([]byte, min(91, size-off))
				if _, err = value.ReadAt(b, int64(off)); err != nil || !bytes.Equal(b, plain[off:off+len(b)]) {
					t.Fatal(off, err)
				}
			}
			if _, err = value.ReadAt(make([]byte, 1), int64(size)); err != io.EOF {
				t.Fatal(err)
			}
		})
	}
}

func fmtSize(n int) string { return fmt.Sprintf("%d", n) }

type failedResource struct {
	*os.File
	err error
}

func (f failedResource) Write([]byte) (int, error) { return 0, f.err }

func TestEncodingAdmissionAndWriteFailures(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "resource"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	source := bytes.NewReader(bytes.Repeat([]byte("data"), 40000))
	encoded, err := Encode(context.Background(), source, f, false)
	if err != nil || encoded.Reason != "independent-resource-fork" {
		t.Fatal(encoded, err)
	}
	if info, _ := f.Stat(); info.Size() != 0 {
		t.Fatal("independent fork overwritten")
	}
	sentinel := errors.New("resource disk full")
	if _, err = Encode(context.Background(), source, failedResource{f, sentinel}, true); !errors.Is(err, sentinel) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = Encode(ctx, source, f, true); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	v, err := fork.Bytes(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer v.Close()
	encoded, err = Encode(context.Background(), v, f, true)
	if err != nil || encoded.Reason != "empty-file" {
		t.Fatal(encoded, err)
	}
	if _, err = Encode(context.Background(), nil, f, true); err == nil {
		t.Fatal("nil source admitted")
	}
	if _, err = f.WriteAt([]byte{1}, 0); err != nil {
		t.Fatal(err)
	}
	if _, err = Encode(context.Background(), source, f, true); err == nil {
		t.Fatal("nonempty destination admitted")
	}
}

type shortSource struct{}

func (shortSource) Size() int64                           { return 70000 }
func (shortSource) ReadAt(b []byte, _ int64) (int, error) { return len(b) / 2, nil }
func TestEncodingRejectsShortSource(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "resource"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err = Encode(context.Background(), shortSource{}, f, true); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
	if _, err = Encode(context.Background(), bytes.NewReader(nil), nil, true); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
}

func TestAttributeCapacityTransition(t *testing.T) {
	random := make([]byte, 65536)
	for i := uint32(0); i < 2048; i++ {
		var counter [4]byte
		binary.LittleEndian.PutUint32(counter[:], i)
		h := sha256.Sum256(counter[:])
		copy(random[int(i)*32:], h[:])
	}
	for _, tc := range []struct {
		count int
		kind  uint32
	}{{3300, 3}, {3900, 4}} {
		data := make([]byte, 65536)
		copy(data, random[:tc.count])
		f, err := os.Create(filepath.Join(t.TempDir(), "resource"))
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := Encode(context.Background(), bytes.NewReader(data), f, true)
		f.Close()
		if err != nil || encoded.Reason != "" || binary.LittleEndian.Uint32(encoded.Attribute[4:]) != tc.kind {
			t.Fatal(tc, encoded, err)
		}
	}
}
