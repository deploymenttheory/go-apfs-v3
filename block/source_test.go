package block

import (
	"bytes"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestSectionCannotReadAdjacentPartition(t *testing.T) {
	s, err := NewSection(bytes.NewReader([]byte("beforePAYLOADafter")), 6, 7)
	if err != nil {
		t.Fatal(err)
	}
	p := bytes.Repeat([]byte{0xcc}, 16)
	n, err := s.ReadAt(p, 0)
	if n != 7 || !errors.Is(err, io.EOF) || string(p[:n]) != "PAYLOAD" {
		t.Fatalf("read: %d %v %q", n, err, p)
	}
	if !bytes.Equal(p[n:], bytes.Repeat([]byte{0xcc}, 9)) {
		t.Fatal("read wrote beyond returned bytes")
	}
	if _, err := s.ReadAt(p, -1); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if n, err := s.ReadAt(p, math.MaxInt64); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("overflow: %d %v", n, err)
	}
	if _, err := NewSection(s, 1, math.MaxInt64); !errors.Is(err, os.ErrInvalid) {
		t.Fatal("accepted overflowing section", err)
	}
	if n, err := s.ReadAt(nil, s.Size()); n != 0 || err != nil {
		t.Fatal("zero-byte read", n, err)
	}
}

func TestFileReadsDoNotChangeSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image")
	if err := os.WriteFile(path, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	p := make([]byte, 20)
	if n, err := f.ReadAt(p, 0); n != 9 || !errors.Is(err, io.EOF) {
		t.Fatal(n, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "unchanged" {
		t.Fatal(string(b), err)
	}
}

type shortReader struct{}

func (shortReader) ReadAt(p []byte, off int64) (int, error) { return 0, nil }

func TestReadFullRejectsShortSuccess(t *testing.T) {
	if err := ReadFull(shortReader{}, make([]byte, 8), 0); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatal(err)
	}
}
