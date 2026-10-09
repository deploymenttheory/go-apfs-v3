// Package block provides bounded, read-only random access to disk bytes.
package block

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// Source must support concurrent ReadAt calls. A successful call fills p;
// a short read returns an error. Size is immutable during use.
type Source interface {
	io.ReaderAt
	Size() int64
}

// File owns a read-only descriptor. No forensic open obtains write access.
type File struct {
	file *os.File
	size int64
}

func Open(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	s, err := f.Stat()
	if err != nil {
		return nil, errors.Join(err, f.Close())
	}
	if !s.Mode().IsRegular() {
		return nil, errors.Join(fmt.Errorf("block source must be a regular image: %w", os.ErrInvalid), f.Close())
	}
	return &File{file: f, size: s.Size()}, nil
}

func (f *File) Size() int64  { return f.size }
func (f *File) Close() error { return f.file.Close() }
func (f *File) ReadAt(p []byte, off int64) (int, error) {
	return readAt(f.file, f.size, p, off)
}

// Section borrows its source; closing the owner invalidates every section.
type Section struct {
	source       Source
	offset, size int64
}

func NewSection(source Source, offset, size int64) (*Section, error) {
	if source == nil || offset < 0 || size < 0 || offset > source.Size() || size > source.Size()-offset {
		return nil, fmt.Errorf("section outside source: %w", os.ErrInvalid)
	}
	return &Section{source: source, offset: offset, size: size}, nil
}

func (s *Section) Size() int64 { return s.size }
func (s *Section) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, os.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= s.size {
		return 0, io.EOF
	}
	q := p
	if int64(len(q)) > s.size-off {
		q = q[:s.size-off]
	}
	n, err := s.source.ReadAt(q, s.offset+off)
	if n < len(p) && err == nil {
		err = io.EOF
	}
	return n, err
}

func readAt(r io.ReaderAt, size int64, p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, os.ErrInvalid
	}
	if len(p) == 0 {
		return 0, nil
	}
	if off >= size {
		return 0, io.EOF
	}
	q := p
	if int64(len(q)) > size-off {
		q = q[:size-off]
	}
	n, err := r.ReadAt(q, off)
	if n < len(p) && err == nil {
		err = io.EOF
	}
	return n, err
}

// ReadFull rejects broken ReaderAt implementations returning short success.
func ReadFull(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	if n != len(p) {
		if err == nil || errors.Is(err, io.EOF) {
			return io.ErrUnexpectedEOF
		}
		return err
	}
	return err
}
