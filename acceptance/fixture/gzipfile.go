package fixture

import (
	"compress/gzip"
	"os"
)

type gzipFile struct {
	f  *os.File
	gz *gzip.Writer
}

// newGzipFile creates path exclusively and gzip-compresses writes with a
// zero modification time so identical bytes produce identical files.
func newGzipFile(path string) (*gzipFile, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, err
	}
	gz := gzip.NewWriter(f)
	gz.ModTime = zeroTime
	return &gzipFile{f: f, gz: gz}, nil
}

func (g *gzipFile) Write(p []byte) (int, error) { return g.gz.Write(p) }

func (g *gzipFile) Close() error {
	if err := g.gz.Close(); err != nil {
		_ = g.f.Close()
		return err
	}
	if err := g.f.Sync(); err != nil {
		_ = g.f.Close()
		return err
	}
	return g.f.Close()
}

var zeroTime = unixZero()
