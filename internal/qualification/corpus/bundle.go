package corpus

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"
)

func (r *Resolver) extract(ctx context.Context, entry Entry) (_ *Resolved, err error) {
	if r.options.Bundles == "" {
		return nil, errors.New("bundle directory is required; no missing-input fallback exists")
	}
	bundles, err := os.OpenRoot(r.options.Bundles)
	if err != nil {
		return nil, err
	}
	defer func() { _ = bundles.Close() }()
	b := entry.Location.Bundle
	info, err := bundles.Lstat(b.Filename())
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() != b.Bytes {
		return nil, errors.New("invalid stored corpus bundle")
	}
	input, err := bundles.Open(b.Filename())
	if err != nil {
		return nil, err
	}
	defer func() { _ = input.Close() }()
	directory, err := os.MkdirTemp(r.options.Scratch, "native-corpus-")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = os.RemoveAll(directory)
		}
	}()
	root, err := os.OpenRoot(directory)
	if err != nil {
		return nil, err
	}
	result := &Resolved{path: directory, entry: entry, root: root, owned: true}
	defer func() {
		if err != nil {
			_ = result.Close()
		}
	}()
	hash := sha256.New()
	stored := bufio.NewReader(io.TeeReader(contextReader{ctx, io.LimitReader(input, b.Bytes+1)}, hash))
	z, err := gzip.NewReader(stored)
	if err != nil {
		return nil, err
	}
	defer func() { _ = z.Close() }()
	z.Multistream(false)
	// Bound data plus tar metadata/padding separately. Even hidden PAX headers
	// cannot turn a small compressed archive into unbounded decoded work.
	budget := entry.TotalBytes() + int64(len(entry.Files))*8192 + (1 << 20)
	decoded := &io.LimitedReader{R: contextReader{ctx, z}, N: budget + 1}
	archive := tar.NewReader(decoded)
	files := map[string]File{}
	directories := map[string]bool{}
	for _, f := range entry.Files {
		files[f.Path] = f
		for parent := path.Dir(f.Path); parent != "."; parent = path.Dir(parent) {
			directories[parent] = true
		}
	}
	seen := map[string]bool{}
	count := 0
	for {
		header, nextErr := archive.Next()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return nil, nextErr
		}
		name := header.Name
		if header.Typeflag == tar.TypeDir {
			name = strings.TrimSuffix(name, "/")
		}
		key := strings.ToLower(name)
		if !PortablePath(name) || seen[key] || header.Linkname != "" || header.Format == tar.FormatGNU {
			return nil, fmt.Errorf("unsafe/duplicate archive member: %q", header.Name)
		}
		seen[key] = true
		for k := range header.PAXRecords {
			if k != "path" && k != "size" && k != "mtime" {
				return nil, fmt.Errorf("unsupported archive metadata: %s", k)
			}
		}
		if header.Typeflag == tar.TypeDir {
			if !directories[name] || header.Size != 0 {
				return nil, fmt.Errorf("unexpected archive directory: %s", name)
			}
			continue
		}
		if header.Typeflag != tar.TypeReg {
			return nil, errors.New("archive links/special/sparse files are forbidden")
		}
		file, ok := files[name]
		if !ok || header.Size != file.Bytes {
			return nil, fmt.Errorf("unexpected archive member or size: %s", name)
		}
		if err = root.MkdirAll(path.Dir(name), 0700); err != nil {
			return nil, err
		}
		output, createErr := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr != nil {
			return nil, createErr
		}
		err = copyVerified(ctx, output, archive, file.Bytes, file.SHA256)
		closeErr := output.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		count++
	}
	if count != len(files) {
		return nil, errors.New("bundle is missing required corpus members")
	}
	// tar EOF alone does not consume the gzip trailer or reject a hidden second
	// archive after its end markers. Only zero tar padding may remain.
	if _, err = io.Copy(zeroPadding{}, decoded); err != nil {
		return nil, err
	}
	if decoded.N == 0 {
		return nil, errors.New("decoded bundle exceeds metadata/data bound")
	}
	if _, peekErr := stored.Peek(1); !errors.Is(peekErr, io.EOF) {
		return nil, errors.New("trailing bytes or multiple gzip streams in corpus bundle")
	}
	if hex.EncodeToString(hash.Sum(nil)) != b.SHA256 {
		return nil, errors.New("stored corpus bundle SHA-256 mismatch")
	}
	for _, capture := range entry.Captures {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		if err = verifyCapture(root, capture); err != nil {
			return nil, err
		}
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

type zeroPadding struct{}

func (zeroPadding) Write(data []byte) (int, error) {
	for _, value := range data {
		if value != 0 {
			return 0, errors.New("nonzero bytes after tar end markers")
		}
	}
	return len(data), nil
}

type boundedWriter struct {
	output  io.Writer
	written int64
}

func (w *boundedWriter) Write(data []byte) (int, error) {
	if int64(len(data)) > MaxBundleBytes-w.written {
		return 0, errors.New("corpus release bundle exceeds size bound")
	}
	n, err := w.output.Write(data)
	w.written += int64(n)
	return n, err
}

// WriteBundle prepares an ordinary local file for later reviewed publication.
// It never alters the approved catalog or uploads/replaces a release asset.
func WriteBundle(ctx context.Context, source *Resolved, directory string) (_ Bundle, err error) {
	var bundle Bundle
	if err = source.Verify(ctx); err != nil {
		return bundle, err
	}
	actualDirectory, err := filepath.EvalSymlinks(directory)
	if err != nil {
		return bundle, err
	}
	actualSource, err := filepath.EvalSymlinks(source.path)
	if err != nil {
		return bundle, err
	}
	actualDirectory, err = filepath.Abs(actualDirectory)
	if err != nil {
		return bundle, err
	}
	actualSource, err = filepath.Abs(actualSource)
	if err != nil {
		return bundle, err
	}
	rel, err := filepath.Rel(actualSource, actualDirectory)
	if err == nil && (rel == "." || filepath.IsLocal(rel)) {
		return bundle, errors.New("bundle output must be outside immutable corpus")
	}
	output, err := os.CreateTemp(directory, ".native-bundle-")
	if err != nil {
		return bundle, err
	}
	temporary := output.Name()
	defer func() { _ = output.Close(); _ = os.Remove(temporary) }()
	hash := sha256.New()
	stored := &boundedWriter{output: io.MultiWriter(output, hash)}
	z, err := gzip.NewWriterLevel(stored, gzip.BestSpeed)
	if err != nil {
		return bundle, err
	}
	archive := tar.NewWriter(z)
	for _, file := range source.entry.Files {
		header := &tar.Header{Name: file.Path, Mode: 0444, Size: file.Bytes, Typeflag: tar.TypeReg, ModTime: time.Unix(0, 0), Format: tar.FormatPAX}
		if err = archive.WriteHeader(header); err != nil {
			return bundle, err
		}
		input, openErr := source.root.Open(file.Path)
		if openErr != nil {
			return bundle, openErr
		}
		err = copyVerified(ctx, archive, input, file.Bytes, file.SHA256)
		closeErr := input.Close()
		if err != nil {
			return bundle, err
		}
		if closeErr != nil {
			return bundle, closeErr
		}
	}
	if err = archive.Close(); err != nil {
		return bundle, err
	}
	if err = z.Close(); err != nil {
		return bundle, err
	}
	if err = output.Sync(); err != nil {
		return bundle, err
	}
	if err = output.Close(); err != nil {
		return bundle, err
	}
	if err = source.Verify(ctx); err != nil {
		return bundle, err
	}
	bundle = Bundle{SHA256: hex.EncodeToString(hash.Sum(nil)), Bytes: stored.written}
	final := filepath.Join(directory, bundle.Filename())
	// Link publishes atomically without replacing any existing addressed file.
	if err = os.Link(temporary, final); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return bundle, err
		}
		info, statErr := os.Lstat(final)
		if statErr != nil {
			return bundle, statErr
		}
		if !info.Mode().IsRegular() || info.Size() != bundle.Bytes {
			return bundle, errors.New("existing addressed bundle differs")
		}
		input, openErr := os.Open(final)
		if openErr != nil {
			return bundle, openErr
		}
		defer func() { _ = input.Close() }()
		if err = copyVerified(ctx, io.Discard, input, bundle.Bytes, bundle.SHA256); err != nil {
			return bundle, err
		}
	}
	return bundle, nil
}
