// Package decoded reuses verified, read-only native input bytes within one CI
// job. It never retains test verdicts or supplies writable filesystem scratch.
package decoded

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/corpus"
)

const Capacity int64 = 2 << 30

type Archive struct {
	Path, StoredSHA256, SHA256 string
	Bytes, Limit               int64
}

// Directory is exclusively owned by qualification within RUNNER_TEMP. An empty
// directory disables caching. Budget defaults to Capacity and cannot exceed it.
type Cache struct {
	Directory string
	Budget    int64
}

type Input struct {
	Path   string
	Cached bool
	source Archive
	bytes  int64
}

// Verify detects consumer mutation as well as changes to the original archive.
// Cached paths are read-only; writable outputs must use distinct scratch files.
func (i *Input) Verify(ctx context.Context) error {
	if err := verify(ctx, i.source.Path, -1, i.source.StoredSHA256); err != nil {
		return err
	}
	return verify(ctx, i.Path, i.bytes, i.source.SHA256)
}

var (
	cacheGate = make(chan struct{}, 1)
	cacheName = regexp.MustCompile(`^sha256-[a-f0-9]{64}-[a-f0-9]{64}\.raw$`)
	partial   = regexp.MustCompile(`^\.decode-[0-9]+$`)
)

func (c Cache) Open(ctx context.Context, source Archive, scratch string) (_ *Input, err error) {
	if !corpus.ValidDigest(source.StoredSHA256) || !corpus.ValidDigest(source.SHA256) || source.Limit <= 0 || source.Limit > corpus.MaxTreeBytes || source.Bytes < 0 || source.Bytes > source.Limit {
		return nil, errors.New("incomplete decoded input contract")
	}
	budget := c.Budget
	if budget == 0 {
		budget = Capacity
	}
	if budget < 0 || budget > Capacity {
		return nil, errors.New("decoded input budget exceeds the job-local cap")
	}
	source.Path, err = ordinaryPath(source.Path, false)
	if err != nil {
		return nil, err
	}
	scratch, err = ordinaryPath(scratch, true)
	if err != nil {
		return nil, err
	}
	if err = separate(filepath.Dir(source.Path), scratch); err != nil {
		return nil, err
	}
	if err = verify(ctx, source.Path, -1, source.StoredSHA256); err != nil {
		return nil, err
	}
	result := &Input{source: source}
	// Unknown lengths and oversize inputs keep the bounded uncached path. Do
	// not evict inputs that another test may still be reading.
	if c.Directory == "" || source.Bytes == 0 || source.Bytes > budget {
		result.Path, result.bytes, err = decode(ctx, source, scratch)
		return result, err
	}
	cache, err := cacheDirectory(c.Directory)
	if err != nil {
		return nil, err
	}
	if err = errors.Join(separate(cache, filepath.Dir(source.Path)), separate(cache, scratch)); err != nil {
		return nil, err
	}
	select {
	case cacheGate <- struct{}{}:
		defer func() { <-cacheGate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	lock, err := lockCache(ctx, filepath.Join(cache, ".lock"))
	if err != nil {
		return nil, err
	}
	defer func() { _ = lock.Close() }() // The OS also releases this lock on process exit.
	used, err := inspect(ctx, cache, budget)
	if err != nil {
		return nil, err
	}
	name := filepath.Join(cache, "sha256-"+source.StoredSHA256+"-"+source.SHA256+".raw")
	if _, statErr := os.Lstat(name); statErr == nil {
		if err = verify(ctx, name, source.Bytes, source.SHA256); err != nil {
			return nil, fmt.Errorf("cached input changed: %w", err)
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return nil, statErr
	} else if source.Bytes > budget-used {
		result.Path, result.bytes, err = decode(ctx, source, scratch)
		return result, err
	} else {
		var temporary string
		temporary, result.bytes, err = decode(ctx, source, cache)
		if err != nil {
			return nil, err
		}
		defer func() { _ = os.Remove(temporary) }()
		if err = verify(ctx, source.Path, -1, source.StoredSHA256); err != nil {
			return nil, err
		}
		if err = os.Rename(temporary, name); err != nil {
			return nil, err
		}
	}
	// A process interrupted between rename and chmod leaves complete bytes.
	// Verify those bytes on the next open, then restore read-only protection.
	if err = os.Chmod(name, 0400); err != nil {
		return nil, err
	}
	if err = verify(ctx, source.Path, -1, source.StoredSHA256); err != nil {
		return nil, err
	}
	result.Path, result.bytes, result.Cached = name, source.Bytes, true
	return result, nil
}

func ordinaryPath(name string, directory bool) (string, error) {
	name, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(name)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || directory && !info.IsDir() || !directory && !info.Mode().IsRegular() {
		return "", errors.New("decoded inputs require ordinary source and scratch paths")
	}
	return filepath.EvalSymlinks(name)
}

func separate(left, right string) error {
	if !filepath.IsAbs(left) || !filepath.IsAbs(right) {
		return errors.New("decoded path separation requires absolute resolved paths")
	}
	// ordinaryPath has already resolved both locations. Different Windows
	// volumes cannot contain each other, and filepath.Rel intentionally fails
	// across them (the hosted checkout and test scratch use D: and C:).
	if !strings.EqualFold(filepath.VolumeName(left), filepath.VolumeName(right)) {
		return nil
	}
	for _, pair := range [][2]string{{left, right}, {right, left}} {
		relative, err := filepath.Rel(pair[0], pair[1])
		if err != nil {
			return err
		}
		if relative == "." || filepath.IsLocal(relative) {
			return errors.New("decoded cache, original inputs and writable scratch must be separate")
		}
	}
	return nil
}

func cacheDirectory(name string) (string, error) {
	if !filepath.IsAbs(name) {
		return "", errors.New("decoded cache requires an absolute job-local directory")
	}
	if err := os.Mkdir(name, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	return ordinaryPath(name, true)
}

func inspect(ctx context.Context, directory string, budget int64) (int64, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, err
	}
	if len(entries) > 10000 {
		return 0, errors.New("decoded cache member bound exceeded")
	}
	var used int64
	for _, entry := range entries {
		if err = ctx.Err(); err != nil {
			return 0, err
		}
		info, err := entry.Info()
		if err != nil {
			return 0, err
		}
		if !info.Mode().IsRegular() {
			return 0, errors.New("decoded cache contains an aliased or special member")
		}
		switch {
		case entry.Name() == ".lock":
			if info.Size() != 0 {
				return 0, errors.New("decoded cache lock contains unowned bytes")
			}
		case partial.MatchString(entry.Name()):
			// No active writer holds the OS lock, so these are interrupted
			// private scratch files. None was published as a reusable input.
			if err = os.Remove(filepath.Join(directory, entry.Name())); err != nil {
				return 0, err
			}
		case cacheName.MatchString(entry.Name()):
			if info.Size() <= 0 || info.Size() > budget-used {
				return 0, errors.New("decoded cache exceeds its logical byte cap")
			}
			used += info.Size()
		default:
			return 0, errors.New("decoded cache contains an unowned member")
		}
	}
	return used, nil
}

func verify(ctx context.Context, name string, size int64, want string) error {
	if _, err := ordinaryPath(name, false); err != nil {
		return err
	}
	input, err := os.Open(name)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	info, err := input.Stat()
	if err != nil {
		return err
	}
	if info.Size() > corpus.MaxTreeBytes || size >= 0 && info.Size() != size {
		return errors.New("decoded input size differs")
	}
	digest := sha256.New()
	buffer := make([]byte, 128<<10)
	var count int64
	for {
		if err = ctx.Err(); err != nil {
			return err
		}
		n, readErr := input.Read(buffer)
		count += int64(n)
		if count > info.Size() {
			return errors.New("decoded input changed while hashing")
		}
		_, _ = digest.Write(buffer[:n])
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}
	if count != info.Size() || hex.EncodeToString(digest.Sum(nil)) != want {
		return errors.New("decoded input hash or length differs")
	}
	return nil
}

func decode(ctx context.Context, source Archive, directory string) (name string, count int64, err error) {
	input, err := os.Open(source.Path)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = input.Close() }()
	compressed, err := gzip.NewReader(input)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = compressed.Close() }()
	output, err := os.CreateTemp(directory, ".decode-")
	if err != nil {
		return "", 0, err
	}
	name = output.Name()
	defer func() {
		closeErr := output.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			_ = os.Remove(name)
		}
	}()
	digest := sha256.New()
	buffer := make([]byte, 128<<10)
	limit := source.Limit
	if source.Bytes > 0 {
		limit = source.Bytes
	}
	for {
		if err = ctx.Err(); err != nil {
			return name, count, err
		}
		n, readErr := compressed.Read(buffer)
		if int64(n) > limit-count {
			return name, count, errors.New("native archive exceeds its original decoded bound")
		}
		data := buffer[:n]
		_, _ = digest.Write(data)
		if bytes.Count(data, []byte{0}) != n {
			written, writeErr := output.WriteAt(data, count)
			if writeErr != nil || written != n {
				return name, count, errors.Join(writeErr, io.ErrShortWrite)
			}
		}
		count += int64(n)
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return name, count, readErr
		}
	}
	if count == 0 || source.Bytes > 0 && count != source.Bytes || hex.EncodeToString(digest.Sum(nil)) != source.SHA256 {
		return name, count, errors.New("native archive decoded hash or length differs")
	}
	if err = output.Truncate(count); err == nil {
		err = output.Sync()
	}
	return name, count, err
}

// Waiting for an OS file lock remains cancellable and never leaves a stale
// pid/timeout lease after an interrupted writer.
func waitLock(ctx context.Context, attempt func() (bool, error)) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		locked, err := attempt()
		if err != nil || locked {
			return err
		}
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func openLock(name string) (*os.File, error) {
	if info, err := os.Lstat(name); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("decoded cache lock is aliased or special")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if !strings.HasSuffix(name, string(filepath.Separator)+".lock") {
		return nil, errors.New("invalid decoded cache lock path")
	}
	return os.OpenFile(name, os.O_CREATE|os.O_RDWR, 0600)
}
