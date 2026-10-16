package decoded

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func controlArchive(t testing.TB, data []byte) Archive {
	t.Helper()
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(t.TempDir(), "reference.raw.gz")
	if err := os.WriteFile(name, compressed.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return Archive{Path: name, StoredSHA256: digest(compressed.Bytes()), SHA256: digest(data), Bytes: int64(len(data)), Limit: int64(len(data))}
}

func controlCache(t testing.TB, budget int64) Cache {
	t.Helper()
	cache := Cache{Directory: filepath.Join(t.TempDir(), "decoded"), Budget: budget}
	t.Cleanup(func() {
		_ = filepath.WalkDir(cache.Directory, func(path string, entry os.DirEntry, err error) error {
			if err == nil && !entry.IsDir() {
				_ = os.Chmod(path, 0600)
			}
			return nil
		})
	})
	return cache
}

func TestDecodedReusePreservesSourceAndRejectsConsumerMutation(t *testing.T) {
	ctx := context.Background()
	data := append(bytes.Repeat([]byte{0}, 128<<10), []byte("native control bytes")...)
	archive := controlArchive(t, data)
	cache := controlCache(t, 1<<20)
	first, err := cache.Open(ctx, archive, t.TempDir())
	if err != nil || !first.Cached {
		t.Fatal("original decode failed", err)
	}
	second, err := cache.Open(ctx, archive, t.TempDir())
	if err != nil || !second.Cached || second.Path != first.Path {
		t.Fatal("identical original bytes were decoded again", err)
	}
	actual, err := os.ReadFile(second.Path)
	if err != nil || !bytes.Equal(actual, data) || second.Verify(ctx) != nil {
		t.Fatal("sparse decode lost original bytes", err)
	}
	writable := filepath.Join(t.TempDir(), "output.raw")
	if err = os.WriteFile(writable, actual, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(writable, []byte("independent output"), 0600); err != nil || second.Verify(ctx) != nil {
		t.Fatal("writable scratch aliased immutable source", err)
	}
	if err = os.Chmod(first.Path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(first.Path, bytes.Repeat([]byte{1}, len(data)), 0600); err != nil {
		t.Fatal(err)
	}
	if err = first.Verify(ctx); err == nil {
		t.Fatal("consumer mutation was not detected")
	}
	if _, err = cache.Open(ctx, archive, t.TempDir()); err == nil {
		t.Fatal("corrupt cached bytes were silently reused or replaced")
	}
	if err = verify(ctx, archive.Path, -1, archive.StoredSHA256); err != nil {
		t.Fatal("decoding or consumer writes changed original evidence", err)
	}
}

func TestDecodedRelativeEvidencePathsRemainSeparateFromAbsoluteScratch(t *testing.T) {
	archive := controlArchive(t, []byte("native source with repository-relative path"))
	working, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	archive.Path, err = filepath.Rel(working, archive.Path)
	if err != nil {
		t.Fatal(err)
	}
	input, err := controlCache(t, 4096).Open(context.Background(), archive, t.TempDir())
	if err != nil || !input.Cached || !filepath.IsAbs(input.Path) || input.Verify(context.Background()) != nil {
		t.Fatal("relative original evidence could not use managed absolute scratch", err)
	}
}

func TestDecodedOriginalArchiveMutationCannotReuseEarlierDisk(t *testing.T) {
	ctx := context.Background()
	archive := controlArchive(t, []byte("original native evidence"))
	cache := controlCache(t, 4096)
	input, err := cache.Open(ctx, archive, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(archive.Path, []byte("changed captured archive"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = input.Verify(ctx); err == nil {
		t.Fatal("decoded disk concealed mutation of its original archive")
	}
	if _, err = cache.Open(ctx, archive, t.TempDir()); err == nil {
		t.Fatal("old decoded bytes bypassed changed original evidence")
	}
	if err = verify(ctx, input.Path, archive.Bytes, archive.SHA256); err != nil {
		t.Fatal("refusing changed original archive rewrote cached bytes", err)
	}
}

func TestDecodedCapacityKeepsOversizedAndOverflowInputsUncached(t *testing.T) {
	ctx := context.Background()
	cache := controlCache(t, 32)
	first := controlArchive(t, bytes.Repeat([]byte{1}, 24))
	second := controlArchive(t, bytes.Repeat([]byte{2}, 16))
	large := controlArchive(t, bytes.Repeat([]byte{3}, 64))
	for index, archive := range []Archive{first, second, large} {
		input, err := cache.Open(ctx, archive, t.TempDir())
		if err != nil || input.Cached != (index == 0) || input.Verify(ctx) != nil {
			t.Fatal("budget admission changed decode behavior", index, err)
		}
	}
	used, err := inspect(ctx, cache.Directory, cache.Budget)
	if err != nil || used != first.Bytes {
		t.Fatal("decoded cache exceeded its logical byte budget", used, err)
	}
	cache.Budget = Capacity + 1
	if _, err = cache.Open(ctx, first, t.TempDir()); err == nil {
		t.Fatal("job-local cache accepted more than 2 GiB")
	}
}

func TestDecodedInterruptionNeverPublishesPartialInput(t *testing.T) {
	ctx := context.Background()
	archive := controlArchive(t, bytes.Repeat([]byte{0}, 4096))
	cache := controlCache(t, 8192)
	if err := os.Mkdir(cache.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	partial := filepath.Join(cache.Directory, ".decode-123")
	if err := os.WriteFile(partial, []byte("interrupted writer"), 0600); err != nil {
		t.Fatal(err)
	}
	input, err := cache.Open(ctx, archive, t.TempDir())
	if err != nil || !input.Cached || input.Verify(ctx) != nil {
		t.Fatal("interrupted temporary file contaminated publication", err)
	}
	if _, err = os.Lstat(partial); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("interrupted private decode retained", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = cache.Open(cancelled, archive, t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatal("cancelled decode returned reusable evidence", err)
	}
}

func TestDecodedWrongHashesBoundsAndAliasedPathsFailClosed(t *testing.T) {
	ctx := context.Background()
	archive := controlArchive(t, []byte("captured native disk"))
	cache := controlCache(t, 4096)
	for _, mutation := range []string{"stored-hash", "decoded-hash", "size", "bound", "source-scratch", "cache-source", "cache-scratch"} {
		t.Run(mutation, func(t *testing.T) {
			changed, option, scratch := archive, cache, t.TempDir()
			switch mutation {
			case "stored-hash":
				changed.StoredSHA256 = strings.Repeat("a", 64)
			case "decoded-hash":
				changed.SHA256 = strings.Repeat("a", 64)
			case "size":
				changed.Bytes--
			case "bound":
				changed.Limit--
			case "source-scratch":
				scratch = filepath.Dir(archive.Path)
			case "cache-source":
				option.Directory = filepath.Dir(archive.Path)
			case "cache-scratch":
				option.Directory = scratch
			}
			if _, err := option.Open(ctx, changed, scratch); err == nil {
				t.Fatal("invalid decoded input was admitted")
			}
		})
	}
	if _, err := cache.Open(ctx, archive, t.TempDir()); err != nil {
		t.Fatal("failed decodes contaminated later admission", err)
	}
	if err := os.WriteFile(filepath.Join(cache.Directory, "unowned.raw"), []byte("unknown owner"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Open(ctx, archive, t.TempDir()); err == nil {
		t.Fatal("unowned cache member bypassed accounting")
	}
}

func TestDecodedConcurrentReadersPublishOneImmutableCopy(t *testing.T) {
	ctx := context.Background()
	archive := controlArchive(t, bytes.Repeat([]byte("native bytes"), 4096))
	cache := controlCache(t, 1<<20)
	var workers sync.WaitGroup
	paths := make(chan string, 8)
	errorsFound := make(chan error, 8)
	for range 8 {
		scratch := t.TempDir()
		workers.Go(func() {
			input, err := cache.Open(ctx, archive, scratch)
			if err != nil {
				errorsFound <- err
				return
			}
			paths <- input.Path
			errorsFound <- input.Verify(ctx)
		})
	}
	workers.Wait()
	close(paths)
	close(errorsFound)
	for err := range errorsFound {
		if err != nil {
			t.Fatal(err)
		}
	}
	var original string
	for path := range paths {
		if original != "" && original != path {
			t.Fatal("concurrent readers published duplicate decoded inputs")
		}
		original = path
	}
	used, err := inspect(ctx, cache.Directory, cache.Budget)
	if err != nil || used != archive.Bytes {
		t.Fatal("concurrent publication violated the cap", used, err)
	}
}

func TestDecodedLockProcess(t *testing.T) {
	name := os.Getenv("APFS_DECODED_LOCK_CONTROL")
	if name == "" {
		return
	}
	lock, err := lockCache(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	if _, err = os.Stdout.WriteString("locked\n"); err != nil {
		t.Fatal(err)
	}
	_, _ = os.Stdin.Read(make([]byte, 1))
}

func TestDecodedLockWaitCancelsAndInterruptedProcessReleasesOwnership(t *testing.T) {
	name := filepath.Join(t.TempDir(), ".lock")
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestDecodedLockProcess$")
	child.Env = append(os.Environ(), "APFS_DECODED_LOCK_CONTROL="+name)
	input, err := child.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = input.Close() }()
	output, err := child.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	child.Stderr = os.Stderr
	if err = child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if child.ProcessState == nil {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	})
	ready, err := bufio.NewReader(output).ReadString('\n')
	if err != nil || ready != "locked\n" {
		t.Fatal("child did not hold the original OS file lock", ready, err)
	}
	bounded, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	defer stop()
	if lock, err := lockCache(bounded, name); !errors.Is(err, context.DeadlineExceeded) {
		if lock != nil {
			_ = lock.Close()
		}
		t.Fatal("another process bypassed ownership or ignored cancellation", err)
	}
	if err = child.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = child.Wait()
	lock, err := lockCache(ctx, name)
	if err != nil {
		t.Fatal("interrupted writer left a stale ownership lease", err)
	}
	if err = lock.Close(); err != nil {
		t.Fatal(err)
	}
}
