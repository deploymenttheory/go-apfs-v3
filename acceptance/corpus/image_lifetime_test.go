package corpus

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestCorpusOwnsAndReleasesOnlyItsRunExpansions(t *testing.T) {
	source, digest := compressedRaw(t, []byte("original compressed fixture"))
	parent := t.TempDir()
	legacy := filepath.Join(parent, "unrelated.raw")
	if err := os.WriteFile(legacy, []byte("not this run"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Corpus{ExpandDir: parent}
	k := rawLeaseCase(source, digest)
	first, err := c.AcquireImage(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.AcquireImage(context.Background(), k)
	if err != nil || first.Path() != second.Path() {
		t.Fatal("same source did not share its completed publication", err)
	}
	reader, err := os.Open(second.Path())
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Release(nil); err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(reader); err != nil || !bytes.Equal(got, []byte("original compressed fixture")) {
		t.Fatal("another release retired an active reader", err)
	}
	if _, err := os.Stat(second.Path()); err != nil {
		t.Fatal("active backing path disappeared", err)
	}
	if err := second.Release(reader.Close()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(second.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("last confirmed release retained a regenerable raw image", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(legacy); err != nil || string(got) != "not this run" {
		t.Fatal("run cleanup removed unrelated scratch storage", err)
	}
	if got, err := schema.FileDigest(source); err != nil || got != digest {
		t.Fatal("compressed original changed", err)
	}
}

func rawLeaseCase(source, digest string) Case {
	return Case{Dir: filepath.Dir(source), Observation: &schema.Observation{Image: schema.Image{File: filepath.Base(source), SHA256: digest}}}
}

func TestIdenticalSourceFilesKeepSeparateBackingPaths(t *testing.T) {
	source, digest := compressedRaw(t, []byte("identical original bytes"))
	copySource := filepath.Join(t.TempDir(), filepath.Base(source))
	compressed, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(copySource, compressed, 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Corpus{ExpandDir: t.TempDir()}
	first, err := c.AcquireImage(context.Background(), rawLeaseCase(source, digest))
	if err != nil {
		t.Fatal(err)
	}
	second, err := c.AcquireImage(context.Background(), rawLeaseCase(copySource, digest))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := errors.Join(first.Release(nil), second.Release(nil), c.Close()); err != nil {
			t.Error(err)
		}
	})
	if first.Path() == second.Path() {
		t.Fatal("distinct retained source paths collapsed into one backing path")
	}
	if err := os.WriteFile(first.Path(), []byte("first private working image"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(second.Path()); err != nil || string(got) != "identical original bytes" {
		t.Fatal("independent source backing changed", err)
	}
	if err := first.Release(nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(second.Path()); err != nil {
		t.Fatal("another source release retired this image", err)
	}
	for _, file := range []string{source, copySource} {
		if got, err := schema.FileDigest(file); err != nil || got != digest {
			t.Fatal("compressed original changed", err)
		}
	}
}

func TestUncertainCleanupPinsTheBackingPathAcrossRepeatedReleasesAndRunClose(t *testing.T) {
	source, digest := compressedRaw(t, []byte("retained raw bytes"))
	c := &Corpus{ExpandDir: t.TempDir()}
	lease, err := c.AcquireImage(context.Background(), rawLeaseCase(source, digest))
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("native release unknown")
	for _, err := range []error{lease.Release(cause), lease.Release(nil), c.Close(), c.Close()} {
		if !errors.Is(err, cause) {
			t.Fatal("cleanup uncertainty was lost", err)
		}
	}
	if got, err := os.ReadFile(lease.Path()); err != nil || string(got) != "retained raw bytes" {
		t.Fatal("uncertain backing path was deleted or renamed", err)
	}
}

type beforeAcquisitionReturn struct {
	context.Context
	once   sync.Once
	action func()
}

func (c *beforeAcquisitionReturn) Done() <-chan struct{} {
	c.once.Do(c.action)
	return c.Context.Done()
}

func TestPendingImageAcquisitionRejectsNewCleanupUncertainty(t *testing.T) {
	source, digest := compressedRaw(t, []byte("shared source backing"))
	c := &Corpus{ExpandDir: t.TempDir()}
	k := rawLeaseCase(source, digest)
	first, err := c.AcquireImage(context.Background(), k)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("another reader could not release the backing")
	// Schedule another lease's failed cleanup exactly after reservation, while
	// this acquisition still has not returned its path to the next reader.
	ctx := &beforeAcquisitionReturn{Context: context.Background(), action: func() {
		if err := first.Release(cause); !errors.Is(err, cause) {
			t.Error(err)
		}
	}}
	second, err := c.AcquireImage(ctx, k)
	if second != nil || !errors.Is(err, cause) {
		t.Fatal("pending acquisition escaped retained uncertainty", err)
	}
	if err := c.Close(); !errors.Is(err, cause) {
		t.Fatal("run lost uncertain backing", err)
	}
}

func TestAcquireAndRunCloseCannotDeleteAnUnfinishedPublication(t *testing.T) {
	source, digest := compressedRaw(t, bytes.Repeat([]byte("small synthetic image"), 2000))
	c := &Corpus{ExpandDir: t.TempDir()}
	started, release := make(chan struct{}), make(chan struct{})
	c.images.expand = func(ctx context.Context, source, destination string) error {
		close(started)
		<-release
		return ExpandGzipContext(ctx, source, destination)
	}
	result := make(chan error, 1)
	go func() { _, err := c.AcquireImage(context.Background(), rawLeaseCase(source, digest)); result <- err }()
	<-started
	root := c.images.root
	if err := c.Close(); err == nil {
		t.Fatal("run close did not report the in-flight acquisition")
	}
	if _, err := c.AcquireImage(context.Background(), rawLeaseCase(source, digest)); !errors.Is(err, fs.ErrClosed) {
		t.Fatal("closed run admitted another acquisition", err)
	}
	close(release)
	if err := <-result; !errors.Is(err, fs.ErrClosed) {
		t.Fatal("publication escaped the closed run", err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(root); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("completed acquisition retained the closed run directory", err)
	}
}

func TestCanceledWaiterDoesNotRetireAnotherImageLease(t *testing.T) {
	source, digest := compressedRaw(t, []byte("shared bytes"))
	c := &Corpus{ExpandDir: t.TempDir()}
	started, publish := make(chan struct{}), make(chan struct{})
	c.images.expand = func(ctx context.Context, source, destination string) error {
		close(started)
		<-publish
		return ExpandGzipContext(ctx, source, destination)
	}
	acquired := make(chan *ImageLease, 1)
	errorsCh := make(chan error, 1)
	go func() {
		lease, err := c.AcquireImage(context.Background(), rawLeaseCase(source, digest))
		acquired <- lease
		errorsCh <- err
	}()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	waiting := make(chan struct{})
	waiter := &acquisitionWaitContext{Context: ctx, waiting: waiting}
	waiterResult := make(chan error, 1)
	go func() { _, err := c.AcquireImage(waiter, rawLeaseCase(source, digest)); waiterResult <- err }()
	<-waiting
	cancel()
	if err := <-waiterResult; !errors.Is(err, context.Canceled) {
		t.Fatal("canceled acquisition was admitted", err)
	}
	close(publish)
	lease := <-acquired
	if err := <-errorsCh; err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(nil); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

type acquisitionWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *acquisitionWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func TestConcurrentImageReadersPublishOnlyCompletedBytesAndReleaseTheirRun(t *testing.T) {
	want := make([]byte, 2<<20)
	copy(want[6000:], "synthetic fixture payload")
	source, digest := compressedRaw(t, want)
	c := &Corpus{ExpandDir: t.TempDir()}
	var wg sync.WaitGroup
	errorsCh := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			lease, err := c.AcquireImage(context.Background(), rawLeaseCase(source, digest))
			if err != nil {
				errorsCh <- err
				return
			}
			data, readErr := os.ReadFile(lease.Path())
			if readErr == nil && !bytes.Equal(data, want) {
				readErr = errors.New("reader saw incomplete fixture bytes")
			}
			errorsCh <- errors.Join(readErr, lease.Release(nil))
		}()
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(c.ExpandDir)
	if err != nil || len(entries) != 0 {
		t.Fatal("successful run retained expanded history", err)
	}
}

type cancelExpansionReader struct {
	io.Reader
	cancel context.CancelFunc
}

func (r cancelExpansionReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	r.cancel()
	return n, err
}

func TestCanceledSparseExpansionCannotPublishOrLeakAPartialCopy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	dir := t.TempDir()
	dst := filepath.Join(dir, "fixture.raw")
	err := expandSparse(ctx, cancelExpansionReader{Reader: bytes.NewReader(make([]byte, 2<<20)), cancel: cancel}, dst)
	if !errors.Is(err, context.Canceled) {
		t.Fatal("expansion lost cancellation", err)
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 0 {
		t.Fatal("canceled expansion left a published or partial image", err)
	}
}

func TestFailedRawDeletionRetainsTheBackingAndReportsItsCause(t *testing.T) {
	source, digest := compressedRaw(t, []byte("synthetic backing"))
	c := &Corpus{ExpandDir: t.TempDir()}
	cause := errors.New("open-reader deletion refused")
	c.images.remove = func(string) error { return cause }
	lease, err := c.AcquireImage(context.Background(), rawLeaseCase(source, digest))
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(nil); !errors.Is(err, cause) {
		t.Fatal("failed release was hidden", err)
	}
	if err := c.Close(); !errors.Is(err, cause) {
		t.Fatal("run close erased failed-release state", err)
	}
	if _, err := os.Stat(lease.Path()); err != nil {
		t.Fatal("uncertain backing was deleted", err)
	}
}

func TestRepeatedRunsReleaseRawImagesAndNeverDeleteRetainedOriginals(t *testing.T) {
	parent := t.TempDir()
	source, digest := compressedRaw(t, []byte("same original across independent runs"))
	for range 3 {
		c := &Corpus{ExpandDir: parent}
		lease, err := c.AcquireImage(context.Background(), rawLeaseCase(source, digest))
		if err != nil {
			t.Fatal(err)
		}
		if err := errors.Join(lease.Release(nil), c.Close(), c.Close()); err != nil {
			t.Fatal(err)
		}
		entries, err := os.ReadDir(parent)
		if err != nil || len(entries) != 0 {
			t.Fatal("normal runs accumulated raw history", err)
		}
	}
	original := filepath.Join(t.TempDir(), "native-original.raw")
	if err := os.WriteFile(original, []byte("sole uncompressed evidence"), 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Corpus{ExpandDir: parent}
	lease, err := c.AcquireImage(context.Background(), Case{Dir: filepath.Dir(original), Observation: &schema.Observation{Image: schema.Image{File: filepath.Base(original)}}})
	if err != nil {
		t.Fatal(err)
	}
	if lease.Path() != original {
		t.Fatal("uncompressed original was moved")
	}
	if err := errors.Join(lease.Release(nil), c.Close()); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(original); err != nil || string(got) != "sole uncompressed evidence" {
		t.Fatal("original was deleted or rewritten", err)
	}
}
