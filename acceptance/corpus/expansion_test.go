package corpus

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func compressedRaw(t *testing.T, data []byte) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "apfs.final.raw.gz")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	if _, err := z.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	sum, err := schema.FileDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	return path, sum
}

func TestRawExpansionsDoNotReuseAnotherCapturesBytes(t *testing.T) {
	cache := t.TempDir()
	var paths []string
	for _, data := range [][]byte{[]byte("original Apple capture"), []byte("refreshed Apple capture")} {
		path, sum := compressedRaw(t, data)
		k := Case{Producer: 15, Recipe: "checkpoint-recovery", Dir: filepath.Dir(path), expandDir: cache, Observation: &schema.Observation{Image: schema.Image{File: filepath.Base(path), SHA256: sum}}}
		expanded := k.Image()
		paths = append(paths, expanded)
		got, err := os.ReadFile(expanded)
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("capture expanded to stale bytes %q (%v)", got, err)
		}
	}
	if paths[0] == paths[1] {
		t.Fatal("different capture digests share an expanded filename")
	}
}

func TestConcurrentRawExpansionPublishesOnlyCompleteCopies(t *testing.T) {
	data := make([]byte, 4<<20)
	copy(data[64<<10:], "native payload")
	copy(data[len(data)-100:], "tail payload")
	src, _ := compressedRaw(t, data)
	dst := filepath.Join(t.TempDir(), "expanded.raw")
	var wg sync.WaitGroup
	errors := make(chan error, 8)
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errors <- ExpandGzip(src, dst) }()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	got, err := os.ReadFile(dst)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("concurrent expansion published incomplete bytes", err)
	}
	partial, err := filepath.Glob(filepath.Join(filepath.Dir(dst), "*.partial-*"))
	if err != nil || len(partial) != 0 {
		t.Fatal("partial expansion files remain", partial, err)
	}
}

func TestTruncatedGzipCannotPublishAnExpandedImage(t *testing.T) {
	src, _ := compressedRaw(t, bytes.Repeat([]byte("native bytes"), 1000))
	f, err := os.OpenFile(src, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(info.Size() - 8); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "expanded.raw")
	if err := ExpandGzip(src, dst); err == nil {
		t.Fatal("truncated compressed evidence was accepted")
	}
	if _, err := os.Stat(dst); !os.IsNotExist(err) {
		t.Fatal("failed expansion published an image", err)
	}
}
