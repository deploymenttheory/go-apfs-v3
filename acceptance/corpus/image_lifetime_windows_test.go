//go:build windows

package corpus

import (
	"context"
	"os"
	"testing"
)

func TestWindowsOpenReaderDeletionFailureRetainsItsBackingPath(t *testing.T) {
	source, digest := compressedRaw(t, []byte("ordinary Windows file-lifetime control"))
	c := &Corpus{ExpandDir: t.TempDir()}
	lease, err := c.AcquireImage(context.Background(), rawLeaseCase(source, digest))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := os.Open(lease.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	// Deliberately violate release ordering to prove the OS refusal is fatal;
	// correct callers keep this reader's lease until after reader.Close.
	if err := lease.Release(nil); err == nil {
		t.Fatal("open Windows backing handle did not make release fail")
	}
	if err := c.Close(); err == nil {
		t.Fatal("run cleanup discarded the failed release")
	}
	if _, err := os.Stat(lease.Path()); err != nil {
		t.Fatal("failed cleanup lost the backing path", err)
	}
}
