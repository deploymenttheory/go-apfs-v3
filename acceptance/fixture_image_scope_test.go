package acceptance_test

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestFixtureLeaseScopePreservesFirstCleanupFailureWithoutPinningHealthyOperations(t *testing.T) {
	for _, state := range []string{"healthy reader after operation failure", "failed reader close", "unrelated output close failure"} {
		t.Run(state, func(t *testing.T) {
			uncertain := state == "failed reader close"
			file := filepath.Join(t.TempDir(), "synthetic.raw.gz")
			out, err := os.Create(file)
			if err != nil {
				t.Fatal(err)
			}
			z := gzip.NewWriter(out)
			_, writeErr := z.Write([]byte("ordinary lease-scope bytes"))
			if err := errors.Join(writeErr, z.Close(), out.Close()); err != nil {
				t.Fatal(err)
			}
			digest, err := schema.FileDigest(file)
			if err != nil {
				t.Fatal(err)
			}
			c := &corpus.Corpus{ExpandDir: t.TempDir()}
			lease, err := c.AcquireImage(context.Background(), corpus.Case{Dir: filepath.Dir(file), Observation: &schema.Observation{Image: schema.Image{File: filepath.Base(file), SHA256: digest}}})
			if err != nil {
				t.Fatal(err)
			}
			reader := io.NopCloser(strings.NewReader("owned input"))
			scope := &fixtureImageScope{images: map[string]*corpus.ImageLease{"input": lease}, readers: map[io.Closer]*corpus.ImageLease{reader: lease}}
			cause := errors.New("first reader close failed")
			if uncertain {
				scope.recordCleanup(reader, cause)
			} else if state == "unrelated output close failure" {
				scope.recordCleanup(io.NopCloser(strings.NewReader("unrelated output")), cause)
			}
			// Later idempotent Close calls often return nil. They must never erase
			// the first cleanup error, and assertion state alone does not pin.
			scope.recordCleanup(reader, nil)
			err = scope.release()
			if uncertain {
				if !errors.Is(err, cause) || !errors.Is(c.Close(), cause) {
					t.Fatal("first cleanup error was hidden", err)
				}
				if _, err := os.Stat(lease.Path()); err != nil {
					t.Fatal("uncertain source lost backing", err)
				}
			} else {
				if err != nil || c.Close() != nil {
					t.Fatal("healthy reader release failed", err)
				}
				if _, err := os.Stat(lease.Path()); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("healthy reader pinned by a separate operation failure", err)
				}
			}
		})
	}
}
