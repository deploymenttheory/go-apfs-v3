package filecompression

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

func TestPreparationAdmissionAndSharedBudget(t *testing.T) {
	ctx := context.Background()
	clock := time.Unix(1700000000, 0).UTC()
	s, err := session.Create(ctx, filepath.Join(t.TempDir(), "source"), session.Options{Names: filesystem.NameRules{Format: "APFS", NormalizationInsensitive: true}, Time: &clock})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	budget := int64(64<<20) - 512
	if _, err = Prepare(ctx, s, "zlib", t.TempDir(), &budget); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal(err)
	}
	if _, err = Prepare(ctx, s, "unknown", "", &budget); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err = Prepare(ctx, nil, "preserve", "", &budget); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err = Prepare(ctx, s, "preserve", "", nil); !errors.Is(err, os.ErrInvalid) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	budget = 0
	if _, err = Prepare(ctx, s, "preserve", "", &budget); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
