package acceptance_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/internal/qualification/decoded"
)

// Original archives and decoded inputs are immutable. Each edit continues to
// create its own output; a cached disk never supplies writable test scratch.
func decodedNativeArchive(t *testing.T, directory string, archive hfsGrowthArchive, limit int64) string {
	t.Helper()
	verifyDigest(t, directory, archive.Image, archive.SHA256)
	cache := decoded.Cache{Directory: os.Getenv("APFS_DECODED_INPUT_CACHE")}
	input, err := cache.Open(t.Context(), decoded.Archive{
		Path: filepath.Join(directory, archive.Image), StoredSHA256: archive.SHA256,
		SHA256: archive.UncompressedSHA256, Bytes: archive.UncompressedBytes, Limit: limit,
	}, t.TempDir())
	if err != nil {
		t.Fatal("native disk archive admission", err)
	}
	t.Cleanup(func() {
		if err := input.Verify(context.Background()); err != nil {
			t.Error("original or decoded native input changed", err)
		}
	})
	if input.Cached {
		t.Log("Using verified immutable decoded native input")
	}
	return input.Path
}
