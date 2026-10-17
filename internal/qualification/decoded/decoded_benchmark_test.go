package decoded

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Use the real original source of the 120,000-file HFS boundary case. This
// benchmarks immutable input admission only; it does not shorten or execute the
// filesystem mutation test and cannot grant its acceptance verdict.
func BenchmarkRetainedHFSCatalogSource(b *testing.B) {
	directory, err := filepath.Abs("../../../acceptance/testdata/hfs-metadata-growth/macos-15")
	if err != nil {
		b.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(directory, "manifest.json"))
	if err != nil {
		b.Fatal(err)
	}
	var manifest struct {
		Cases []struct {
			ID     string
			Source struct {
				Image, SHA256, UncompressedSHA256 string
				UncompressedBytes                 int64
			}
		}
	}
	if err = json.Unmarshal(data, &manifest); err != nil {
		b.Fatal(err)
	}
	var archive Archive
	for _, c := range manifest.Cases {
		if c.ID == "hfsplus-catalog-map-growth" {
			archive = Archive{Path: filepath.Join(directory, c.Source.Image), StoredSHA256: c.Source.SHA256, SHA256: c.Source.UncompressedSHA256, Bytes: c.Source.UncompressedBytes, Limit: 2 << 30}
		}
	}
	if archive.Bytes != 512<<20 {
		b.Fatal("original HFS catalog source boundary changed")
	}
	for _, name := range []string{"decode-each-time", "reuse-decoded"} {
		b.Run(name, func(b *testing.B) {
			cache := Cache{}
			if name == "reuse-decoded" {
				cache = controlCache(b, Capacity)
			}
			scratch := b.TempDir()
			ctx := context.Background()
			if cache.Directory != "" {
				if _, err := cache.Open(ctx, archive, scratch); err != nil {
					b.Fatal(err)
				}
			}
			b.SetBytes(archive.Bytes)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				input, err := cache.Open(ctx, archive, scratch)
				if err != nil {
					b.Fatal(err)
				}
				if err = input.Verify(ctx); err != nil {
					b.Fatal(err)
				}
				if !input.Cached {
					if err = os.Remove(input.Path); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
