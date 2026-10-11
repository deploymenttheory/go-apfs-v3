package acceptance_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/internal/decmpfs"
	"github.com/deploymenttheory/go-apfs-v3/pack"
)

// Both policies use the same native trees and existing image-building output
// archives. Apple's final verifier observes storage independently of this replay.
func buildCompressionOutputs(t *testing.T, r filesystem.Reader, want fileObservation, output string, clock time.Time) {
	t.Helper()
	if os.Getenv("APFS_REQUIRED_NATIVE_MAJORS") != "" {
		paths := map[string]bool{}
		for _, entry := range want.Entries {
			paths[entry.Path] = true
		}
		for _, name := range []string{"size-0", "size-1", "size-3801", "size-3802", "size-65535", "size-65536", "size-65537", "size-196625", "size-2097169", "incompressible", "mixed-blocks", "attribute-edge-3300", "attribute-edge-3900", "independent-inline", "independent-resource", "inactive-decmpfs", "hardlink"} {
			if !paths[want.Root+"/compression-writing/"+name] {
				t.Fatal("fresh native writing control missing", name)
			}
		}
	}
	format := "UDRO"
	if r.NameRules().CaseSensitive {
		format = "UDZO"
	}
	for _, policy := range []string{"zlib", "none"} {
		t.Run("file-compression/"+policy, func(t *testing.T) {
			path := filepath.Join(output, "file-compression", policy, format+".dmg")
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			options := pack.Options{Format: format, FileCompression: policy, Volume: pack.VolumeOptions{Name: "Example", Time: clock, CaseSensitive: r.NameRules().CaseSensitive}}
			if r.NameRules().CaseSensitive {
				options.Volume.Capacity = 160 << 20
			}
			report, err := pack.Create(context.Background(), path, r, options)
			if err != nil {
				t.Fatal(err)
			}
			b, err := json.MarshalIndent(report, "", "  ")
			if err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(filepath.Join(filepath.Dir(path), "report.json"), b, 0600); err != nil {
				t.Fatal(err)
			}
			repeat := filepath.Join(t.TempDir(), "repeat.dmg")
			if _, err = pack.Create(context.Background(), repeat, r, options); err != nil {
				t.Fatal(err)
			}
			if fileDigest(t, path) != fileDigest(t, repeat) {
				t.Fatal("file compression is not reproducible")
			}
			image, err := diskimage.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer image.Close()
			section, err := image.Partition(0)
			if err != nil {
				t.Fatal(err)
			}
			var built filesystem.Reader
			if r.NameRules().Format == "APFS" {
				c, e := apfs.Open(section)
				if e != nil {
					t.Fatal(e)
				}
				built = &c.Volumes[0]
			} else {
				v, e := hfsplus.Open(section)
				if e != nil {
					t.Fatal(e)
				}
				built = v
			}
			compareCompressedBuild(t, r, built, want, policy)
			t.Logf("%s: %d file outcomes, deterministic %s output; independent Apple readback required", policy, len(report.Compression), format)
		})
	}
}

func compareCompressedBuild(t *testing.T, source, built filesystem.Reader, want fileObservation, policy string) {
	t.Helper()
	ctx := context.Background()
	relative := want
	relative.Root = "."
	relative.Entries = append([]nativeFile(nil), want.Entries...)
	relative.RawAttributes = nil
	forward, reverse := map[uint64]uint64{}, map[uint64]uint64{}
	for i := range relative.Entries {
		e := &relative.Entries[i]
		original := e.Object
		e.Path = strings.TrimPrefix(e.Path, want.Root+"/")
		if e.Path == want.Root {
			e.Path = "."
		}
		id, err := filesystem.LookupExact(ctx, built, e.Path)
		if err != nil {
			t.Fatal(err)
		}
		if old, ok := forward[original]; ok && old != id {
			t.Fatal("compressed hard link split")
		}
		if old, ok := reverse[id]; ok && old != original {
			t.Fatal("unrelated compressed files merged")
		}
		forward[original], reverse[id] = id, original
		e.Object = id
		before, err := source.Stat(ctx, original)
		if err != nil {
			t.Fatal(err)
		}
		after, err := built.Stat(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if before.Metadata.BSDFlags.Value&^32 != after.Metadata.BSDFlags.Value&^32 {
			t.Fatal("unrelated flags changed")
		}
		e.Flags = after.Metadata.BSDFlags.Value
		if policy == "none" && after.Compression.State != filesystem.Absent {
			t.Fatal("compression survived none", e.Path)
		}
		if policy == "zlib" && after.Compression.State == filesystem.Present && after.Compression.Value.Type != 3 && after.Compression.Value.Type != 4 {
			t.Fatal("new compression is not zlib")
		}
		owned := map[string]bool{}
		if before.Compression.State == filesystem.Present {
			owned[filesystem.Decmpfs] = true
			uses, err := decmpfs.UsesResourceFork(before.Compression.Value.Type)
			if err != nil {
				t.Fatal(err)
			}
			owned[filesystem.ResourceFork] = uses
		}
		e.Attributes = make(map[string]nativeValue)
		for name, value := range want.Entries[i].Attributes {
			if !owned[name] {
				e.Attributes[name] = value
			}
		}
		for _, raw := range want.RawAttributes {
			if raw.Object == original {
				for name, value := range raw.Attributes {
					if !owned[name] {
						v, err := built.OpenAttribute(ctx, id, name)
						if err != nil {
							t.Fatal(err)
						}
						compareValue(t, e.Path+":"+name, v, value)
					}
				}
				break
			}
		}
	}
	compareFiles(t, built, relative)
}
