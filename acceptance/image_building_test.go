package acceptance_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

// TestNativeImageBuilding takes independently observed Apple files, captures a
// persistent session, and builds both UDIF encodings twice. CI returns every
// host's actual images to every Mac for fsck, mounted readback and codesign.
func TestNativeImageBuilding(t *testing.T) {
	t.Parallel()
	testFileCorpus(t, "image-building", "APFS_NATIVE_IMAGE_BUILDING", "testdata/image-building", 420, nil)
}

type buildRoot struct {
	filesystem.Reader
	id uint64
}

func (r buildRoot) Root() uint64 { return r.id }
func compareImageBuilding(t *testing.T, reader filesystem.Reader, want fileObservation, caseID, major string) {
	t.Helper()
	ctx := context.Background()
	id, err := filesystem.LookupExact(ctx, reader, want.Root)
	if err != nil {
		t.Fatal(err)
	}
	if len(want.RawAttributes) != len(want.Entries) {
		t.Fatal("missing raw attribute observations")
	}
	kinds := map[uint32]bool{}
	for _, entry := range want.Entries {
		n, e := reader.Stat(ctx, entry.Object)
		if e != nil {
			t.Fatal(e)
		}
		if n.Compression.State == filesystem.Present {
			kinds[n.Compression.Value.Type] = true
		}
	}
	for _, kind := range []uint32{1, 3, 4, 7, 8} {
		if !kinds[kind] {
			t.Fatal("missing native compression control", kind)
		}
	}
	clock := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
	s, err := session.Capture(ctx, buildRoot{reader, id}, filepath.Join(t.TempDir(), "session"), session.Options{Time: &clock})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	output := os.Getenv("APFS_IMAGE_BUILDING_OUTPUT")
	if output == "" {
		output = t.TempDir()
	}
	output = filepath.Join(output, "macos-"+major, strings.TrimPrefix(caseID, "image-building/"))
	if err = os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	if reader.NameRules().Format == "APFS" && !reader.NameRules().CaseSensitive {
		buildEmptyAPFS(t, reader, want, output, clock)
	}
	for _, format := range []string{"UDRO", "UDZO"} {
		t.Run(format, func(t *testing.T) {
			options := pack.Options{Format: format, Volume: pack.VolumeOptions{Name: "Example", Time: clock, CaseSensitive: reader.NameRules().CaseSensitive}}
			// Cross the allocation bitmap block boundary and exercise large zero chunks.
			if reader.NameRules().CaseSensitive {
				options.Volume.Capacity = 160 << 20
			}
			destination := filepath.Join(output, format+".dmg")
			report, err := pack.Create(ctx, destination, s, options)
			if err != nil {
				t.Fatal(err)
			}
			repeat := filepath.Join(t.TempDir(), "repeat.dmg")
			if _, err = pack.Create(ctx, repeat, s, options); err != nil {
				t.Fatal(err)
			}
			buildEncryptedOutput(t, destination, encryptedBuildBits(strings.TrimPrefix(caseID, "image-building/"), format), func(path string, encryption *diskimage.EncryptionOptions) error {
				encryptedOptions := options
				encryptedOptions.Encryption = encryption
				_, err := pack.Create(ctx, path, s, encryptedOptions)
				return err
			})
			sum := fileDigest(t, destination)
			if sum != fileDigest(t, repeat) {
				t.Fatal("identical build inputs produced different bytes")
			}
			img, err := diskimage.Open(destination)
			if err != nil {
				t.Fatal(err)
			}
			defer img.Close()
			if img.Size() != report.VolumeBytes {
				t.Fatal("wrong encoded volume size")
			}
			section, err := img.Partition(0)
			if err != nil {
				t.Fatal(err)
			}
			var volume filesystem.Reader
			if reader.NameRules().Format == "APFS" {
				container, e := apfs.Open(section)
				if e != nil {
					t.Fatal(e)
				}
				if len(container.Volumes) != 1 || container.Volumes[0].Name != "Example" || container.Volumes[0].Encrypted || container.Volumes[0].Sealed || container.Volumes[0].CaseSensitive != reader.NameRules().CaseSensitive {
					t.Fatal("wrong built APFS profile")
				}
				volume = &container.Volumes[0]
			} else {
				v, e := hfsplus.Open(section)
				if e != nil {
					t.Fatal(e)
				}
				if v.Name != "Example" || !v.Clean || v.Journaled || v.CaseSensitive != reader.NameRules().CaseSensitive {
					t.Fatal("wrong built HFS profile")
				}
				volume = v
			}
			if reader.NameRules().Format == "APFS" && len(want.Lookups) != 53 {
				t.Fatal("missing native name lookups")
			}
			compareBuiltFiles(t, volume, want)
			if sum != fileDigest(t, destination) {
				t.Fatal("readback changed image")
			}
			t.Logf("built %d native entries as %s; %d bytes; deterministic output", len(want.Entries), format, report.ImageBytes)
		})
	}
	buildCompressionOutputs(t, s, want, output, clock)
}

func buildEmptyAPFS(t *testing.T, r filesystem.Reader, want fileObservation, output string, clock time.Time) {
	t.Helper()
	ctx := context.Background()
	id, err := filesystem.LookupExact(ctx, r, want.Root+"/empty-build-root")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(output, "empty")
	if err = os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
	options := pack.Options{Format: "UDZO", Volume: pack.VolumeOptions{Name: "Example", Time: clock, Capacity: 64 << 20}}
	root := buildRoot{r, id}
	destination := filepath.Join(path, "UDZO.dmg")
	if _, err = pack.Create(ctx, destination, root, options); err != nil {
		t.Fatal(err)
	}
	repeat := filepath.Join(t.TempDir(), "repeat.dmg")
	if _, err = pack.Create(ctx, repeat, root, options); err != nil {
		t.Fatal(err)
	}
	if fileDigest(t, destination) != fileDigest(t, repeat) {
		t.Fatal("empty APFS build is not deterministic")
	}
}

func fileDigest(t *testing.T, path string) [32]byte {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		t.Fatal(err)
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum
}

func compareBuiltFiles(t *testing.T, volume filesystem.Reader, want fileObservation) {
	t.Helper()
	ctx := context.Background()
	relative := want
	relative.Root = "."
	relative.Entries = append([]nativeFile(nil), want.Entries...)
	forward, reverse := map[uint64]uint64{}, map[uint64]uint64{}
	for i := range relative.Entries {
		e := &relative.Entries[i]
		e.Path = strings.TrimPrefix(e.Path, want.Root+"/")
		if e.Path == want.Root {
			e.Path = "."
		}
		id, err := filesystem.LookupExact(ctx, volume, e.Path)
		if err != nil {
			t.Fatal(err)
		}
		if old, ok := forward[e.Object]; ok && old != id {
			t.Fatal("hard link split")
		}
		if old, ok := reverse[id]; ok && old != e.Object {
			t.Fatal("unrelated files merged")
		}
		forward[e.Object] = id
		reverse[id] = e.Object
		e.Object = id
	}
	compareFiles(t, volume, relative)
	for _, query := range want.Lookups {
		got, err := filesystem.Lookup(ctx, volume, strings.TrimPrefix(query.Path, want.Root+"/"))
		if query.Object == 0 {
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatal(query.Path, got, err)
			}
		} else if err != nil || got != forward[query.Object] {
			t.Fatal(query.Path, got, err)
		}
	}
	for _, raw := range want.RawAttributes {
		for name, value := range raw.Attributes {
			v, err := volume.OpenAttribute(ctx, forward[raw.Object], name)
			if err != nil {
				t.Fatal(err)
			}
			compareValue(t, name, v, value)
		}
	}
}
