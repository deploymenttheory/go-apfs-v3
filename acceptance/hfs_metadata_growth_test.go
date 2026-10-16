package acceptance_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

type hfsMetadataState struct {
	Files         fileObservation
	FileArchive   hfsGrowthArchive
	Headers       json.RawMessage
	CheckerStatus int
	Journal       json.RawMessage
}

type hfsMetadataCase struct {
	ID, Operation                            string
	Source, NativeAfter                      hfsGrowthArchive
	Before, After                            hfsMetadataState
	Sensitive, Journaled, Growth, Fragmented bool
	GrowthFiles                              int
	Collapsed, Reused                        *hfsMetadataState
	NativeCollapsed, NativeReused            hfsGrowthArchive
}

type hfsMetadataManifest struct {
	Schema, Major            int
	Contract, CommandsSHA256 string
	OriginalManifestSHA256   string
	Producer                 struct {
		System, Build, Architecture, Revision, Run string
		Sources                                    map[string]string
		Formatter                                  struct {
			HFSRevision, LibutilRevision, BinarySHA256, SDKVersion string
			Files                                                  []struct{ Path, SHA256 string }
		}
	}
	Cases []hfsMetadataCase
}

func hfsMetadataFiles(t *testing.T, directory string, state hfsMetadataState) fileObservation {
	t.Helper()
	if state.FileArchive.Image == "" {
		return state.Files
	}
	verifyDigest(t, directory, state.FileArchive.Image, state.FileArchive.SHA256)
	f, err := os.Open(filepath.Join(directory, state.FileArchive.Image))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	z, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	data, err := io.ReadAll(io.LimitReader(z, (128<<20)+1))
	if err != nil || len(data) > 128<<20 {
		t.Fatal("native observation bound", err)
	}
	var files fileObservation
	if err = json.Unmarshal(data, &files); err != nil {
		t.Fatal(err)
	}
	return files
}

func verifyNativeSourceDigest(t *testing.T, directory, name, digest string) {
	t.Helper()
	if !fs.ValidPath(name) || name == "." || len(digest) != 64 {
		t.Fatal("unsafe native source reference", name)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, err := root.Open(filepath.FromSlash(name))
	if errors.Is(err, os.ErrNotExist) {
		if err = checkCompressedDigest(root, filepath.FromSlash(name), digest, 4<<20); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 4<<20 {
		t.Fatal("native source bound", name, err)
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		t.Fatal("native source hash", name)
	}
}

// Catalog-map controls contain many long names by necessity. Cache one complete
// enumeration of each immutable directory so comparison remains linear. The
// expected identities/metadata still come entirely from Apple's observations.
type comparisonReader struct {
	filesystem.Reader
	children map[uint64][]filesystem.DirEntry
}

func (r *comparisonReader) ReadDir(ctx context.Context, id uint64, yield func(filesystem.DirEntry) error) error {
	values, ok := r.children[id]
	if !ok {
		if err := r.Reader.ReadDir(ctx, id, func(e filesystem.DirEntry) error { values = append(values, e); return nil }); err != nil {
			return err
		}
		r.children[id] = values
	}
	for _, e := range values {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := yield(e); err != nil {
			return err
		}
	}
	return nil
}

func hfsMetadataChanges(c hfsMetadataCase) []imageedit.Change {
	if c.Fragmented {
		changes := []imageedit.Change{{Operation: "mkdir", Path: "/Fixture"}}
		attribute := make([]byte, 512)
		for i := range attribute {
			attribute[i] = byte(i)
		}
		for n := 0; n < 256; n++ {
			name := fmt.Sprintf("%05d-", n) + strings.Repeat("long-name-", 24)
			path := "/Fixture/" + name
			changes = append(changes, imageedit.Change{Operation: "cp", Path: path, Data: bytes.NewReader([]byte("Metadata growth contents\n"))}, imageedit.Change{Operation: "xattr", Path: path, Attribute: "org.go-apfs.growth", Data: bytes.NewReader(attribute)})
		}
		return changes
	}
	if c.Growth {
		changes := make([]imageedit.Change, 0, c.GrowthFiles-1000)
		for n := 1000; n < c.GrowthFiles; n++ {
			name := fmt.Sprintf("%05d-", n) + strings.Repeat("long-name-", 24)
			changes = append(changes, imageedit.Change{Operation: "cp", Path: "/Fixture/" + name, Data: bytes.NewReader(nil)})
		}
		return changes
	}
	return []imageedit.Change{
		{Operation: "mkdir", Path: "/Fixture"},
		{Operation: "cp", Path: "/Fixture/data", Data: bytes.NewReader([]byte("First ordinary contents\n"))},
		{Operation: "xattr", Path: "/Fixture/data", Attribute: "org.go-apfs.first", Data: bytes.NewReader([]byte("First native attribute\x00\xff"))},
		{Operation: "ln", Path: "/Fixture/data", Destination: "/Fixture/alias"},
	}
}

func compareHFSEditedState(t *testing.T, reader filesystem.Reader, before, expected fileObservation, when time.Time) {
	t.Helper()
	r := &comparisonReader{Reader: reader, children: map[uint64][]filesystem.DirEntry{}}
	// Resolve the large flat namespace once, rather than scan it per object.
	ids := map[string]uint64{}
	root, err := filesystem.LookupExact(context.Background(), r, "Fixture")
	if err != nil {
		t.Fatal(err)
	}
	ids["Fixture"] = root
	if err = r.ReadDir(context.Background(), root, func(e filesystem.DirEntry) error { ids["Fixture/"+e.Name] = e.Object; return nil }); err != nil {
		t.Fatal(err)
	}
	previous := map[string]nativeFile{}
	for _, entry := range before.Entries {
		previous[entry.Path] = entry
	}
	forward, reverse := map[uint64]uint64{}, map[uint64]uint64{}
	expected.Entries = append([]nativeFile(nil), expected.Entries...)
	for i := range expected.Entries {
		entry := &expected.Entries[i]
		id, ok := ids[entry.Path]
		if !ok {
			t.Fatal("native path missing", entry.Path)
		}
		if old, ok := forward[entry.Object]; ok && old != id {
			t.Fatal("native aliases separated")
		}
		if old, ok := reverse[id]; ok && old != entry.Object {
			t.Fatal("native objects conflated")
		}
		forward[entry.Object], reverse[id] = id, entry.Object
		if old, ok := previous[entry.Path]; ok {
			if old.Object != id {
				t.Fatal("original catalog identity changed", entry.Path)
			}
			if entry.Path == "Fixture" {
				entry.ModifyNS, entry.ChangeNS = when.UnixNano(), when.UnixNano()
			}
		} else {
			entry.BirthSeconds = when.Unix()
			entry.BirthNS = nil
			entry.ModifyNS, entry.AccessNS, entry.ChangeNS = when.UnixNano(), when.UnixNano(), when.UnixNano()
		}
		entry.Object = id
	}
	// The underlying full directory enumeration established the exact names;
	// Reuse the common comparisons with that independently enumerated index.
	compareFilesAt(t, r, expected, ids)
	compareRawMetadata(t, r, expected)
}

func TestNativeHFSMetadataGrowth(t *testing.T) {
	testNativeHFSMetadataGrowth(t, "APFS_NATIVE_HFS_METADATA_GROWTH", "testdata/hfs-metadata-growth", "hfs-metadata-growth", 6, false)
}

func TestNativeHFSFragmentedMetadataGrowth(t *testing.T) {
	testNativeHFSMetadataGrowth(t, "APFS_NATIVE_HFS_FRAGMENTED_METADATA", "testdata/hfs-fragmented-metadata", "hfs-fragmented-metadata", 2, false)
}

func TestNativeHFSMetadataLifecycle(t *testing.T) {
	testNativeHFSMetadataGrowth(t, "APFS_NATIVE_HFS_METADATA_LIFECYCLE", "testdata/hfs-metadata-lifecycle", "hfs-fragmented-metadata", 2, true)
}

func testNativeHFSMetadataGrowth(t *testing.T, environment, retained, contract string, count int, requireLifecycle bool) {
	root := nativeInput(t, environment, retained)
	paths, err := filepath.Glob(filepath.Join(root, "macos-*", "manifest.json"))
	if err != nil || len(paths) == 0 {
		t.Fatal("native HFS completion references absent", err)
	}
	majors := map[int]bool{}
	for _, name := range paths {
		var manifest hfsMetadataManifest
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &manifest); err != nil {
			t.Fatal(err)
		}
		if manifest.Schema != 1 || manifest.Contract != contract || len(manifest.Cases) != count || manifest.Producer.System != "macOS" || manifest.Producer.Build == "" || manifest.Producer.Architecture == "" || len(manifest.Producer.Revision) != 40 || manifest.Producer.Run == "" || len(manifest.Producer.Formatter.Files) != 8 || manifest.Producer.Formatter.BinarySHA256 == "" || manifest.Producer.Formatter.SDKVersion == "" || majors[manifest.Major] {
			t.Fatal("native HFS inventory/provenance")
		}
		majors[manifest.Major] = true
		directory := filepath.Dir(name)
		if manifest.OriginalManifestSHA256 != "" {
			verifyDigest(t, directory, "original-manifest.json", manifest.OriginalManifestSHA256)
		}
		verifyDigest(t, directory, "commands.json", manifest.CommandsSHA256)
		for source, hash := range manifest.Producer.Sources {
			verifyNativeSourceDigest(t, directory, source, hash)
		}
		for _, file := range manifest.Producer.Formatter.Files {
			if manifest.Producer.Sources["reference/hfs/"+file.Path] != file.SHA256 {
				t.Fatal("original formatter source provenance", file.Path)
			}
		}
		for _, c := range manifest.Cases {
			t.Run(filepath.Base(directory)+"/"+c.ID, func(t *testing.T) {
				if c.Before.CheckerStatus != 0 || c.After.CheckerStatus != 0 || (c.Growth && c.GrowthFiles != 120000) {
					t.Fatal("native control incomplete")
				}
				verifyDigest(t, directory, c.NativeAfter.Image, c.NativeAfter.SHA256)
				source := openNativeDiskArchive(t, directory, c.Source)
				before, want := hfsMetadataFiles(t, directory, c.Before), hfsMetadataFiles(t, directory, c.After)
				outputVariable := "APFS_HFS_METADATA_GROWTH_OUTPUT"
				if c.Fragmented {
					outputVariable = "APFS_HFS_FRAGMENTED_METADATA_OUTPUT"
				}
				if requireLifecycle {
					outputVariable = "APFS_HFS_METADATA_LIFECYCLE_OUTPUT"
				}
				output := os.Getenv(outputVariable)
				if output == "" {
					output = t.TempDir()
				}
				output = filepath.Join(output, filepath.Base(directory), c.ID)
				if err = os.MkdirAll(output, 0700); err != nil {
					t.Fatal(err)
				}
				when := time.Unix(1749283750, 0).UTC()
				for _, format := range []string{"UDRO", "UDZO"} {
					t.Run(format, func(t *testing.T) {
						destination := filepath.Join(output, "edited-"+format+".dmg")
						_, err := imageedit.Edit(context.Background(), source, destination, imageedit.Options{Time: when, Format: format}, func(editor *imageedit.Editor) error { _, err := editor.Apply(hfsMetadataChanges(c)); return err })
						if err != nil {
							t.Fatal(err)
						}
						compareHFSEditedState(t, metadataReader(t, destination, "hfs"), before, want, when)
						if c.Fragmented {
							if (requireLifecycle || requireNativeControl(t, "metadata-collapse-reuse")) && (c.Collapsed == nil || c.Reused == nil) {
								t.Fatal("fresh fragmented controls omit root collapse and reuse")
							}
							if c.Collapsed != nil && c.Reused != nil {
								previous := destination
								for _, step := range []struct {
									name    string
									state   *hfsMetadataState
									archive hfsGrowthArchive
								}{
									{"collapsed", c.Collapsed, c.NativeCollapsed}, {"reused", c.Reused, c.NativeReused},
								} {
									t.Run(step.name, func(t *testing.T) {
										verifyDigest(t, directory, step.archive.Image, step.archive.SHA256)
										next := filepath.Join(output, step.name+"-"+format+".dmg")
										var changes []imageedit.Change
										if step.name == "collapsed" {
											for n := 0; n < 256; n++ {
												changes = append(changes, imageedit.Change{Operation: "rm", Path: "/Fixture/" + fmt.Sprintf("%05d-", n) + strings.Repeat("long-name-", 24)})
											}
										} else {
											attribute := make([]byte, 512)
											for n := range attribute {
												attribute[n] = byte(n)
											}
											changes = []imageedit.Change{{Operation: "cp", Path: "/Fixture/reused", Data: bytes.NewReader([]byte("Metadata growth contents\n"))}, {Operation: "xattr", Path: "/Fixture/reused", Attribute: "org.go-apfs.growth", Data: bytes.NewReader(attribute)}}
										}
										if _, err := imageedit.Apply(context.Background(), previous, next, imageedit.Options{Time: when, Format: format}, changes); err != nil {
											t.Fatal(step.name, err)
										}
										compareHFSEditedState(t, metadataReader(t, next, "hfs"), before, hfsMetadataFiles(t, directory, *step.state), when)
										previous = next
									})
								}
							}
						}
					})
				}
				digest := fileDigest(t, source)
				if hex.EncodeToString(digest[:]) != c.Source.UncompressedSHA256 {
					t.Fatal("native source altered")
				}
			})
		}
	}
	requireNativeVersions(t, majors)
}
