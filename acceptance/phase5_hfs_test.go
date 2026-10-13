package acceptance_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

type phase5HFSState struct {
	Files         fileObservation
	FileArchive   hfsGrowthArchive
	Headers       json.RawMessage
	CheckerStatus int
	Journal       json.RawMessage
}

type phase5HFSCase struct {
	ID, Operation                            string
	Source, NativeAfter                      hfsGrowthArchive
	Before, After                            phase5HFSState
	Sensitive, Journaled, Growth, Fragmented bool
	GrowthFiles                              int
}

type phase5HFSManifest struct {
	Schema, Major            int
	Contract, CommandsSHA256 string
	Producer                 struct {
		System, Build, Architecture, Revision, Run string
		Sources                                    map[string]string
		Formatter                                  struct {
			HFSRevision, LibutilRevision, BinarySHA256, SDKVersion string
			Files                                                  []struct{ Path, SHA256 string }
		}
	}
	Cases []phase5HFSCase
}

func phase5HFSFiles(t *testing.T, directory string, state phase5HFSState) fileObservation {
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

func verifyPhase5Source(t *testing.T, directory, name, digest string) {
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

func phase5HFSChanges(c phase5HFSCase) []imageedit.Change {
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

func comparePhase5HFS(t *testing.T, reader filesystem.Reader, before, expected fileObservation, when time.Time) {
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

func TestNativePhase5HFS(t *testing.T) {
	testPhase5HFS(t, "APFS_NATIVE_PHASE5_HFS", "testdata/phase5-hfs", "phase5-hfs-allocation", 6)
}

func TestNativePhase5HFSFragmented(t *testing.T) {
	testPhase5HFS(t, "APFS_NATIVE_PHASE5_HFS_FRAGMENTED", "testdata/phase5-hfs-fragmented", "phase5-hfs-fragmented", 2)
}

func testPhase5HFS(t *testing.T, environment, retained, contract string, count int) {
	root := os.Getenv(environment)
	if root == "" {
		root = retained
	}
	paths, err := filepath.Glob(filepath.Join(root, "macos-*", "manifest.json"))
	if err != nil || len(paths) == 0 {
		t.Fatal("native HFS completion references absent", err)
	}
	majors := map[int]bool{}
	for _, name := range paths {
		var manifest phase5HFSManifest
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
		verifyDigest(t, directory, "commands.json", manifest.CommandsSHA256)
		for source, hash := range manifest.Producer.Sources {
			verifyPhase5Source(t, directory, source, hash)
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
				source := openPhase5Archive(t, directory, c.Source)
				before, want := phase5HFSFiles(t, directory, c.Before), phase5HFSFiles(t, directory, c.After)
				outputVariable := "APFS_PHASE5_HFS_OUTPUT"
				if c.Fragmented {
					outputVariable = "APFS_PHASE5_HFS_FRAGMENTED_OUTPUT"
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
					destination := filepath.Join(output, "edited-"+format+".dmg")
					_, err := imageedit.Edit(context.Background(), source, destination, imageedit.Options{Time: when, Format: format}, func(editor *imageedit.Editor) error { _, err := editor.Apply(phase5HFSChanges(c)); return err })
					if err != nil {
						t.Fatal(err)
					}
					comparePhase5HFS(t, metadataReader(t, destination, "hfs"), before, want, when)
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
