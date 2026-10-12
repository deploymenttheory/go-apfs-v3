package acceptance_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

type nativeImageMetadataOperation struct {
	Op, Path, Attribute string
	Size                int64
	Finder              bool
	Flags, UID, GID     uint32
	ModifyNS, AccessNS  int64
	Object              uint64
	Seed                uint8
}
type nativeImageMetadataState struct {
	nativeEditState
	Operations  []nativeImageMetadataOperation
	ClockFields map[string][]string
}
type nativeImageMetadataManifest struct {
	nativeEditManifest
	Cases []struct {
		ID     string
		Source hfsGrowthArchive
		Before nativeEditState
		States map[string]nativeImageMetadataState
	}
	Producer struct {
		Sources                 map[string]string
		ReferenceManifestSHA256 string
	}
}

func imageMetadataChanges(ops []nativeImageMetadataOperation) []imageedit.Change {
	var changes []imageedit.Change
	for _, op := range ops {
		c := imageedit.Change{Operation: op.Op, Path: "/Fixture/" + op.Path, NoFollow: true, Attribute: op.Attribute}
		if op.Path == "." {
			c.Path = "/Fixture"
		}
		switch op.Op {
		case "xattr":
			var data []byte
			if op.Finder {
				data = append([]byte("TEXTttxt\x40"), make([]byte, 23)...)
			} else {
				unit := make([]byte, 256)
				for i := range unit {
					unit[i] = byte(i) + op.Seed
				}
				unit = append(unit, []byte("attribute bytes\x00\xff")...)
				data = bytes.Repeat(unit, (int(op.Size)+len(unit)-1)/len(unit))[:op.Size]
			}
			c.Data = bytes.NewReader(data)
		case "xattr-remove":
			c.Operation = "xattr"
			c.DeleteAttribute = true
		case "chown":
			c.Metadata = &filesystem.Metadata{UID: filesystem.Observed(op.UID), GID: filesystem.Observed(op.GID)}
		case "chflags":
			c.Flags = fmt.Sprintf("%o", op.Flags)
		case "touch":
			c.Metadata = &filesystem.Metadata{ModifyTime: filesystem.Observed(time.Unix(0, op.ModifyNS)), AccessTime: filesystem.Observed(time.Unix(0, op.AccessNS))}
		}
		changes = append(changes, c)
	}
	return changes
}

func metadataExpected(state nativeImageMetadataState, stamp int64) fileObservation {
	want := state.Files
	want.Entries = append([]nativeFile(nil), want.Entries...)
	for i := range want.Entries {
		e := &want.Entries[i]
		for _, field := range state.ClockFields[strconv.FormatUint(e.Object, 10)] {
			switch field {
			case "changeNS":
				e.ChangeNS = stamp * 1e9
			case "modifyNS":
				e.ModifyNS = stamp * 1e9
			}
		}
	}
	return want
}

func metadataReader(t *testing.T, path, kind string) filesystem.Reader {
	t.Helper()
	if kind == "apfs" {
		return &openAPFSEditVolume(t, path).Volumes[0]
	}
	image, err := diskimage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { image.Close() })
	part, err := image.Partition(0)
	if err != nil {
		t.Fatal(err)
	}
	v, err := hfsplus.Open(part)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
func compareMetadataState(t *testing.T, r filesystem.Reader, want fileObservation, kind string) {
	t.Helper()
	compareFiles(t, r, want)
	// Check all raw attributes including compression-owned values, not just
	// selected edited attributes. Symlink storage is internal to APFS.
	for _, entry := range want.Entries {
		names := map[string]bool{}
		if err := r.ListAttributes(context.Background(), entry.Object, func(name string) error { names[name] = true; return nil }); err != nil {
			t.Fatal(err)
		}
		delete(names, "com.apple.fs.symlink")
		for name, v := range entry.RawAttributes {
			if !names[name] {
				t.Fatal(entry.Path, "missing raw attribute", name)
			}
			value, err := r.OpenAttribute(context.Background(), entry.Object, name)
			if err != nil {
				t.Fatal(err)
			}
			compareValue(t, name, value, v)
			delete(names, name)
		}
		if len(names) != 0 {
			t.Fatal(entry.Path, "unexpected attributes", names)
		}
	}
}
func TestNativeAPFSImageMetadataEditing(t *testing.T) {
	testImageMetadata(t, "apfs", "APFS_NATIVE_APFS_METADATA", "APFS_APFS_METADATA_OUTPUT", "testdata/apfs-metadata-editing")
}
func TestNativeHFSImageMetadataEditing(t *testing.T) {
	t.Parallel()
	testImageMetadata(t, "hfs", "APFS_NATIVE_HFS_METADATA", "APFS_HFS_METADATA_OUTPUT", "testdata/hfs-metadata-editing")
}
func TestNativeHFSJournaledImageMetadataEditing(t *testing.T) {
	t.Parallel()
	testImageMetadata(t, "hfs", "APFS_NATIVE_HFS_JOURNALED_METADATA", "APFS_HFS_JOURNALED_METADATA_OUTPUT", "testdata/hfs-journaled-metadata-editing")
}

func imageMetadataCases(kind string) []string {
	if kind == "apfs" {
		return []string{"apfs", "apfs-case-sensitive"}
	}
	return []string{"hfsplus", "hfsx", "hfsplus-empty-attributes", "hfsx-empty-attributes"}
}

func testImageMetadata(t *testing.T, kind, rootEnv, outputEnv, retained string) {
	t.Helper()
	root := os.Getenv(rootEnv)
	if root == "" {
		root = retained
	}
	paths, err := filepath.Glob(filepath.Join(root, "macos-*", "manifest.json"))
	if err != nil || len(paths) == 0 {
		t.Fatal("required native metadata references absent", err)
	}
	majors := map[int]bool{}
	for _, path := range paths {
		var m nativeImageMetadataManifest
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if m.Schema != 1 || m.Contract != "existing-"+kind+"-metadata-edits" || len(m.Cases) != len(imageMetadataCases(kind)) || majors[m.Major] || len(m.Producer.Sources) < 12 {
			t.Fatal("metadata reference contract")
		}
		majors[m.Major] = true
		dir := filepath.Dir(path)
		verifyDigest(t, dir, "commands.json", m.CommandsSHA256)
		verifyDigest(t, dir, "reference-manifest.json", m.Producer.ReferenceManifestSHA256)
		for name, hash := range m.Producer.Sources {
			verifyDigest(t, dir, name, hash)
		}
		cases := map[string]bool{}
		for _, id := range imageMetadataCases(kind) {
			cases[id] = true
		}
		for _, c := range m.Cases {
			if !cases[c.ID] {
				t.Fatal("unexpected or duplicate metadata case", c.ID)
			}
			delete(cases, c.ID)
			if kind == "hfs" && (c.Before.Journal != nil) != strings.Contains(retained, "journaled") {
				t.Fatal("metadata journal profile mismatch")
			}
			t.Run(filepath.Base(dir)+"/"+c.ID, func(t *testing.T) {
				openArchive := openEditArchive
				if kind == "apfs" {
					openArchive = openAPFSEditArchive
				}
				source := openArchive(t, dir, c.Source)
				digest := fileDigest(t, source)
				compareMetadataState(t, metadataReader(t, source, kind), c.Before.Files, kind)
				output := os.Getenv(outputEnv)
				if output == "" {
					output = t.TempDir()
				}
				output = filepath.Join(output, filepath.Base(dir), c.ID)
				if err = os.MkdirAll(output, 0700); err != nil {
					t.Fatal(err)
				}
				when := time.Unix(m.ModificationSeconds, 0)
				for _, format := range []string{"UDRO", "UDZO"} {
					current := source
					for _, phase := range []string{"metadata", "metadata-final"} {
						state, ok := c.States[phase]
						if !ok || state.CheckerStatus != 0 || len(state.Operations) == 0 {
							t.Fatal("native state absent")
						}
						native := openArchive(t, dir, state.Archive)
						compareMetadataState(t, metadataReader(t, native, kind), state.Files, kind)
						destination := filepath.Join(output, phase+"-"+format+".dmg")
						changes := imageMetadataChanges(state.Operations)
						if _, err = imageedit.Apply(context.Background(), current, destination, imageedit.Options{Format: format, Time: when}, changes); err != nil {
							t.Fatal(phase, err)
						}
						repeat := filepath.Join(t.TempDir(), "repeat.dmg")
						if _, err = imageedit.Apply(context.Background(), current, repeat, imageedit.Options{Format: format, Time: when}, changes); err != nil {
							t.Fatal(err)
						}
						if fileDigest(t, destination) != fileDigest(t, repeat) {
							t.Fatal("nonreproducible metadata image")
						}
						compareMetadataState(t, metadataReader(t, destination, kind), metadataExpected(state, m.ModificationSeconds), kind)
						if kind == "hfs" && c.Before.Journal != nil {
							img, err := diskimage.Open(destination)
							if err != nil {
								t.Fatal(err)
							}
							part, err := img.Partition(0)
							if err != nil {
								t.Fatal(err)
							}
							verifyEditJournal(t, part, c.Before.Journal)
							img.Close()
						}
						current = destination
					}
				}
				for _, change := range []imageedit.Change{{Operation: "xattr", Path: "/Fixture/small", Attribute: "com.apple.decmpfs", Data: bytes.NewReader(nil)}, {Operation: "xattr", Path: "/Fixture/small", Attribute: "com.apple.FinderInfo", Data: bytes.NewReader(make([]byte, 31))}, {Operation: "xattr", Path: "/Fixture/small", Attribute: "org.go-apfs.missing", DeleteAttribute: true}, {Operation: "chown", Path: "/Fixture/small", Metadata: &filesystem.Metadata{UID: filesystem.Observed(^uint32(0))}}} {
					out := filepath.Join(t.TempDir(), "rejected.dmg")
					if _, err = imageedit.Apply(context.Background(), source, out, imageedit.Options{Time: when}, []imageedit.Change{change}); err == nil {
						t.Fatal("unsafe metadata operation admitted")
					}
					if _, err = os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
						t.Fatal("failed edit published output", err)
					}
				}
				if fileDigest(t, source) != digest {
					t.Fatal("metadata edits changed source")
				}
			})
		}
	}
	required := os.Getenv("APFS_REQUIRED_NATIVE_MAJORS")
	if required == "" {
		required = "15,26,27"
	}
	for _, s := range strings.Split(required, ",") {
		n, _ := strconv.Atoi(s)
		if !majors[n] {
			t.Fatal("required native version absent", n)
		}
	}
}

func TestNativeImageMetadataEditingContinuation(t *testing.T) {
	root := os.Getenv("APFS_IMAGE_METADATA_CONTINUATION")
	if root == "" {
		return
	}
	kind := os.Getenv("APFS_IMAGE_METADATA_KIND")
	if kind != "apfs" && kind != "hfs" {
		t.Fatal("explicit continuation filesystem required")
	}
	paths, err := filepath.Glob(filepath.Join(root, "*.raw"))
	expected := map[string]bool{}
	for _, major := range []int{15, 26, 27} {
		for _, id := range imageMetadataCases(kind) {
			expected[fmt.Sprintf("macos-%d-%s.raw", major, id)] = true
		}
	}
	if err != nil || len(paths) != len(expected) {
		t.Fatalf("complete native metadata continuation: got %d inputs, want %d: %v", len(paths), len(expected), err)
	}
	output := os.Getenv("APFS_IMAGE_METADATA_CONTINUED_OUTPUT")
	if err = os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	for _, source := range paths {
		if !expected[filepath.Base(source)] {
			t.Fatal("unexpected native continuation source", filepath.Base(source))
		}
		delete(expected, filepath.Base(source))
		var control struct {
			Before   fileObservation
			Expected nativeImageMetadataState
		}
		b, err := os.ReadFile(strings.TrimSuffix(source, ".raw") + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(b, &control); err != nil {
			t.Fatal(err)
		}
		digest := fileDigest(t, source)
		compareMetadataState(t, metadataReader(t, source, kind), control.Before, kind)
		destination := filepath.Join(output, strings.TrimSuffix(filepath.Base(source), ".raw")+".dmg")
		if _, err = imageedit.Apply(context.Background(), source, destination, imageedit.Options{Time: time.Unix(1749283750, 0)}, imageMetadataChanges(control.Expected.Operations)); err != nil {
			t.Fatal(err)
		}
		compareMetadataState(t, metadataReader(t, destination, kind), metadataExpected(control.Expected, 1749283750), kind)
		if fileDigest(t, source) != digest {
			t.Fatal("continued edits changed native source")
		}
	}
}
