package acceptance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

type linkPattern int64

func (p linkPattern) Size() int64 { return int64(p) }
func (p linkPattern) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 {
		return 0, fs.ErrInvalid
	}
	if len(b) == 0 {
		return 0, nil
	}
	if off >= int64(p) {
		return 0, io.EOF
	}
	unit := make([]byte, 256)
	for i := range unit {
		unit[i] = byte(i)
	}
	unit = append(unit, []byte("link lifetime\x00\xff")...)
	want := len(b)
	n := min(int64(len(b)), int64(p)-off)
	for i := range n {
		b[i] = unit[(off+i)%int64(len(unit))]
	}
	if n < int64(want) {
		return int(n), io.EOF
	}
	return int(n), nil
}

func imageLinkChanges(ops []nativeImageMetadataOperation) []imageedit.Change {
	changes := make([]imageedit.Change, 0, len(ops))
	for _, op := range ops {
		c := imageedit.Change{Operation: op.Op, Path: "/Fixture/" + op.Path, Force: op.Force, Symbolic: op.Symbolic, NoFollow: op.NoFollow || op.Force}
		if op.Destination != "" {
			c.Destination = "/Fixture/" + op.Destination
		}
		if op.Symbolic {
			c.Path = op.Path
		}
		switch op.Op {
		case "write":
			c.Operation = "cp"
			c.Data = linkPattern(op.Size)
		case "xattr":
			c.Attribute, c.Data, c.NoFollow = op.Attribute, linkPattern(op.Size), true
		case "chmod":
			c.Mode = strconv.FormatUint(uint64(op.Mode), 8)
		}
		changes = append(changes, c)
	}
	return changes
}

// Native and portable allocation histories differ for new objects. Preserve
// every original inode and a bijection of all identities across the entire
// lifecycle, including objects no longer reachable after later removals.
type linkIdentities struct{ nativeToGo, goToNative map[uint64]uint64 }

func imageLinkCases(kind string) []string {
	if kind == "apfs" {
		return []string{"apfs", "apfs-case-sensitive"}
	}
	return []string{"hfsplus", "hfsx"}
}

func newLinkIdentities(before fileObservation) *linkIdentities {
	ids := &linkIdentities{map[uint64]uint64{}, map[uint64]uint64{}}
	for _, e := range before.Entries {
		ids.nativeToGo[e.Object], ids.goToNative[e.Object] = e.Object, e.Object
	}
	return ids
}
func (ids *linkIdentities) compare(t *testing.T, r filesystem.Reader, want fileObservation, kind string) {
	t.Helper()
	want.Entries = append([]nativeFile(nil), want.Entries...)
	for i := range want.Entries {
		e := &want.Entries[i]
		id, err := filesystem.LookupExact(context.Background(), r, e.Path)
		if err != nil {
			t.Fatal(e.Path, err)
		}
		if old, ok := ids.nativeToGo[e.Object]; ok && id != old {
			t.Fatal("inode identity or alias relationship changed", e.Path, id, old)
		}
		if old, ok := ids.goToNative[id]; ok && e.Object != old {
			t.Fatal("distinct or retired native identities conflated", e.Path, e.Object, old)
		}
		ids.nativeToGo[e.Object], ids.goToNative[id] = id, e.Object
		e.Object = id
	}
	compareMetadataState(t, r, want, kind)
}

func TestNativeAPFSImageLinkEditing(t *testing.T) {
	testImageLinks(t, "apfs", "APFS_NATIVE_APFS_LINKS", "APFS_APFS_LINK_OUTPUT", "testdata/apfs-link-editing")
}
func TestNativeHFSImageLinkEditing(t *testing.T) {
	testImageLinks(t, "hfs", "APFS_NATIVE_HFS_LINKS", "APFS_HFS_LINK_OUTPUT", "testdata/hfs-link-editing")
}
func TestNativeHFSJournaledImageLinkEditing(t *testing.T) {
	testImageLinks(t, "hfs", "APFS_NATIVE_HFS_JOURNALED_LINKS", "APFS_HFS_JOURNALED_LINK_OUTPUT", "testdata/hfs-journaled-link-editing")
}
func testImageLinks(t *testing.T, kind, rootEnv, outputEnv, retained string) {
	t.Helper()
	root := os.Getenv(rootEnv)
	if root == "" {
		root = retained
	}
	paths, err := filepath.Glob(filepath.Join(root, "macos-*", "manifest.json"))
	if err != nil || len(paths) == 0 {
		t.Fatal("native link evidence absent", err)
	}
	majors := map[int]bool{}
	for _, manifestPath := range paths {
		var m nativeImageMetadataManifest
		b, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(b, &m); err != nil {
			t.Fatal(err)
		}
		if m.Schema != 1 || m.Contract != "existing-"+kind+"-link-edits" || len(m.Cases) != 2 || majors[m.Major] || len(m.Producer.Sources) < 12 {
			t.Fatal("native link inventory")
		}
		majors[m.Major] = true
		dir := filepath.Dir(manifestPath)
		verifyDigest(t, dir, "commands.json", m.CommandsSHA256)
		verifyDigest(t, dir, "reference-manifest.json", m.Producer.ReferenceManifestSHA256)
		for name, hash := range m.Producer.Sources {
			verifyDigest(t, dir, name, hash)
		}
		cases := map[string]bool{}
		for _, id := range imageLinkCases(kind) {
			cases[id] = true
		}
		for _, c := range m.Cases {
			if !cases[c.ID] {
				t.Fatal("unexpected or duplicate native link case", c.ID)
			}
			delete(cases, c.ID)
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
				for _, phase := range []string{"links", "links-final", "removed"} {
					state, ok := c.States[phase]
					if !ok || state.CheckerStatus != 0 || len(state.Operations) == 0 {
						t.Fatal("complete native link phase required")
					}
					native := openArchive(t, dir, state.Archive)
					compareMetadataState(t, metadataReader(t, native, kind), state.Files, kind)
				}
				for _, format := range []string{"UDRO", "UDZO"} {
					current, ids := source, newLinkIdentities(c.Before.Files)
					for _, phase := range []string{"links", "links-final", "removed"} {
						state, ok := c.States[phase]
						if !ok || state.CheckerStatus != 0 || len(state.Operations) == 0 {
							t.Fatal("complete native link phase required")
						}
						changes := imageLinkChanges(state.Operations)
						destination := filepath.Join(output, phase+"-"+format+".dmg")
						if _, err = imageedit.Apply(context.Background(), current, destination, imageedit.Options{Format: format, Time: when}, changes); err != nil {
							t.Fatal(phase, err)
						}
						repeat := filepath.Join(t.TempDir(), "repeat.dmg")
						if _, err = imageedit.Apply(context.Background(), current, repeat, imageedit.Options{Format: format, Time: when}, changes); err != nil {
							t.Fatal(err)
						}
						if fileDigest(t, repeat) != fileDigest(t, destination) {
							t.Fatal("nonreproducible link edits")
						}
						ids.compare(t, metadataReader(t, destination, kind), metadataExpected(state, m.ModificationSeconds), kind)
						if c.Before.Journal != nil {
							image, err := diskimage.Open(destination)
							if err != nil {
								t.Fatal(err)
							}
							part, err := image.Partition(0)
							if err != nil {
								t.Fatal(err)
							}
							verifyEditJournal(t, part, c.Before.Journal)
							image.Close()
						}
						current = destination
					}
				}
				for _, change := range []imageedit.Change{
					{Operation: "ln", Path: "/Fixture", Destination: "/Fixture/not-a-file"},
					{Operation: "ln", Path: "/Fixture/symlink", Destination: "/Fixture/not-a-link"},
					{Operation: "ln", Path: "/Fixture/independent", Destination: "/Fixture/empty"},
					{Operation: "ln", Path: "/Fixture/independent", Destination: "/Fixture/independent", Force: true},
					{Operation: "ln", Path: "missing", Symbolic: true, Destination: "/Fixture/symlink/unsafe"},
					{Operation: "ln", Path: strings.Repeat("x", 1024), Symbolic: true, Destination: "/Fixture/too-long"},
				} {
					out := filepath.Join(t.TempDir(), "rejected.dmg")
					if _, err = imageedit.Apply(context.Background(), source, out, imageedit.Options{Time: when}, []imageedit.Change{change}); err == nil {
						t.Fatal("unsafe link admitted", fmt.Sprintf("%+v", change))
					}
					if _, err = os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
						t.Fatal("failed link published output", err)
					}
				}
				if fileDigest(t, source) != digest {
					t.Fatal("link edits changed original source")
				}
			})
		}
	}
	required := os.Getenv("APFS_REQUIRED_NATIVE_MAJORS")
	if required == "" {
		required = "15,26,27"
	}
	for _, s := range strings.Split(required, ",") {
		major, err := strconv.Atoi(s)
		if err != nil || !majors[major] {
			t.Fatal("required native link version absent", s)
		}
	}
}

func TestNativeImageLinkEditingContinuation(t *testing.T) {
	root := os.Getenv("APFS_IMAGE_LINK_CONTINUATION")
	if root == "" {
		t.Skip("native continuation inputs are supplied by the required image-edit pipelines")
	}
	kind := os.Getenv("APFS_IMAGE_LINK_KIND")
	if kind != "apfs" && kind != "hfs" {
		t.Fatal("explicit continuation filesystem required")
	}
	paths, err := filepath.Glob(filepath.Join(root, "*.raw"))
	expected := map[string]bool{}
	for _, major := range []int{15, 26, 27} {
		for _, id := range imageLinkCases(kind) {
			expected[fmt.Sprintf("macos-%d-%s.raw", major, id)] = true
		}
	}
	if err != nil || len(paths) != len(expected) {
		t.Fatalf("complete link continuations: got %d inputs, want %d: %v", len(paths), len(expected), err)
	}
	output := os.Getenv("APFS_IMAGE_LINK_CONTINUED_OUTPUT")
	if output == "" {
		t.Fatal("continued image output required")
	}
	if err = os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	for _, source := range paths {
		if !expected[filepath.Base(source)] {
			t.Fatal("unexpected continuation source", source)
		}
		delete(expected, filepath.Base(source))
		t.Run(filepath.Base(source), func(t *testing.T) {
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
			out := filepath.Join(output, strings.TrimSuffix(filepath.Base(source), ".raw")+".dmg")
			if _, err = imageedit.Apply(context.Background(), source, out, imageedit.Options{Time: time.Unix(1749283750, 0)}, imageLinkChanges(control.Expected.Operations)); err != nil {
				t.Fatal(err)
			}
			newLinkIdentities(control.Before).compare(t, metadataReader(t, out, kind), metadataExpected(control.Expected, 1749283750), kind)
			if fileDigest(t, source) != digest {
				t.Fatal("continued edits changed native source")
			}
		})
	}
}
