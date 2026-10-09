package acceptance_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

type fileObservation struct {
	Schema          int                    `json:"schema"`
	Root            string                 `json:"root"`
	Entries         []nativeFile           `json:"entries"`
	Lookups         []nativeLookup         `json:"lookups,omitempty"`
	FragmentedForks []nativeFragmentedFork `json:"fragmentedForks,omitempty"`
}
type nativeFile struct {
	Path                  string `json:"path"`
	Object                uint64 `json:"object"`
	Mode, UID, GID, Flags uint32
	BirthSeconds          int64                  `json:"birthSeconds"`
	ModifyNS              int64                  `json:"modifyNS"`
	ChangeNS              int64                  `json:"changeNS"`
	AccessNS              int64                  `json:"accessNS"`
	Size                  uint64                 `json:"size"`
	Links                 uint32                 `json:"links"`
	SHA256                string                 `json:"sha256"`
	Target                string                 `json:"target"`
	Attributes            map[string]nativeValue `json:"attributes"`
}
type nativeValue struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// TestNativeFileReading is the packaging/forensics reading contract: native
// names, identity, bytes, forks and logical metadata survive portable decoding.
// Native capture is a separate program and never uses this implementation.
func TestNativeFileReading(t *testing.T) {
	testFileCorpus(t, "file-reading", "APFS_NATIVE_FILES", "testdata/files", 100, nil)
}

func testFileCorpus(t *testing.T, scenario, environment, fallback string, minimum int, extra func(*testing.T, filesystem.Reader, fileObservation, string)) {
	t.Helper()
	root := os.Getenv(environment)
	if root == "" {
		root = fallback
	}
	paths, err := filepath.Glob(filepath.Join(root, "*", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "manifest.json")); err == nil {
		paths = append(paths, filepath.Join(root, "manifest.json"))
	}
	if len(paths) == 0 {
		t.Fatalf("no %s corpus at %s", scenario, root)
	}
	profiles := map[string]bool{}
	for _, manifest := range paths {
		t.Run(filepath.Base(filepath.Dir(manifest)), func(t *testing.T) {
			var c corpus
			decodeEvidence(t, manifest, &c)
			major := strings.Split(c.Producer.Version, ".")[0]
			if c.Schema != 1 || c.Scenario != scenario || c.Producer.System != "macOS" || c.Producer.Build == "" || c.Producer.Architecture == "" || (major != "15" && major != "26" && major != "27") || profiles[major] {
				t.Fatal("invalid or duplicate file corpus provenance")
			}
			profiles[major] = true
			dir := filepath.Dir(manifest)
			verifyDigest(t, dir, c.Producer.Source, c.Producer.SourceSHA256)
			wantIDs := map[string]bool{scenario + "/apfs": false, scenario + "/apfs-case-sensitive": false, scenario + "/hfsplus": false, scenario + "/hfsx": false}
			if len(c.Cases) != len(wantIDs) {
				t.Fatal("incomplete file-reading inventory")
			}
			for _, test := range c.Cases {
				seen, known := wantIDs[test.ID]
				if !known || seen {
					t.Fatal("unknown or duplicate file-reading case", test.ID)
				}
				wantIDs[test.ID] = true
				t.Run(test.ID, func(t *testing.T) {
					verifyDigest(t, dir, test.Image, test.SHA256)
					verifyDigest(t, dir, test.Observation, test.ObservationSHA256)
					verifyDigest(t, dir, test.Files, test.FilesSHA256)
					var want fileObservation
					decodeEvidence(t, filepath.Join(dir, test.Files), &want)
					if want.Schema != 1 || want.Root != "Fixture" || len(want.Entries) < minimum {
						t.Fatal("invalid or incomplete file observation")
					}
					img, err := diskimage.Open(filepath.Join(dir, test.Image))
					if err != nil {
						t.Fatal(err)
					}
					defer img.Close()
					r, err := inspect.Image(context.Background(), img)
					if err != nil {
						t.Fatal(err)
					}
					var reader filesystem.Reader
					count := 0
					for _, p := range r.Partitions {
						if p.APFS != nil {
							for i := range p.APFS.Volumes {
								reader = &p.APFS.Volumes[i]
								count++
							}
						}
						if p.HFSPlus != nil {
							reader = p.HFSPlus
							count++
						}
					}
					if count != 1 {
						t.Fatal("expected one native filesystem")
					}
					compareFiles(t, reader, want)
					if extra != nil {
						extra(t, reader, want, test.ID)
					}
					verifyDigest(t, dir, test.Image, test.SHA256)
					t.Logf("matched %d native objects, contents, forks, attributes and metadata from macOS %s; source unchanged", len(want.Entries), c.Producer.Version)
				})
			}
		})
	}
	if required := os.Getenv("APFS_REQUIRED_NATIVE_MAJORS"); required != "" {
		for _, major := range strings.Split(required, ",") {
			if !profiles[major] {
				t.Errorf("required %s producer macOS %s missing", scenario, major)
			}
		}
	}
}

func decodeEvidence(t *testing.T, path string, out any) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 4<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(out); err != nil {
		t.Fatal(err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		t.Fatal("expected exactly one evidence document")
	}
}

func compareFiles(t *testing.T, r filesystem.Reader, want fileObservation) {
	t.Helper()
	ctx := context.Background()
	paths := map[string]bool{}
	for _, expected := range want.Entries {
		if paths[expected.Path] || (expected.Path != want.Root && !strings.HasPrefix(expected.Path, want.Root+"/")) {
			t.Fatal("invalid or duplicate observed path", expected.Path)
		}
		paths[expected.Path] = true
		id, err := filesystem.LookupExact(ctx, r, expected.Path)
		if err != nil {
			t.Fatalf("%s lookup: %v", expected.Path, err)
		}
		n, err := r.Stat(ctx, id)
		if err != nil {
			t.Fatalf("%s stat: %v", expected.Path, err)
		}
		if n.Identity.Object != expected.Object {
			t.Fatalf("%s identity: got %d want %d", expected.Path, n.Identity.Object, expected.Object)
		}
		m := n.Metadata
		for _, field := range []struct {
			name string
			got  filesystem.Observation[uint32]
			want uint32
		}{{"mode", m.Mode, expected.Mode}, {"uid", m.UID, expected.UID}, {"gid", m.GID, expected.GID}, {"flags", m.BSDFlags, expected.Flags}} {
			if field.got.State != filesystem.Present || field.got.Value != field.want {
				t.Fatalf("%s %s: got %+v want %d", expected.Path, field.name, field.got, field.want)
			}
		}
		if m.BirthTime.State != filesystem.Present || m.BirthTime.Value.Unix() != expected.BirthSeconds || m.ModifyTime.State != filesystem.Present || m.ModifyTime.Value.UnixNano() != expected.ModifyNS || m.ChangeTime.State != filesystem.Present || m.ChangeTime.Value.UnixNano() != expected.ChangeNS || m.AccessTime.State != filesystem.Present || m.AccessTime.Value.UnixNano() != expected.AccessNS {
			t.Fatalf("%s timestamp mismatch: got %+v want birth=%d m=%d c=%d a=%d", expected.Path, m, expected.BirthSeconds, expected.ModifyNS, expected.ChangeNS, expected.AccessNS)
		}
		switch expected.Mode & 0170000 {
		case 0040000:
			var children, wantChildren []string
			err := r.ReadDir(ctx, id, func(e filesystem.DirEntry) error { children = append(children, e.Name); return nil })
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range want.Entries {
				if e.Path != expected.Path && path.Dir(e.Path) == expected.Path {
					wantChildren = append(wantChildren, path.Base(e.Path))
				}
			}
			sort.Strings(children)
			sort.Strings(wantChildren)
			if !reflect.DeepEqual(children, wantChildren) {
				t.Fatalf("%s children mismatch: got %v want %v", expected.Path, children, wantChildren)
			}
		case 0100000:
			value, err := r.OpenData(ctx, id)
			if err != nil {
				t.Fatalf("%s data: %v", expected.Path, err)
			}
			compareValue(t, expected.Path, value, nativeValue{int64(expected.Size), expected.SHA256})
		case 0120000:
			got, err := r.Readlink(ctx, id)
			if err != nil || got != expected.Target {
				t.Fatalf("%s link: got %q, %v want %q", expected.Path, got, err, expected.Target)
			}
		default:
			t.Fatal("unrecognized fixture object type")
		}
		if expected.Mode&0170000 != 0040000 && (n.Size != expected.Size || n.Links.State != filesystem.Present || n.Links.Value != expected.Links) {
			t.Fatalf("%s size or links: got %d/%+v want %d/%d", expected.Path, n.Size, n.Links, expected.Size, expected.Links)
		}
		listed := map[string]bool{}
		if err := r.ListAttributes(ctx, id, func(name string) error {
			if listed[name] {
				return fmt.Errorf("duplicate attribute %s", name)
			}
			listed[name] = true
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		// The engine can also enumerate filesystem-owned attributes which macOS
		// hides from listxattr. Every native-visible value must be present and exact.
		for name, value := range expected.Attributes {
			if !listed[name] {
				t.Fatalf("%s attribute %s missing", expected.Path, name)
			}
			got, err := r.OpenAttribute(ctx, id, name)
			if err != nil {
				t.Fatalf("%s attribute %s: %v", expected.Path, name, err)
			}
			compareValue(t, expected.Path+":"+name, got, value)
		}
	}
}

func compareValue(t *testing.T, label string, value filesystem.Value, want nativeValue) {
	t.Helper()
	defer value.Close()
	if value.Size() != want.Size {
		t.Fatalf("%s size: got %d want %d", label, value.Size(), want.Size)
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(value, 0, value.Size())); err != nil {
		t.Fatalf("%s read: %v", label, err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want.SHA256 {
		t.Fatalf("%s content digest: got %s want %s", label, got, want.SHA256)
	}
}
