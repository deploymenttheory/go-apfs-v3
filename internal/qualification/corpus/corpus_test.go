package corpus

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func sum(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }

func store(t *testing.T, root, name string, data []byte) {
	t.Helper()
	name = filepath.Join(root, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(name), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func fixture(t *testing.T, compressed bool) (string, Catalog, []Definition) {
	t.Helper()
	repo := t.TempDir()
	manifest := []byte(`{"schema":1,"scenario":"native-reference","producer":{"system":"macOS","version":"27.0.1","build":"native-build","architecture":"arm64","sourceSHA256":"original-collector-identity"},"cases":[{"id":"native-apfs","nativeVerdict":"independent"}]}`)
	name := "manifest.json"
	if compressed {
		var b bytes.Buffer
		z := gzip.NewWriter(&b)
		if _, err := z.Write(manifest); err != nil {
			t.Fatal(err)
		}
		if err := z.Close(); err != nil {
			t.Fatal(err)
		}
		manifest = b.Bytes()
		name += ".gz"
	}
	store(t, repo, "fixtures/native/"+name, manifest)
	store(t, repo, "fixtures/native/images/source.dmg", []byte("independent native disk bytes\x00\xff"))
	defs := []Definition{{ID: "native", Path: "fixtures/native", Bindings: []Binding{{Family: "file-reading", CaptureClass: "apple-independent"}}, Manifests: []ManifestReference{{Path: name, SHA256: sum(manifest), Cases: []string{"cases/native-apfs"}}}}}
	catalog, err := Build(context.Background(), repo, defs)
	if err != nil {
		t.Fatal(err)
	}
	return repo, catalog, defs
}

func resolve(t *testing.T, catalog Catalog, options Options) *Resolved {
	t.Helper()
	r, err := New(catalog, options)
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.Resolve(context.Background(), "native")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := result.Close(); err != nil {
			t.Error(err)
		}
	})
	return result
}

func TestCommittedAndBundleInputsPreserveIdenticalEvidence(t *testing.T) {
	for _, compressed := range []bool{false, true} {
		t.Run(map[bool]string{false: "original-manifest", true: "retained-gzip-manifest"}[compressed], func(t *testing.T) {
			repo, catalog, defs := fixture(t, compressed)
			if err := MatchRetainedDefinitions(catalog, defs); err != nil {
				t.Fatal(err)
			}
			original := resolve(t, catalog, Options{Repository: repo})
			bundles := t.TempDir()
			bundle, err := WriteBundle(context.Background(), original, bundles)
			if err != nil {
				t.Fatal(err)
			}
			again, err := WriteBundle(context.Background(), original, bundles)
			if err != nil || bundle != again {
				t.Fatal("non-reproducible/replaced bundle", again, err)
			}
			before := catalog.Entries[0].TreeSHA256
			catalog.Entries[0].Location = Location{Kind: "bundle", Bundle: &bundle}
			if err := catalog.Validate(); err != nil {
				t.Fatal(err)
			}
			if catalog.Entries[0].TreeSHA256 != before {
				t.Fatal("transport changed input identity")
			}
			scratch := t.TempDir()
			archived := resolve(t, catalog, Options{Bundles: bundles, Scratch: scratch})
			if archived.TreeSHA256() != original.TreeSHA256() {
				t.Fatal("different admitted inputs")
			}
			for _, file := range catalog.Entries[0].Files {
				a, err := os.ReadFile(filepath.Join(original.Path(), filepath.FromSlash(file.Path)))
				if err != nil {
					t.Fatal(err)
				}
				b, err := os.ReadFile(filepath.Join(archived.Path(), filepath.FromSlash(file.Path)))
				if err != nil || !bytes.Equal(a, b) {
					t.Fatal("changed original retained bytes", file.Path, err)
				}
			}
			if err := archived.Verify(context.Background()); err != nil {
				t.Fatal(err)
			}
			directory := archived.Path()
			if err := archived.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(directory); !os.IsNotExist(err) {
				t.Fatal("managed scratch survived Close", err)
			}
			if err := original.Close(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(original.Path()); err != nil {
				t.Fatal("Close changed committed corpus", err)
			}
		})
	}
}

func TestCommittedEvidenceRejectsMissingChangedAndUnexpectedInputs(t *testing.T) {
	for _, kind := range []string{"missing", "changed", "unexpected", "missing-provenance", "wrong-original-digest", "wrong-producer", "wrong-case"} {
		t.Run(kind, func(t *testing.T) {
			repo, catalog, _ := fixture(t, false)
			switch kind {
			case "missing":
				if err := os.Remove(filepath.Join(repo, "fixtures/native/images/source.dmg")); err != nil {
					t.Fatal(err)
				}
			case "changed":
				store(t, repo, "fixtures/native/images/source.dmg", []byte("changed"))
			case "unexpected":
				store(t, repo, "fixtures/native/extra", []byte("extra"))
			case "missing-provenance":
				catalog.Entries[0].Captures = nil
			case "wrong-original-digest":
				catalog.Entries[0].Captures[0].OriginalSHA256 = strings.Repeat("0", 64)
			case "wrong-producer":
				catalog.Entries[0].Captures[0].Producer.Build = "different"
			case "wrong-case":
				catalog.Entries[0].Captures[0].Cases = []string{"other-case"}
			}
			catalog.Entries[0].TreeSHA256, _ = catalog.Entries[0].Identity()
			r, err := New(catalog, Options{Repository: repo})
			if err == nil {
				_, err = r.Resolve(context.Background(), "native")
			}
			if err == nil {
				t.Fatal("admitted altered native evidence")
			}
		})
	}
}

type member struct {
	name string
	kind byte
	link string
	body []byte
	size int64
	pax  map[string]string
}

func makeArchive(t *testing.T, members []member, padding []byte) []byte {
	t.Helper()
	var raw bytes.Buffer
	archive := tar.NewWriter(&raw)
	for _, m := range members {
		size := int64(len(m.body))
		if m.size != 0 {
			size = m.size
		}
		if m.kind == 0 {
			m.kind = tar.TypeReg
		}
		if err := archive.WriteHeader(&tar.Header{Name: m.name, Typeflag: m.kind, Linkname: m.link, Size: size, Mode: 0600, PAXRecords: m.pax, Format: tar.FormatPAX}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(m.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	raw.Write(padding)
	var stored bytes.Buffer
	z := gzip.NewWriter(&stored)
	if _, err := z.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return stored.Bytes()
}

func TestArchiveAdmissionRejectsUnsafeIncompleteAndCorruptBundles(t *testing.T) {
	for _, kind := range []string{"parent", "absolute", "drive", "backslash", "ads", "device", "trailing-dot", "duplicate", "case-alias", "symlink", "hardlink", "fifo", "unknown-directory", "unknown-pax", "wrong-size", "missing", "changed-member", "wrong-bundle-digest", "wrong-bundle-size", "truncated-gzip", "extra-gzip", "trailing-bytes", "trailing-tar", "excessive-padding"} {
		t.Run(kind, func(t *testing.T) {
			repo, catalog, _ := fixture(t, false)
			entry := &catalog.Entries[0]
			var members []member
			for _, f := range entry.Files {
				body, err := os.ReadFile(filepath.Join(repo, "fixtures/native", filepath.FromSlash(f.Path)))
				if err != nil {
					t.Fatal(err)
				}
				members = append(members, member{name: f.Path, body: body})
			}
			var padding []byte
			switch kind {
			case "parent":
				members[0].name = "../escape"
			case "absolute":
				members[0].name = "/escape"
			case "drive":
				members[0].name = "C:/escape"
			case "backslash":
				members[0].name = `..\escape`
			case "ads":
				members[0].name = "image:stream"
			case "device":
				members[0].name = "NUL.txt"
			case "trailing-dot":
				members[0].name = "image."
			case "duplicate":
				members = append(members, members[0])
			case "case-alias":
				alias := members[0]
				alias.name = strings.ToUpper(alias.name)
				members = append(members, alias)
			case "symlink":
				members[0] = member{name: members[0].name, kind: tar.TypeSymlink, link: "/outside"}
			case "hardlink":
				members[0] = member{name: members[0].name, kind: tar.TypeLink, link: members[1].name}
			case "fifo":
				members[0] = member{name: members[0].name, kind: tar.TypeFifo}
			case "unknown-directory":
				members = append(members, member{name: "unapproved/", kind: tar.TypeDir})
			case "unknown-pax":
				members[0].pax = map[string]string{"SCHILY.xattr.original": "unsafe"}
			case "wrong-size":
				members[0].body = append(members[0].body, 0)
			case "missing":
				members = members[:1]
			case "changed-member":
				members[0].body[0] ^= 1
			case "trailing-tar":
				padding = []byte("hidden archive")
			case "excessive-padding":
				padding = make([]byte, 2<<20)
			}
			data := makeArchive(t, members, padding)
			switch kind {
			case "truncated-gzip":
				data = data[:len(data)-4]
			case "extra-gzip":
				data = append(data, data...)
			case "trailing-bytes":
				data = append(data, 1, 2, 3)
			}
			bundle := Bundle{SHA256: sum(data), Bytes: int64(len(data))}
			if kind == "wrong-bundle-digest" {
				bundle.SHA256 = strings.Repeat("0", 64)
			}
			if kind == "wrong-bundle-size" {
				bundle.Bytes++
			}
			entry.Location = Location{Kind: "bundle", Bundle: &bundle}
			bundles, scratch := t.TempDir(), t.TempDir()
			store(t, bundles, bundle.Filename(), data)
			r, err := New(catalog, Options{Repository: repo, Bundles: bundles, Scratch: scratch})
			if err != nil {
				t.Fatal(err)
			}
			result, err := r.Resolve(context.Background(), "native")
			if err == nil {
				_ = result.Close()
				t.Fatal("admitted unsafe bundle")
			}
			remaining, err := os.ReadDir(scratch)
			if err != nil || len(remaining) != 0 {
				t.Fatal("failed extraction left scratch", remaining, err)
			}
		})
	}
}

func TestAdmissionNeverFallsBackOrInheritsMutableMetadata(t *testing.T) {
	repo, catalog, defs := fixture(t, false)
	r, err := New(catalog, Options{Repository: repo})
	if err != nil {
		t.Fatal(err)
	}
	catalog.Entries[0].Files[0].SHA256 = strings.Repeat("0", 64)
	resolved, err := r.Resolve(context.Background(), "native")
	if err != nil {
		t.Fatal("caller mutated admitted metadata", err)
	}
	if err := resolved.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Resolve(context.Background(), "absent"); err == nil {
		t.Fatal("admitted absent catalog ID")
	}
	_, catalog, _ = fixture(t, false)
	catalog.Entries[0].Location = Location{Kind: "bundle", Bundle: &Bundle{SHA256: strings.Repeat("0", 64), Bytes: 10}}
	r, err = New(catalog, Options{Repository: repo, Bundles: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.Resolve(context.Background(), "native"); err == nil {
		t.Fatal("missing bundle fell back to committed files")
	}
	if err = MatchRetainedDefinitions(catalog, nil); err == nil {
		t.Fatal("lost registry corpus admitted")
	}
	catalog.Entries[0].Bindings[0].CaptureClass = "current-go-experiment"
	catalog.Entries[0].TreeSHA256, _ = catalog.Entries[0].Identity()
	if err = MatchRetainedDefinitions(catalog, defs); err == nil {
		t.Fatal("changed dependency classification admitted")
	}
}

func TestMutationCancellationAndOutputIsolation(t *testing.T) {
	repo, catalog, _ := fixture(t, false)
	input := resolve(t, catalog, Options{Repository: repo})
	if _, err := WriteBundle(context.Background(), input, input.Path()); err == nil {
		t.Fatal("bundle wrote inside immutable corpus")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := WriteBundle(ctx, input, t.TempDir()); err == nil {
		t.Fatal("cancelled construction passed")
	}
	store(t, repo, "fixtures/native/images/source.dmg", []byte("later mutation"))
	if err := input.Verify(context.Background()); err == nil {
		t.Fatal("post-replay source mutation ignored")
	}
	if _, err := WriteBundle(context.Background(), input, t.TempDir()); err == nil {
		t.Fatal("changed source was published")
	}
}

func TestCatalogParserRejectsAmbiguityAndUnboundedContracts(t *testing.T) {
	_, catalog, _ := fixture(t, false)
	data, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{[]byte(`{"schema":1,"schema":1,"entries":[]}`), append(bytes.Clone(data), []byte(` {}`)...), bytes.Replace(data, []byte(`"schema":1`), []byte(`"schema":1,"unknown":true`), 1), bytes.Repeat([]byte(" "), MaxCatalogBytes+1)} {
		if _, err := Read(bytes.NewReader(bad)); err == nil {
			t.Fatal("ambiguous/oversized catalog admitted")
		}
	}
	catalog.Entries[0].Files[0].Bytes = MaxTreeBytes + 1
	if err := catalog.Validate(); err == nil {
		t.Fatal("unbounded member admitted")
	}
	for _, bad := range []string{"../x", "/x", `C:\x`, `x\y`, "x:stream", "x.", "x ", "AUX.dat", "foo/../bar", "foo//bar", "x?y"} {
		if PortablePath(bad) {
			t.Fatal("unsafe portable path admitted", bad)
		}
	}
}

func TestCatalogRejectsPortableDirectoryAliasesAndUnregisteredManifests(t *testing.T) {
	for _, kind := range []string{"directory-case-alias", "file-directory", "unregistered-manifest"} {
		t.Run(kind, func(t *testing.T) {
			_, catalog, _ := fixture(t, false)
			entry := &catalog.Entries[0]
			name := "Images/other"
			if kind == "file-directory" {
				name = "images"
			}
			if kind == "unregistered-manifest" {
				name = "other/manifest.json"
			}
			entry.Files = append(entry.Files, File{Path: name, SHA256: sum(nil)})
			slices.SortFunc(entry.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
			entry.TreeSHA256, _ = entry.Identity()
			if err := catalog.Validate(); err == nil {
				t.Fatal("ambiguous/incomplete file tree admitted")
			}
		})
	}
}
