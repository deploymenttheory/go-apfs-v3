package acceptance_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

// TestRecursiveHostImportsPreserveNativeLogicalTrees qualifies the portable
// host-import boundary, using ordinary host files whose names, bytes, aliases,
// links and directory structure come from a retained Apple observation. Host
// metadata stays a host observation, with explicit platform defaults. This test
// does not turn missing host ACLs/xattrs into restored native metadata, or emit
// images whose truthful host-import provenance would differ across producers.
func TestRecursiveHostImportsPreserveNativeLogicalTrees(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipes := recipesByName(t)
	seen := map[string]bool{}
	for _, k := range cases {
		if k.Recipe != "workspace-edits" || k.Stage != "before" {
			continue
		}
		key := fmt.Sprintf("macos-%d/%s", k.Producer, k.Profile)
		if seen[key] {
			t.Fatal("ambiguous native host-import source", key)
		}
		seen[key] = true
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			img, source, closeSource := openSingleVolume(t, ctx, k, recipes[k.Recipe])
			defer closeSource()
			checkSource := func() {
				t.Helper()
				if got, n := hashReaderAt(img, img.Size()); got != k.Observation.Image.DiskSHA256 || n != k.Observation.Image.DiskBytes {
					t.Fatal("native source changed while supplying host input", got, n)
				}
			}
			checkSource()
			defer checkSource()
			entries := nativeHostImportEntries(t, k.Observation.Views[0])
			host := filepath.Join(t.TempDir(), "host-tree")
			materializeNativeHostTree(t, ctx, host, source, entries)
			for _, preserveLinks := range []bool{false, true} {
				t.Run(fmt.Sprintf("preserve-links-%t", preserveLinks), func(t *testing.T) {
					// Reading host contents may update atime; snapshot its public
					// observations immediately before each import.
					observed := observeHostImportTree(t, host, entries)
					dir := filepath.Join(t.TempDir(), "session")
					current, err := session.Create(ctx, dir, session.Options{Names: source.NameRules(), UID: hostImportUID, GID: hostImportGID, Time: &fixedClock})
					if err != nil {
						t.Fatal(err)
					}
					report, err := current.Copy(ctx, []string{host + string(filepath.Separator)}, "/", session.CopyOptions{FromHost: true, Archive: true, PreserveLinks: preserveLinks})
					if err != nil {
						closeFixture(t, current)
						t.Fatal(err)
					}
					checkImportedHostTree(t, ctx, current, entries, observed, preserveLinks)
					checkHostImportReport(t, report, current, len(observed), preserveLinks)
					if err := current.Verify(ctx); err != nil {
						t.Fatal(err)
					}
					if err := current.Close(); err != nil {
						t.Fatal(err)
					}
					current, err = session.Open(ctx, dir)
					if err != nil {
						t.Fatal(err)
					}
					defer func() { closeFixture(t, current) }()
					checkImportedHostTree(t, ctx, current, entries, observed, preserveLinks)
					checkHostInputUnchanged(t, host, entries, observed)
				})
			}
			t.Run("nonrecursive-refusal", func(t *testing.T) {
				current, err := session.Create(ctx, filepath.Join(t.TempDir(), "session"), session.Options{Names: source.NameRules(), UID: hostImportUID, GID: hostImportGID, Time: &fixedClock})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { closeFixture(t, current) }()
				before := current.Report().Revision
				if _, err := current.Copy(ctx, []string{host}, "/tree", session.CopyOptions{FromHost: true, PreserveLinks: true}); !errors.Is(err, fs.ErrInvalid) {
					t.Fatalf("nonrecursive directory import: %v", err)
				}
				if current.Report().Revision != before {
					t.Fatal("rejected host import published a revision")
				}
				if err := current.ReadDir(ctx, current.Root(), func(e filesystem.DirEntry) error { return fmt.Errorf("refused import published %s", e.Name) }); err != nil {
					t.Error(err)
				}
				if err := current.Verify(ctx); err != nil {
					t.Fatal(err)
				}
			})
		})
	}
	for _, producer := range []int{15, 26, 27} {
		for _, profile := range recipes["workspace-edits"].Profiles {
			if !seen[fmt.Sprintf("macos-%d/%s", producer, profile)] {
				t.Errorf("missing recursive host-import control for macOS %d/%s", producer, profile)
			}
		}
	}
}

const hostImportUID, hostImportGID = 60001, 60002

func nativeHostImportEntries(t *testing.T, view schema.View) []schema.Entry {
	t.Helper()
	// These complete native child subtrees contain no captured ACLs, forks,
	// attributes or compressed storage to invent on a foreign host. The excluded
	// ordinary/alias and compressed/compressed-alias objects retain that evidence
	// in their existing preservation consumers.
	roots := []string{"CaseName", "Contents", "destination", "destination-alias", "directory-link", "empty-dir", "empty-target", "move-dir", "obsolete", "remove-dir", "untouched"}
	var entries []schema.Entry
	seen := map[string]bool{}
	for _, e := range view.Entries {
		if !strings.HasPrefix(e.Path, "Fixture/tree/") {
			continue
		}
		rel := strings.TrimPrefix(e.Path, "Fixture/tree/")
		root, _, _ := strings.Cut(rel, "/")
		if !slices.Contains(roots, root) {
			continue
		}
		if len(e.Xattrs) != 0 || e.ACL != "" || e.Compression != nil || e.Flags != 0 {
			t.Fatalf("native host input %s requires metadata an ordinary foreign host cannot restore", e.Path)
		}
		e.Path = rel
		entries = append(entries, e)
		seen[root] = true
	}
	if len(entries) != 13 || len(seen) != len(roots) {
		t.Fatalf("native host-import controls changed: %d entries, roots %v", len(entries), seen)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	return entries
}

func materializeNativeHostTree(t *testing.T, ctx context.Context, host string, source filesystem.Reader, entries []schema.Entry) {
	t.Helper()
	if err := os.Mkdir(host, 0o750); err != nil {
		t.Fatal(err)
	}
	aliases := map[uint64]string{}
	for _, entry := range entries {
		filename := filepath.Join(host, filepath.FromSlash(entry.Path))
		switch entry.Kind {
		case "dir":
			if err := os.Mkdir(filename, 0o750); err != nil {
				t.Fatal(err)
			}
		case "file":
			if first := aliases[entry.ID]; first != "" {
				if err := os.Link(first, filename); err != nil {
					t.Fatal(err)
				}
				continue
			}
			id, err := filesystem.LookupExact(ctx, source, "Fixture/tree/"+entry.Path)
			if err != nil {
				t.Fatal(err)
			}
			value, err := source.OpenData(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			out, err := os.OpenFile(filename, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
			if err != nil {
				closeFixture(t, value)
				t.Fatal(err)
			}
			_, err = io.Copy(out, io.NewSectionReader(value, 0, value.Size()))
			err = errors.Join(err, out.Close(), value.Close())
			if err != nil {
				t.Fatal(err)
			}
			if got, err := schema.FileDigest(filename); err != nil || got != entry.SHA256 {
				t.Fatalf("host payload %s differs from native bytes: %s (%v)", entry.Path, got, err)
			}
			aliases[entry.ID] = filename
		case "symlink":
			// Created after all real paths, so Windows can identify a
			// directory target without dereferencing it during the import.
		default:
			t.Fatal("unexpected native host-input kind", entry.Kind)
		}
	}
	for _, entry := range entries {
		if entry.Kind == "symlink" {
			target, err := hex.DecodeString(entry.Target)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(string(target), filepath.Join(host, filepath.FromSlash(entry.Path))); err != nil {
				t.Fatal("creating ordinary host symlink control:", err)
			}
		}
	}
	stamp := fixedClock.Add(time.Hour)
	// Linux relatime advances an old atime after the first alias is read.
	// Use an explicit future input atime so copying hard-linked paths as
	// independent files cannot change their source metadata mid-import.
	access := time.Now().UTC().Add(48 * time.Hour)
	for _, entry := range append([]schema.Entry{{Path: ".", Kind: "dir"}}, entries...) {
		if entry.Kind != "symlink" {
			if err := os.Chtimes(filepath.Join(host, filepath.FromSlash(entry.Path)), access, stamp); err != nil {
				t.Fatal(err)
			}
		}
	}
}

type hostImportObservation struct {
	info   os.FileInfo
	mode   uint32
	uid    uint32
	gid    uint32
	flags  uint32
	access time.Time
}

func observeHostImportTree(t *testing.T, host string, entries []schema.Entry) map[string]hostImportObservation {
	t.Helper()
	out := map[string]hostImportObservation{}
	for _, entry := range append([]schema.Entry{{Path: ".", Kind: "dir"}}, entries...) {
		info, err := os.Lstat(filepath.Join(host, filepath.FromSlash(entry.Path)))
		if err != nil {
			t.Fatal(err)
		}
		out[entry.Path] = observeHostImportMetadata(t, info)
	}
	return out
}

func checkImportedHostTree(t *testing.T, ctx context.Context, current *session.Session, entries []schema.Entry, observed map[string]hostImportObservation, preserveLinks bool) {
	t.Helper()
	paths := map[string]uint64{}
	var walk func(uint64, string)
	walk = func(dir uint64, prefix string) {
		if err := current.ReadDir(ctx, dir, func(e filesystem.DirEntry) error {
			p := path.Join(prefix, e.Name)
			paths[p] = e.Object
			n, err := current.Stat(ctx, e.Object)
			if err == nil && n.Metadata.Mode.Value&0o170000 == 0o040000 {
				walk(e.Object, p)
			}
			return err
		}); err != nil {
			t.Fatal(err)
		}
	}
	walk(current.Root(), "")
	if len(paths) != len(entries) {
		t.Fatalf("imported %d paths, native control has %d", len(paths), len(entries))
	}
	forward, reverse := map[uint64]uint64{}, map[uint64]uint64{}
	for _, entry := range entries {
		id, ok := paths[entry.Path]
		if !ok {
			t.Error("missing native logical host path", entry.Path)
			continue
		}
		node, err := current.Stat(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		checkHostImportMetadata(t, current.NameRules(), entry.Path, node, observed[entry.Path])
		switch entry.Kind {
		case "file":
			if sum, size, err := hashValue(ctx, current, id); err != nil || sum != entry.SHA256 || size != entry.Size {
				t.Errorf("%s: native data %s/%d, imported %s/%d (%v)", entry.Path, entry.SHA256, entry.Size, sum, size, err)
			}
			links := uint32(1)
			if preserveLinks {
				links = entry.Links
			}
			if node.Links.State != filesystem.Present || node.Links.Value != links {
				t.Errorf("%s: imported link count %+v, expected %d", entry.Path, node.Links, links)
			}
		case "symlink":
			target, err := current.Readlink(ctx, id)
			if err != nil || hex.EncodeToString([]byte(target)) != entry.Target {
				t.Errorf("%s: native symlink %s, imported %q (%v)", entry.Path, entry.Target, target, err)
			}
		}
		if other, exists := reverse[id]; exists && (!preserveLinks || other != entry.ID) {
			t.Errorf("distinct host objects merged at %s", entry.Path)
		}
		if other, exists := forward[entry.ID]; preserveLinks && exists && other != id {
			t.Errorf("native hard-link group split at %s", entry.Path)
		}
		forward[entry.ID], reverse[id] = id, entry.ID
	}
	root, err := current.Stat(ctx, current.Root())
	if err != nil {
		t.Fatal(err)
	}
	checkHostImportMetadata(t, current.NameRules(), ".", root, observed["."])
}

func checkHostImportMetadata(t *testing.T, rules filesystem.NameRules, name string, node filesystem.Node, host hostImportObservation) {
	t.Helper()
	if node.Metadata.Mode.Value != host.mode || node.Metadata.UID.Value != host.uid || node.Metadata.GID.Value != host.gid || node.Metadata.BSDFlags.Value != host.flags {
		t.Errorf("%s: imported metadata %+v differs from host observation mode=%o uid=%d gid=%d flags=%#x", name, node.Metadata, host.mode, host.uid, host.gid, host.flags)
	}
	nativeTime := func(value time.Time) time.Time {
		if rules.Format == "HFS+" {
			return value.Truncate(time.Second)
		}
		return value
	}
	wantTimes := []struct {
		name string
		got  time.Time
		want time.Time
	}{{"birth", node.Metadata.BirthTime.Value, fixedClock}, {"change", node.Metadata.ChangeTime.Value, fixedClock}, {"modify", node.Metadata.ModifyTime.Value, nativeTime(host.info.ModTime())}, {"access", node.Metadata.AccessTime.Value, nativeTime(host.access)}}
	for _, field := range wantTimes {
		if !field.got.Equal(field.want) {
			t.Errorf("%s: %s time %s, expected host/archive policy %s", name, field.name, field.got, field.want)
		}
	}
	defaults := []string(nil)
	switch runtime.GOOS {
	case "windows":
		defaults = []string{"bsdFlags", "gid", "mode", "uid"}
	case "linux":
		defaults = []string{"bsdFlags"}
	}
	if !slices.Equal(node.MetadataDefaulted, defaults) || node.AttributesUnavailable != (runtime.GOOS == "windows") {
		t.Errorf("%s: metadata provenance defaulted=%v unavailable=%t, expected %v/%t", name, node.MetadataDefaulted, node.AttributesUnavailable, defaults, runtime.GOOS == "windows")
	}
}

func checkHostImportReport(t *testing.T, report session.Report, reader filesystem.Reader, pathCount int, preserveLinks bool) {
	t.Helper()
	// The native pair has one alias, so the copied graph has one fewer object
	// when link preservation is requested. Reports must identify actual nodes.
	objectCount := pathCount
	if preserveLinks {
		objectCount--
	}
	if report.Objects != objectCount || report.Entries != pathCount {
		t.Errorf("host archive graph report has %d objects/%d entries, expected %d/%d", report.Objects, report.Entries, objectCount, pathCount)
	}
	omittedObjects := map[uint64]bool{}
	seen := map[uint64]bool{}
	for _, omitted := range report.OmittedAttributes {
		if omitted.Attribute != "com.apple.system.Security" || omitted.Reason == "" || omitted.Source == "" || omitted.Destination == "" {
			t.Errorf("host archive silently claimed captured ACL data: %+v", omitted)
		}
		id, err := filesystem.Lookup(context.Background(), reader, omitted.Destination)
		if err != nil || omittedObjects[id] {
			t.Errorf("host ACL omission names missing/duplicate destination %s (%v)", omitted.Destination, err)
		}
		omittedObjects[id] = true
	}
	for _, object := range report.AttributesUnavailable {
		if seen[object] {
			t.Error("host availability report duplicates an object", object)
		}
		seen[object] = true
		node, err := reader.Stat(context.Background(), object)
		if err != nil || !node.AttributesUnavailable {
			t.Errorf("unavailable host attributes report names an available node: %d (%v)", object, err)
		}
	}
	if runtime.GOOS == "windows" && len(seen) != objectCount || runtime.GOOS != "windows" && len(seen) != 0 {
		t.Errorf("host attribute-availability report has %d objects for %d paths", len(seen), pathCount)
	}
	if len(omittedObjects) != objectCount {
		t.Errorf("host ACL omissions missing from archive report: %d for %d objects", len(omittedObjects), objectCount)
	}
	defaults := map[uint64]bool{}
	for _, value := range report.Defaulted {
		node, err := reader.Stat(context.Background(), value.Object)
		if err != nil || defaults[value.Object] || !slices.Equal(value.Fields, node.MetadataDefaulted) || len(value.Fields) == 0 {
			t.Errorf("host metadata default report differs from node %d: %v (%v)", value.Object, value.Fields, err)
		}
		defaults[value.Object] = true
	}
	if runtime.GOOS == "darwin" && len(defaults) != 0 || runtime.GOOS != "darwin" && len(defaults) != objectCount {
		t.Errorf("host metadata default report has %d entries for %d objects on %s", len(defaults), objectCount, runtime.GOOS)
	}
}

func checkHostInputUnchanged(t *testing.T, host string, entries []schema.Entry, observed map[string]hostImportObservation) {
	t.Helper()
	for _, entry := range entries {
		filename := filepath.Join(host, filepath.FromSlash(entry.Path))
		info, err := os.Lstat(filename)
		before := observed[entry.Path].info
		if err != nil || !os.SameFile(before, info) || !before.ModTime().Equal(info.ModTime()) || before.Mode() != info.Mode() || before.Size() != info.Size() {
			t.Errorf("host input %s changed during import (%v)", entry.Path, err)
		}
		if entry.Kind == "file" {
			if sum, err := schema.FileDigest(filename); err != nil || sum != entry.SHA256 {
				t.Errorf("host input bytes %s changed during import: %s (%v)", entry.Path, sum, err)
			}
		}
	}
}
