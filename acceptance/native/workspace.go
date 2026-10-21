package native

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// These are independent descriptions of the exported preservation format, not
// aliases of product types. No product reader participates in this verdict.
type workspaceField[T any] struct {
	State int `json:"state"`
	Value T   `json:"value"`
}
type workspaceObject struct {
	Node struct {
		Created       bool `json:"created"`
		DataModified  bool `json:"dataModified"`
		LinksModified bool `json:"linksModified"`
		Identity      struct {
			Volume string `json:"volume"`
			Object uint64 `json:"object"`
			View   uint64 `json:"view"`
		} `json:"identity"`
		Metadata struct {
			Mode, UID, GID                                workspaceField[uint32]
			BSDFlags                                      workspaceField[uint32] `json:"bsdFlags"`
			BirthTime, ModifyTime, ChangeTime, AccessTime workspaceField[time.Time]
		} `json:"metadata"`
		Size        uint64                 `json:"size"`
		Links       workspaceField[uint32] `json:"links"`
		Compression workspaceField[struct {
			Type uint32 `json:"type"`
		}] `json:"compression"`
	} `json:"node"`
	Data       *workspaceBlob `json:"data"`
	Raw        *workspaceBlob `json:"rawData"`
	Target     []byte         `json:"targetBytes"`
	Attributes []struct {
		Name  []byte        `json:"nameBytes"`
		Value workspaceBlob `json:"value"`
	} `json:"attributes"`
}
type workspaceBlob struct {
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type workspaceEntry struct {
	Parent       uint64 `json:"parent"`
	Name         []byte `json:"nameBytes"`
	Object       uint64 `json:"object"`
	Host         string `json:"hostPath"`
	Materialized string `json:"materialized"`
}
type workspaceDocument struct {
	Schema  int               `json:"schema"`
	Root    uint64            `json:"root"`
	Parent  string            `json:"parentManifestSHA256"`
	Objects []workspaceObject `json:"objects"`
	Entries []workspaceEntry  `json:"entries"`
	Names   struct {
		Format                   string `json:"format"`
		CaseSensitive            bool   `json:"caseSensitive"`
		NormalizationInsensitive bool   `json:"normalizationInsensitive"`
	} `json:"names"`
}

// WorkspaceReference projects public API policy onto a copy of Apple's view.
// It never changes captured evidence or derives expectations from Go's output.
func WorkspaceReference(before, after schema.View, expect schema.Expectation) (schema.View, error) {
	if expect.Workspace == nil {
		return schema.View{}, fmt.Errorf("missing workspace policy")
	}
	old := map[uint64]schema.Entry{}
	var boundary int64
	for _, e := range before.Entries {
		old[e.ID] = e
		boundary = max(boundary, e.Times.Birth, e.Times.Modify, e.Times.Change, e.Times.Access)
	}
	result := after
	result.Entries = nil
	var timedID uint64
	for _, e := range after.Entries {
		if e.Path == "Fixture/meta/renamed" {
			timedID = e.ID
		}
	}
	for _, e := range after.Entries {
		if e.Path != expect.Subtree && !strings.HasPrefix(e.Path, expect.Subtree+"/") {
			continue
		}
		e.Xattrs = slices.Clone(e.Xattrs)
		switch expect.Workspace.Policy {
		case "preserve":
			if original, ok := old[e.ID]; ok {
				times := e.Times
				e.Times = original.Times
				// This recipe explicitly patches these three times through
				// every alias of the renamed object. Change time is preserved.
				if e.ID == timedID {
					e.Times.Birth, e.Times.Modify, e.Times.Access = times.Birth, times.Modify, times.Access
				}
			}
		case "commands":
			if expect.Workspace.ClockNS <= boundary {
				return schema.View{}, fmt.Errorf("command clock must follow captured source clocks")
			}
			for _, field := range []*int64{&e.Times.Birth, &e.Times.Modify, &e.Times.Change, &e.Times.Access} {
				if *field > boundary {
					*field = expect.Workspace.ClockNS
				}
			}
			// Fresh host inputs and mkdir/ln receive runner provenance that
			// portable commands cannot invent. Copied provenance stays exact.
			if commandCreatedPath(e.Path) {
				e.Xattrs = slices.DeleteFunc(e.Xattrs, func(x schema.Xattr) bool { return x.Name == "com.apple.provenance" })
			}
			// Sessions copy logical bytes; they do not encode decmpfs.
			if e.Path == "Fixture/plain-copy" && e.Compression != nil {
				e.Compression = nil
				e.Flags &^= 32
				e.Xattrs = slices.DeleteFunc(e.Xattrs, func(x schema.Xattr) bool { return compressionOwned[x.Name] })
			}
		default:
			return schema.View{}, fmt.Errorf("unknown workspace policy %q", expect.Workspace.Policy)
		}
		result.Entries = append(result.Entries, e)
	}
	return result, nil
}

func commandCreatedPath(p string) bool {
	switch p {
	case "Fixture/Applications/Source.app/Contents/Moved", "Fixture/Applications/Source.app/Contents/Moved/deep", "Fixture/Applications/Source.app/Contents/Moved/build.bin", "Fixture/build-alias", "Fixture/app-link":
		return true
	}
	return false
}

func readWorkspaceArchive(filename string) (map[string][]byte, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	z, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	defer func() { _ = z.Close() }()
	r := tar.NewReader(z)
	files := map[string][]byte{}
	seen := map[string]bool{}
	var total int64
	for {
		h, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if h.Name == "." || !fs.ValidPath(h.Name) || strings.Contains(h.Name, "\\") {
			return nil, fmt.Errorf("unsafe workspace archive name %q", h.Name)
		}
		if seen[h.Name] {
			return nil, fmt.Errorf("duplicate archive member %q", h.Name)
		}
		seen[h.Name] = true
		if h.Typeflag == tar.TypeDir {
			if h.Size != 0 {
				return nil, fmt.Errorf("nonempty directory archive member")
			}
			files[h.Name+"/"] = nil
			continue
		}
		if h.Typeflag != tar.TypeReg || h.Size < 0 || h.Size > 64<<20 || total+h.Size > 256<<20 {
			return nil, fmt.Errorf("unsupported workspace archive member %q", h.Name)
		}
		if _, exists := files[h.Name]; exists {
			return nil, fmt.Errorf("duplicate archive member %q", h.Name)
		}
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		files[h.Name] = data
		total += h.Size
	}
	// Consume the gzip trailer too: a truncated evidence archive must fail.
	if _, err := io.Copy(io.Discard, z); err != nil {
		return nil, err
	}
	return files, nil
}

// VerifyWorkspaceArchive checks graph identities, original names, host
// projections, every logical/raw/blob digest, metadata and ACL bytes against
// Apple observations. It is also runnable on portable hosts without native I/O.
func VerifyWorkspaceArchive(filename, profileID string, before, after schema.View, expect schema.Expectation) ([]Difference, error) {
	want, err := WorkspaceReference(before, after, expect)
	if err != nil {
		return nil, err
	}
	files, err := readWorkspaceArchive(filename)
	if err != nil {
		return nil, err
	}
	var doc workspaceDocument
	if err := json.Unmarshal(files["metadata/manifest.json"], &doc); err != nil {
		return nil, err
	}
	if doc.Schema < 1 || doc.Schema > 5 || doc.Root == 0 {
		return nil, fmt.Errorf("invalid workspace manifest")
	}
	profile, err := schema.LookupProfile(profileID)
	if err != nil {
		return nil, err
	}
	format := "HFS+"
	if profile.Family == "apfs" {
		format = "APFS"
	}
	if doc.Names.Format != format || doc.Names.CaseSensitive != profile.CaseSensitive || !doc.Names.NormalizationInsensitive {
		return nil, fmt.Errorf("workspace lost its native filename rules")
	}
	if parent := expect.Workspace.ParentOutput; parent != "" {
		if !schema.ValidDigest(doc.Parent) || filepath.Base(parent) != parent {
			return nil, fmt.Errorf("edited workspace has no valid parent binding")
		}
		previous, err := readWorkspaceArchive(filepath.Join(filepath.Dir(filename), parent))
		if err != nil {
			return nil, err
		}
		digest := sha256.Sum256(previous["metadata/manifest.json"])
		if hex.EncodeToString(digest[:]) != doc.Parent {
			return nil, fmt.Errorf("workspace parent manifest digest differs")
		}
	} else if doc.Parent != "" {
		return nil, fmt.Errorf("unexpected workspace parent binding")
	}
	used := map[string]bool{"metadata/manifest.json": true, "metadata/": true, "metadata/blobs/": true}
	blob := func(b *workspaceBlob) ([]byte, error) {
		if b == nil || !schema.ValidDigest(b.SHA256) || b.Size < 0 {
			return nil, fmt.Errorf("invalid blob reference")
		}
		name := "metadata/blobs/" + b.SHA256
		data, ok := files[name]
		sum := sha256.Sum256(data)
		if !ok || int64(len(data)) != b.Size || hex.EncodeToString(sum[:]) != b.SHA256 {
			return nil, fmt.Errorf("missing or corrupt blob %s", b.SHA256)
		}
		used[name] = true
		return data, nil
	}
	objects := map[uint64]workspaceObject{}
	for _, o := range doc.Objects {
		id := o.Node.Identity.Object
		if id == 0 {
			return nil, fmt.Errorf("zero workspace object")
		}
		if _, exists := objects[id]; exists {
			return nil, fmt.Errorf("duplicate workspace object %d", id)
		}
		objects[id] = o
	}
	sourceRoot, ok := objects[doc.Root]
	if !ok {
		return nil, fmt.Errorf("missing workspace root object")
	}
	paths := map[uint64]string{}
	projected := map[uint64]string{}
	seenObjects := map[uint64]bool{}
	seenPaths, hosts := map[string]bool{}, map[string]bool{}
	nativeByPath := map[string]schema.Entry{}
	originals := map[uint64]schema.Entry{}
	for _, e := range before.Entries {
		originals[e.ID] = e
	}
	for _, e := range want.Entries {
		nativeByPath[e.Path] = e
	}
	forward, reverse := map[uint64]uint64{}, map[uint64]uint64{}
	spellings := map[uint64]map[string]int{}
	for _, entry := range doc.Entries {
		if entry.Parent != 0 {
			if spellings[entry.Parent] == nil {
				spellings[entry.Parent] = map[string]int{}
			}
			spellings[entry.Parent][strings.ToLower(workspaceHostComponent(string(entry.Name)))]++
		}
	}
	var got schema.View
	for _, entry := range doc.Entries {
		o, ok := objects[entry.Object]
		if !ok {
			return nil, fmt.Errorf("entry has no object %d", entry.Object)
		}
		name := string(entry.Name)
		logical := expect.Subtree
		if entry.Parent == 0 {
			if entry.Object != doc.Root || len(entry.Name) != 0 || entry.Host != "files" {
				return nil, fmt.Errorf("invalid workspace root")
			}
		} else {
			parent, ok := paths[entry.Parent]
			if !ok || name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\x00") {
				return nil, fmt.Errorf("invalid workspace parent/name")
			}
			logical = parent + "/" + name
			if path.Dir(entry.Host) != projected[entry.Parent] {
				return nil, fmt.Errorf("projection escaped its logical parent at %s", logical)
			}
			component := workspaceHostComponent(name)
			if spellings[entry.Parent][strings.ToLower(component)] > 1 {
				component = workspaceEscapedName(name)
			}
			if path.Base(entry.Host) != component {
				return nil, fmt.Errorf("incorrect portable name mapping at %s", logical)
			}
		}
		if seenPaths[logical] || hosts[entry.Host] || !strings.HasPrefix(entry.Host+"/", "files/") || !fs.ValidPath(entry.Host) {
			return nil, fmt.Errorf("duplicate/unsafe workspace path %q", logical)
		}
		seenPaths[logical], hosts[entry.Host], seenObjects[entry.Object] = true, true, true
		native, ok := nativeByPath[logical]
		if !ok {
			return nil, fmt.Errorf("unexpected workspace path %s", logical)
		}
		id := o.Node.Identity.Object
		if (forward[native.ID] != 0 && forward[native.ID] != id) || (reverse[id] != 0 && reverse[id] != native.ID) {
			return nil, fmt.Errorf("split or merged hard-link identity at %s", logical)
		}
		forward[native.ID], reverse[id] = id, native.ID
		if original, exists := originals[native.ID]; exists {
			if id != native.ID || o.Node.Created || o.Node.Identity.Volume != sourceRoot.Node.Identity.Volume || o.Node.Identity.View != sourceRoot.Node.Identity.View {
				return nil, fmt.Errorf("source identity replaced at %s", logical)
			}
			if native.Kind == "file" && native.SHA256 != original.SHA256 && !o.Node.DataModified {
				return nil, fmt.Errorf("modified data lost provenance at %s", logical)
			}
			if native.Kind != "dir" && native.Links != original.Links && !o.Node.LinksModified {
				return nil, fmt.Errorf("modified aliases lost provenance at %s", logical)
			}
		} else if !o.Node.Created || !strings.HasPrefix(o.Node.Identity.Volume, "workspace:") || !schema.ValidDigest(strings.TrimPrefix(o.Node.Identity.Volume, "workspace:")) || o.Node.Identity.View != 0 {
			return nil, fmt.Errorf("new object impersonates native identity at %s", logical)
		}
		m := o.Node.Metadata
		for _, state := range []int{m.Mode.State, m.UID.State, m.GID.State, m.BSDFlags.State, m.BirthTime.State, m.ModifyTime.State, m.ChangeTime.State, m.AccessTime.State} {
			if state != 2 {
				return nil, fmt.Errorf("uncaptured metadata at %s", logical)
			}
		}
		e := schema.Entry{Path: logical, NameBytes: hex.EncodeToString([]byte(path.Base(logical))), ID: native.ID, Mode: m.Mode.Value & 07777, UID: m.UID.Value, GID: m.GID.Value, Flags: m.BSDFlags.Value, Times: schema.Times{Birth: m.BirthTime.Value.UnixNano(), Modify: m.ModifyTime.Value.UnixNano(), Change: m.ChangeTime.Value.UnixNano(), Access: m.AccessTime.Value.UnixNano()}}
		switch m.Mode.Value & 0170000 {
		case 0040000:
			e.Kind = "dir"
			if entry.Materialized != "directory" {
				return nil, fmt.Errorf("directory projection missing at %s", logical)
			}
			if _, exists := paths[id]; exists {
				return nil, fmt.Errorf("directory alias or cycle")
			}
			paths[id] = logical
			projected[id] = entry.Host
			if _, exists := files[entry.Host+"/"]; !exists {
				return nil, fmt.Errorf("missing projected directory at %s", logical)
			}
			used[entry.Host+"/"] = true
		case 0100000:
			e.Kind, e.Size, e.Links = "file", int64(o.Node.Size), o.Node.Links.Value
			data, err := blob(o.Data)
			if err != nil {
				return nil, err
			}
			raw, err := blob(o.Raw)
			if err != nil {
				return nil, err
			}
			if int64(len(data)) != e.Size {
				return nil, fmt.Errorf("logical length mismatch at %s", logical)
			}
			e.SHA256, e.RawSHA256 = o.Data.SHA256, o.Raw.SHA256
			if _, exists := files[entry.Host]; !exists || !bytes.Equal(files[entry.Host], data) {
				return nil, fmt.Errorf("host file projection differs at %s", logical)
			}
			if entry.Materialized != "file" && entry.Materialized != "hard-link" && entry.Materialized != "hard-link-copy" {
				return nil, fmt.Errorf("invalid file projection at %s", logical)
			}
			used[entry.Host] = true
			if o.Node.Compression.State == 2 {
				t := o.Node.Compression.Value.Type
				storage := "attribute"
				if t == 4 || t == 8 {
					storage = "resource"
				}
				e.Compression = &schema.Compression{Type: t, Storage: storage, KernelRead: "ok"}
			} else if o.Node.Compression.State != 1 || !bytes.Equal(data, raw) {
				return nil, fmt.Errorf("invalid ordinary raw data at %s", logical)
			}
		case 0120000:
			e.Kind, e.Size, e.Links, e.Target = "symlink", int64(o.Node.Size), o.Node.Links.Value, hex.EncodeToString(o.Target)
			_, exists := files[entry.Host]
			if !exists || entry.Materialized != "symlink-record" || !bytes.Equal(files[entry.Host], o.Target) || uint64(len(o.Target)) != o.Node.Size {
				return nil, fmt.Errorf("unsafe or incorrect symlink projection")
			}
			used[entry.Host] = true
		default:
			return nil, fmt.Errorf("unsupported workspace object type")
		}
		if e.Kind != "dir" && o.Node.Links.State != 2 {
			return nil, fmt.Errorf("uncaptured link count")
		}
		attrs := map[string]bool{}
		for _, a := range o.Attributes {
			name := string(a.Name)
			if attrs[name] {
				return nil, fmt.Errorf("duplicate attribute %q", name)
			}
			attrs[name] = true
			data, err := blob(&a.Value)
			if err != nil {
				return nil, err
			}
			switch name {
			case "com.apple.fs.symlink":
			case "com.apple.system.Security":
				e.ACL = hex.EncodeToString(workspaceSecurityOrder(data))
			default:
				// Native listxattr can hide an empty retained record.
				if len(data) == 0 && !slices.ContainsFunc(native.Xattrs, func(x schema.Xattr) bool { return x.Name == name }) {
					continue
				}
				e.Xattrs = append(e.Xattrs, schema.Xattr{Name: name, Bytes: a.Value.Size, SHA256: a.Value.SHA256})
			}
		}
		// Raw bytes are compared independently wherever Apple supplied them.
		if native.RawSHA256 != "" && e.RawSHA256 != native.RawSHA256 {
			return nil, fmt.Errorf("raw fork changed at %s", logical)
		}
		got.Entries = append(got.Entries, e)
	}
	if len(seenObjects) != len(objects) {
		return nil, fmt.Errorf("unreachable workspace objects")
	}
	for name := range files {
		if !used[name] {
			return nil, fmt.Errorf("unreferenced workspace file %s", name)
		}
	}
	return CompareViews(got, want, CompareOptions{}), nil
}

// The preservation format reserves a hash spelling for unsafe, long, Unicode,
// case-colliding and Windows device names, consistently on every host.
func workspaceHostComponent(name string) string {
	safe := len(name) <= 120 && !strings.HasSuffix(name, ".") && !strings.HasSuffix(name, " ") && !strings.HasPrefix(name, "~")
	for _, b := range []byte(name) {
		if b < 32 || b > 126 || strings.ContainsRune(`<>:"/\|?*`, rune(b)) {
			safe = false
		}
	}
	stem := strings.ToUpper(strings.SplitN(name, ".", 2)[0])
	switch stem {
	case "CON", "PRN", "AUX", "NUL", "CLOCK$", "CONIN$", "CONOUT$":
		safe = false
	}
	if len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) && stem[3] >= '1' && stem[3] <= '9' {
		safe = false
	}
	if safe {
		return name
	}
	return workspaceEscapedName(name)
}
func workspaceEscapedName(name string) string {
	sum := sha256.Sum256([]byte(name))
	return "~" + hex.EncodeToString(sum[:])
}

// getattrlist uses host-order integer words; the serialized security attribute
// uses network order. GUID bytes are unchanged (Apple filesec layout).
func workspaceSecurityOrder(data []byte) []byte {
	b := slices.Clone(data)
	for _, off := range []int{0, 36, 40} {
		if off+4 <= len(b) {
			slices.Reverse(b[off : off+4])
		}
	}
	for off := 44; off+24 <= len(b); off += 24 {
		slices.Reverse(b[off+16 : off+20])
		slices.Reverse(b[off+20 : off+24])
	}
	return b
}
