package corpus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"reflect"
	"slices"
	"strings"
)

type ManifestReference struct {
	Path   string
	SHA256 string
	Cases  []string
}

type Definition struct {
	ID        string
	Path      string
	Bindings  []Binding
	Manifests []ManifestReference
}

// Build inventories existing evidence only. Its caller must review the new
// catalog; this does not approve, replace or publish any native reference.
func Build(ctx context.Context, repository string, definitions []Definition) (Catalog, error) {
	catalog := Catalog{Schema: 1}
	repo, err := os.OpenRoot(repository)
	if err != nil {
		return catalog, err
	}
	defer func() { _ = repo.Close() }()
	for _, def := range definitions {
		if !PortablePath(def.Path) {
			return catalog, errors.New("unsafe committed corpus directory")
		}
		root, err := openCommitted(repo, def.Path)
		if err != nil {
			return catalog, err
		}
		entry, err := buildEntry(ctx, root, def)
		closeErr := root.Close()
		if err != nil {
			return catalog, fmt.Errorf("%s: %w", def.ID, err)
		}
		if closeErr != nil {
			return catalog, closeErr
		}
		catalog.Entries = append(catalog.Entries, entry)
	}
	slices.SortFunc(catalog.Entries, func(a, b Entry) int { return strings.Compare(a.ID, b.ID) })
	return catalog, catalog.Validate()
}

func buildEntry(ctx context.Context, root *os.Root, def Definition) (Entry, error) {
	entry := Entry{ID: def.ID, Bindings: slices.Clone(def.Bindings), Location: Location{Kind: "committed", Path: def.Path}}
	slices.SortFunc(entry.Bindings, func(a, b Binding) int { return strings.Compare(a.Family, b.Family) })
	var total int64
	err := fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !PortablePath(name) || len(entry.Files) >= MaxFiles {
			return errors.New("invalid corpus member path/count")
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > MaxTreeBytes-total {
			return errors.New("invalid corpus member type/size")
		}
		input, err := root.Open(name)
		if err != nil {
			return err
		}
		hash := sha256.New()
		n, err := io.CopyBuffer(hash, io.LimitReader(contextReader{ctx, input}, info.Size()+1), make([]byte, 64<<10))
		closeErr := input.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		if n != info.Size() {
			return errors.New("corpus member changed during inventory")
		}
		entry.Files = append(entry.Files, File{Path: name, Bytes: n, SHA256: hex.EncodeToString(hash.Sum(nil))})
		total += n
		return nil
	})
	if err != nil {
		return entry, err
	}
	slices.SortFunc(entry.Files, func(a, b File) int { return strings.Compare(a.Path, b.Path) })
	files := map[string]File{}
	for _, f := range entry.Files {
		files[f.Path] = f
	}
	for _, ref := range def.Manifests {
		file, ok := files[ref.Path]
		if !ok || file.SHA256 != ref.SHA256 {
			return entry, fmt.Errorf("registered original manifest differs: %s", ref.Path)
		}
		data, err := originalManifest(root, ref.Path)
		if err != nil {
			return entry, err
		}
		capture, err := parseCapture(ref.Path, data)
		if err != nil {
			return entry, err
		}
		if !slices.Equal(capture.Cases, ref.Cases) {
			return entry, errors.New("registered original case inventory differs")
		}
		entry.Captures = append(entry.Captures, capture)
	}
	for _, f := range entry.Files {
		if IsManifest(f.Path) {
			found := false
			for _, c := range entry.Captures {
				found = found || c.Manifest == f.Path
			}
			if !found {
				return entry, fmt.Errorf("unregistered native manifest: %s", f.Path)
			}
		}
	}
	slices.SortFunc(entry.Captures, func(a, b Capture) int { return strings.Compare(a.Manifest, b.Manifest) })
	entry.TreeSHA256, err = entry.Identity()
	if err != nil {
		return entry, err
	}
	return entry, entry.Validate()
}

// MatchRetainedDefinitions checks catalog coverage against the separate capability
// registry, without tying native input identity to workflow or result hashes.
func MatchRetainedDefinitions(catalog Catalog, definitions []Definition) error {
	if err := catalog.Validate(); err != nil {
		return err
	}
	if len(catalog.Entries) != len(definitions) {
		return errors.New("corpus catalog/registry entry count differs")
	}
	entries := map[string]Entry{}
	for _, entry := range catalog.Entries {
		entries[entry.ID] = entry
	}
	seen := map[string]bool{}
	for _, def := range definitions {
		if seen[def.ID] {
			return errors.New("duplicate registry corpus definition")
		}
		seen[def.ID] = true
		entry, ok := entries[def.ID]
		if !ok || len(entry.Captures) != len(def.Manifests) {
			return fmt.Errorf("required corpus/captures missing: %s", def.ID)
		}
		if entry.Location.Kind == "committed" && entry.Location.Path != def.Path {
			return errors.New("committed corpus path differs from registry")
		}
		bindings := slices.Clone(def.Bindings)
		slices.SortFunc(bindings, func(a, b Binding) int { return strings.Compare(a.Family, b.Family) })
		if !reflect.DeepEqual(entry.Bindings, bindings) {
			return fmt.Errorf("capture dependency classification differs: %s", def.ID)
		}
		files := map[string]File{}
		for _, f := range entry.Files {
			files[f.Path] = f
		}
		captures := map[string]Capture{}
		for _, c := range entry.Captures {
			captures[c.Manifest] = c
		}
		for _, ref := range def.Manifests {
			capture, ok := captures[ref.Path]
			if !ok || !slices.Equal(capture.Cases, ref.Cases) || files[ref.Path].SHA256 != ref.SHA256 {
				return fmt.Errorf("catalog changes registered native evidence: %s/%s", def.ID, ref.Path)
			}
		}
	}
	return nil
}

func IsManifest(name string) bool {
	name = path.Base(strings.TrimSuffix(name, ".gz"))
	return strings.HasSuffix(name, "manifest.json") || name == "recovery.json"
}
