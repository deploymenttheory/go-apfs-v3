package fixture

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// WriteManifest indexes every regular file under dir, grouped by the
// observation files the capture wrote, and writes manifest.json.
func WriteManifest(dir string, producer schema.Producer, recipesDigest string) (*schema.Manifest, error) {
	var observations []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(d.Name(), ".observation.json") {
			rel, _ := filepath.Rel(dir, path)
			observations = append(observations, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(observations)
	manifest := &schema.Manifest{Schema: schema.ManifestSchema, Producer: producer, Recipes: recipesDigest}
	for _, rel := range observations {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			return nil, err
		}
		var obs schema.Observation
		if err := schema.DecodeStrict(data, &obs); err != nil {
			return nil, fmt.Errorf("%s: %w", rel, err)
		}
		cf := schema.CaseFile{Recipe: obs.Recipe, Profile: obs.Profile, Stage: obs.Stage, Observation: rel}
		caseDir := filepath.Dir(filepath.FromSlash(rel))
		prefix := strings.TrimSuffix(filepath.Base(rel), ".observation.json")
		entries, err := os.ReadDir(filepath.Join(dir, caseDir))
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasPrefix(entry.Name(), prefix+".") {
				continue
			}
			path := filepath.Join(dir, caseDir, entry.Name())
			sum, err := schema.FileDigest(path)
			if err != nil {
				return nil, err
			}
			info, err := entry.Info()
			if err != nil {
				return nil, err
			}
			cf.Files = append(cf.Files, schema.FileEntry{Path: filepath.ToSlash(filepath.Join(caseDir, entry.Name())), Bytes: info.Size(), SHA256: sum})
		}
		manifest.Cases = append(manifest.Cases, cf)
	}
	if len(manifest.Cases) == 0 {
		return nil, fmt.Errorf("%s: no observations to index", dir)
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), append(data, '\n'), 0o644); err != nil {
		return nil, err
	}
	return manifest, nil
}

// WriteBundle packs dir into a deterministic tar.gz named by its digest:
// fixtures-macos-<major>-<sha256[:16]>.tar.gz in outDir. Entries are sorted,
// ownership is zeroed and mtimes are fixed so the same tree yields the same
// bytes.
func WriteBundle(dir string, major int, outDir string) (string, string, int64, error) {
	var paths []string
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			if !d.Type().IsRegular() {
				return fmt.Errorf("bundle: %s is not a regular file", path)
			}
			paths = append(paths, path)
		}
		return nil
	})
	if err != nil {
		return "", "", 0, err
	}
	sort.Strings(paths)
	tmp, err := os.CreateTemp(outDir, "bundle-*.tar.gz")
	if err != nil {
		return "", "", 0, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	digest := sha256.New()
	gz := gzip.NewWriter(io.MultiWriter(tmp, digest))
	tw := tar.NewWriter(gz)
	for _, path := range paths {
		rel, _ := filepath.Rel(dir, path)
		info, err := os.Stat(path)
		if err != nil {
			return "", "", 0, err
		}
		hdr := &tar.Header{Name: filepath.ToSlash(rel), Mode: 0o644, Size: info.Size(), Format: tar.FormatPAX}
		if err := tw.WriteHeader(hdr); err != nil {
			return "", "", 0, err
		}
		f, err := os.Open(path)
		if err != nil {
			return "", "", 0, err
		}
		_, err = io.Copy(tw, f)
		_ = f.Close()
		if err != nil {
			return "", "", 0, err
		}
	}
	if err := tw.Close(); err != nil {
		return "", "", 0, err
	}
	if err := gz.Close(); err != nil {
		return "", "", 0, err
	}
	if err := tmp.Close(); err != nil {
		return "", "", 0, err
	}
	sum := hex.EncodeToString(digest.Sum(nil))
	name := fmt.Sprintf("fixtures-macos-%d-%s.tar.gz", major, sum[:16])
	final := filepath.Join(outDir, name)
	if err := os.Rename(tmp.Name(), final); err != nil {
		return "", "", 0, err
	}
	info, err := os.Stat(final)
	if err != nil {
		return "", "", 0, err
	}
	return final, sum, info.Size(), nil
}

// ExtractBundle unpacks a bundle into dir with bounded, safe extraction:
// no absolute paths, no traversal, no links, regular files only.
func ExtractBundle(bundle, dir string, maxBytes int64) error {
	f, err := os.Open(bundle)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		name := filepath.ToSlash(hdr.Name)
		if strings.HasPrefix(name, "/") || strings.Contains(name, "..") || name == "" {
			return fmt.Errorf("bundle: unsafe path %q", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg:
		default:
			return fmt.Errorf("bundle: %s is not a regular file", hdr.Name)
		}
		total += hdr.Size
		if total > maxBytes {
			return fmt.Errorf("bundle: exceeds %d bytes", maxBytes)
		}
		target := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		out, err := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
		if err != nil {
			return err
		}
		if _, err := io.CopyN(out, tr, hdr.Size); err != nil {
			_ = out.Close()
			return err
		}
		if err := out.Close(); err != nil {
			return err
		}
	}
}
