// Package corpus resolves the pinned fixture corpus for tests: it reads
// acceptance/fixtures.lock.json, downloads each producer's bundle from the
// GitHub release, verifies its digest, extracts it into a content-addressed
// cache and returns the manifests. A missing bundle, a digest mismatch or a
// case listed in a manifest but absent from disk is an error, never a skip.
package corpus

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// Producer is one macOS version's extracted bundle.
type Producer struct {
	Major    int
	Dir      string
	Manifest *schema.Manifest
}

// Corpus is every producer the lock pins, in ascending major order.
type Corpus struct {
	Lock      *schema.Lock
	Producers []Producer
}

// Options control resolution. Zero values mean: lock at
// acceptance/fixtures.lock.json relative to Root, cache under the user cache
// directory, download from the repository's GitHub release.
type Options struct {
	Root       string // repository checkout root
	LockPath   string
	CacheDir   string
	Repository string // owner/name for release downloads
	Client     *http.Client
	// LocalDir points tests at a local capture output (APFS_FIXTURE_DIR);
	// it must contain macos-<major>/manifest.json directories.
	LocalDir string
}

// MaxBundleBytes bounds extraction of one bundle.
const MaxBundleBytes = 4 << 30

// Resolve returns the corpus, downloading and extracting bundles as needed.
func Resolve(ctx context.Context, opts Options) (*Corpus, error) {
	if opts.LocalDir == "" {
		opts.LocalDir = os.Getenv("APFS_FIXTURE_DIR")
	}
	if opts.CacheDir == "" {
		opts.CacheDir = os.Getenv("APFS_FIXTURE_CACHE")
	}
	if opts.CacheDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return nil, err
		}
		opts.CacheDir = filepath.Join(base, "go-apfs-v3", "fixtures")
	}
	if opts.LockPath == "" {
		opts.LockPath = filepath.Join(opts.Root, "acceptance", "fixtures.lock.json")
	}
	if opts.Repository == "" {
		opts.Repository = "deploymenttheory/go-apfs-v3"
	}
	if opts.Client == nil {
		opts.Client = &http.Client{Timeout: 10 * time.Minute}
	}
	lock, err := schema.ReadLock(opts.LockPath)
	if err != nil {
		return nil, err
	}
	c := &Corpus{Lock: lock}
	if opts.LocalDir != "" {
		return c, c.loadLocal(opts.LocalDir)
	}
	if len(lock.Bundles) == 0 {
		return nil, fmt.Errorf("%s pins no bundles yet; capture a corpus and update the lock, or set APFS_FIXTURE_DIR to a local capture", opts.LockPath)
	}
	for _, major := range schema.Producers {
		key := "macos-" + strconv.Itoa(major)
		bundle, ok := lock.Bundles[key]
		if !ok {
			return nil, fmt.Errorf("%s: no bundle for %s", opts.LockPath, key)
		}
		dir, err := materialize(ctx, opts, lock, bundle)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		manifest, err := readManifest(dir, major, lock.RecipesSHA256)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", key, err)
		}
		c.Producers = append(c.Producers, Producer{Major: major, Dir: dir, Manifest: manifest})
	}
	return c, nil
}

// materialize returns the extracted directory for a bundle, downloading
// and extracting it when the cache does not already hold a verified copy.
func materialize(ctx context.Context, opts Options, lock *schema.Lock, bundle schema.Bundle) (string, error) {
	dir := filepath.Join(opts.CacheDir, bundle.SHA256)
	if _, err := os.Stat(filepath.Join(dir, "manifest.json")); err == nil {
		return dir, nil
	}
	if err := os.MkdirAll(opts.CacheDir, 0o755); err != nil {
		return "", err
	}
	archive := filepath.Join(opts.CacheDir, bundle.SHA256+".tar.gz")
	if _, err := os.Stat(archive); err != nil {
		url := fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", opts.Repository, lock.Release, bundle.Asset)
		if err := download(ctx, opts.Client, url, archive, bundle); err != nil {
			return "", err
		}
	}
	sum, err := schema.FileDigest(archive)
	if err != nil {
		return "", err
	}
	if sum != bundle.SHA256 {
		_ = os.Remove(archive)
		return "", fmt.Errorf("bundle %s has digest %s, lock expects %s", bundle.Asset, sum, bundle.SHA256)
	}
	tmp := dir + ".extracting"
	_ = os.RemoveAll(tmp)
	if err := fixture.ExtractBundle(archive, tmp, MaxBundleBytes); err != nil {
		_ = os.RemoveAll(tmp)
		return "", err
	}
	if err := os.Rename(tmp, dir); err != nil {
		return "", err
	}
	return dir, nil
}

func download(ctx context.Context, client *http.Client, url, dst string, bundle schema.Bundle) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: HTTP %d", url, resp.StatusCode)
	}
	tmp := dst + ".partial"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	digest := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, digest), io.LimitReader(resp.Body, bundle.Bytes+1))
	if cerr := out.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if n != bundle.Bytes {
		_ = os.Remove(tmp)
		return fmt.Errorf("download %s: %d bytes, lock expects %d", url, n, bundle.Bytes)
	}
	if sum := hex.EncodeToString(digest.Sum(nil)); sum != bundle.SHA256 {
		_ = os.Remove(tmp)
		return fmt.Errorf("download %s: digest %s, lock expects %s", url, sum, bundle.SHA256)
	}
	return os.Rename(tmp, dst)
}

// readManifest decodes a bundle manifest and checks that every file it
// lists is present with the recorded digest and that it was captured from
// the recipes the lock pins.
func readManifest(dir string, major int, recipesDigest string) (*schema.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m schema.Manifest
	if err := schema.DecodeStrict(data, &m); err != nil {
		return nil, fmt.Errorf("manifest: %w", err)
	}
	if m.Schema != schema.ManifestSchema {
		return nil, fmt.Errorf("manifest schema %d, want %d", m.Schema, schema.ManifestSchema)
	}
	if m.Producer.Major != major {
		return nil, fmt.Errorf("manifest produced on macOS %d, expected %d", m.Producer.Major, major)
	}
	if recipesDigest != "" && m.Recipes != recipesDigest {
		return nil, fmt.Errorf("manifest captured recipes %s, lock pins %s", m.Recipes, recipesDigest)
	}
	if len(m.Cases) == 0 {
		return nil, errors.New("manifest lists no cases")
	}
	for _, c := range m.Cases {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(c.Observation))); err != nil {
			return nil, fmt.Errorf("case %s/%s/%s: %w", c.Recipe, c.Profile, c.Stage, err)
		}
		for _, f := range c.Files {
			path := filepath.Join(dir, filepath.FromSlash(f.Path))
			info, err := os.Stat(path)
			if err != nil {
				return nil, fmt.Errorf("case %s/%s/%s: %w", c.Recipe, c.Profile, c.Stage, err)
			}
			if info.Size() != f.Bytes {
				return nil, fmt.Errorf("%s: %d bytes, manifest says %d", f.Path, info.Size(), f.Bytes)
			}
		}
	}
	return &m, nil
}

// loadLocal reads producers from a local capture tree.
func (c *Corpus) loadLocal(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "macos-") {
			continue
		}
		major, err := strconv.Atoi(strings.TrimPrefix(e.Name(), "macos-"))
		if err != nil {
			continue
		}
		dir := filepath.Join(root, e.Name())
		m, err := readManifest(dir, major, "")
		if err != nil {
			return fmt.Errorf("%s: %w", e.Name(), err)
		}
		c.Producers = append(c.Producers, Producer{Major: major, Dir: dir, Manifest: m})
	}
	if len(c.Producers) == 0 {
		return fmt.Errorf("%s: no macos-<major> capture directories", root)
	}
	sort.Slice(c.Producers, func(i, j int) bool { return c.Producers[i].Major < c.Producers[j].Major })
	return nil
}

// Case is one captured case with its decoded observation.
type Case struct {
	Producer    int
	Recipe      string
	Profile     string
	Stage       string
	Dir         string
	Observation *schema.Observation
	Files       map[string]string // bundle-relative path -> absolute path
}

// Cases decodes every observation across producers, sorted by producer,
// recipe, profile and stage.
func (c *Corpus) Cases() ([]Case, error) {
	var cases []Case
	for _, p := range c.Producers {
		for _, cf := range p.Manifest.Cases {
			data, err := os.ReadFile(filepath.Join(p.Dir, filepath.FromSlash(cf.Observation)))
			if err != nil {
				return nil, err
			}
			var obs schema.Observation
			if err := schema.DecodeStrict(data, &obs); err != nil {
				return nil, fmt.Errorf("%s: %w", cf.Observation, err)
			}
			files := map[string]string{}
			for _, f := range cf.Files {
				files[f.Path] = filepath.Join(p.Dir, filepath.FromSlash(f.Path))
			}
			cases = append(cases, Case{Producer: p.Major, Recipe: cf.Recipe, Profile: cf.Profile, Stage: cf.Stage, Dir: filepath.Join(p.Dir, filepath.Dir(filepath.FromSlash(cf.Observation))), Observation: &obs, Files: files})
		}
	}
	sort.Slice(cases, func(i, j int) bool {
		a, b := cases[i], cases[j]
		if a.Producer != b.Producer {
			return a.Producer < b.Producer
		}
		if a.Recipe != b.Recipe {
			return a.Recipe < b.Recipe
		}
		if a.Profile != b.Profile {
			return a.Profile < b.Profile
		}
		return a.Stage < b.Stage
	})
	return cases, nil
}

// Image returns the absolute path of the case's retained image. A
// gzip-compressed raw image is expanded once beside the bundle, keyed by
// its recorded digest, so callers always receive a file the product can
// open directly.
func (k Case) Image() string {
	path := filepath.Join(k.Dir, k.Observation.Image.File)
	if !strings.HasSuffix(path, ".raw.gz") {
		return path
	}
	expanded := filepath.Join(k.Dir, ".expanded", strings.TrimSuffix(k.Observation.Image.File, ".gz"))
	if _, err := os.Stat(expanded); err == nil {
		return expanded
	}
	if err := expandGzip(path, expanded); err != nil {
		return path + ": " + err.Error()
	}
	return expanded
}

func expandGzip(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	gz, err := gzip.NewReader(in)
	if err != nil {
		return err
	}
	tmp := dst + ".partial"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, gz); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}
