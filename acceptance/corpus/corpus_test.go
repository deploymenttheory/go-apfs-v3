package corpus

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// buildBundle writes a minimal capture tree for one producer and packs it.
func buildBundle(t *testing.T, major int, recipes string) (string, string, int64) {
	t.Helper()
	tree := t.TempDir()
	caseDir := filepath.Join(tree, "file-corpus")
	if err := os.MkdirAll(caseDir, 0o755); err != nil {
		t.Fatal(err)
	}
	obs := schema.Observation{Schema: 1, Recipe: "file-corpus", Profile: "apfs", Stage: "final", Image: schema.Image{File: "apfs.final.dmg"}}
	data, _ := json.Marshal(obs)
	if err := os.WriteFile(filepath.Join(caseDir, "apfs.final.observation.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(caseDir, "apfs.final.dmg"), []byte("image bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fixture.WriteManifest(tree, schema.Producer{Major: major, Version: "27.0.1"}, recipes); err != nil {
		t.Fatal(err)
	}
	path, sum, size, err := fixture.WriteBundle(tree, major, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return path, sum, size
}

func writeLock(t *testing.T, dir string, lock schema.Lock) string {
	t.Helper()
	path := filepath.Join(dir, "fixtures.lock.json")
	data, _ := json.Marshal(lock)
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveDownloadsVerifiesExtractsAndCaches(t *testing.T) {
	recipes := strings.Repeat("ab", 32)
	bundles := map[string]schema.Bundle{}
	files := map[string]string{}
	for _, major := range schema.Producers {
		path, sum, size := buildBundle(t, major, recipes)
		name := filepath.Base(path)
		bundles["macos-"+itoa(major)] = schema.Bundle{Asset: name, SHA256: sum, Bytes: size, Build: "b", CaptureRun: "r"}
		files[name] = path
	}
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		name := filepath.Base(r.URL.Path)
		http.ServeFile(w, r, files[name])
	}))
	defer server.Close()
	lock := schema.Lock{Schema: 1, Release: "fixtures/2026.10.18", RecipesSHA256: recipes, Bundles: bundles}
	lockPath := writeLock(t, t.TempDir(), lock)
	cache := t.TempDir()
	opts := Options{LockPath: lockPath, CacheDir: cache, Repository: "x/y", Client: redirecting(server.URL)}
	c, err := Resolve(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Producers) != 3 || hits != 3 {
		t.Fatalf("producers %d hits %d", len(c.Producers), hits)
	}
	cases, err := c.Cases()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 3 || cases[0].Producer != 15 || cases[0].Observation.Image.File == "" {
		t.Fatalf("cases %+v", cases)
	}
	if _, err := Resolve(context.Background(), opts); err != nil || hits != 3 {
		t.Fatalf("second resolve should use the cache: err=%v hits=%d", err, hits)
	}
}

func TestResolveRejectsTamperedOrMissingBundles(t *testing.T) {
	recipes := strings.Repeat("ab", 32)
	good := map[string]schema.Bundle{}
	files := map[string]string{}
	for _, major := range schema.Producers {
		path, sum, size := buildBundle(t, major, recipes)
		good["macos-"+itoa(major)] = schema.Bundle{Asset: filepath.Base(path), SHA256: sum, Bytes: size, Build: "b", CaptureRun: "r"}
		files[filepath.Base(path)] = path
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := filepath.Base(r.URL.Path)
		if files[name] == "" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, files[name])
	}))
	defer server.Close()
	base := func(assets map[string]schema.Bundle) Options {
		lock := schema.Lock{Schema: 1, Release: "r", RecipesSHA256: recipes, Bundles: assets}
		return Options{LockPath: writeLock(t, t.TempDir(), lock), CacheDir: t.TempDir(), Repository: "x/y", Client: redirecting(server.URL)}
	}
	with := func(key string, b schema.Bundle) map[string]schema.Bundle {
		out := map[string]schema.Bundle{}
		for k, v := range good {
			out[k] = v
		}
		out[key] = b
		return out
	}
	swapped := with("macos-15", good["macos-27"])
	if _, err := Resolve(context.Background(), base(swapped)); err == nil || !strings.Contains(err.Error(), "produced on macOS 27, expected 15") {
		t.Fatalf("producer mismatch not detected: %v", err)
	}
	wrongDigest := good["macos-27"]
	wrongDigest.SHA256 = strings.Repeat("00", 32)
	if _, err := Resolve(context.Background(), base(with("macos-27", wrongDigest))); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("digest mismatch not detected: %v", err)
	}
	missing := good["macos-15"]
	missing.Asset = "missing.tar.gz"
	if _, err := Resolve(context.Background(), base(with("macos-15", missing))); err == nil || !strings.Contains(err.Error(), "HTTP 404") {
		t.Fatalf("missing asset not detected: %v", err)
	}
	if _, err := Resolve(context.Background(), base(map[string]schema.Bundle{"macos-27": good["macos-27"]})); err == nil || !strings.Contains(err.Error(), "no bundle for macos-15") {
		t.Fatalf("missing producer not detected: %v", err)
	}
	recipeChanged := schema.Lock{Schema: 1, Release: "r", RecipesSHA256: strings.Repeat("cd", 32), Bundles: good}
	if _, err := Resolve(context.Background(), Options{LockPath: writeLock(t, t.TempDir(), recipeChanged), CacheDir: t.TempDir(), Repository: "x/y", Client: redirecting(server.URL)}); err == nil || !strings.Contains(err.Error(), "captured recipes") {
		t.Fatalf("recipe digest mismatch not detected: %v", err)
	}
	empty := schema.Lock{Schema: 1, RecipesSHA256: recipes, Bundles: map[string]schema.Bundle{}}
	if _, err := Resolve(context.Background(), Options{LockPath: writeLock(t, t.TempDir(), empty), CacheDir: t.TempDir()}); err == nil || !strings.Contains(err.Error(), "pins no bundles") {
		t.Fatalf("empty lock not reported: %v", err)
	}
}

func TestResolveUsesLocalCaptureOverride(t *testing.T) {
	recipes := strings.Repeat("ab", 32)
	root := t.TempDir()
	path, _, _ := buildBundle(t, 27, recipes)
	dir := filepath.Join(root, "macos-27")
	if err := fixture.ExtractBundle(path, dir, MaxBundleBytes); err != nil {
		t.Fatal(err)
	}
	lock := schema.Lock{Schema: 1, RecipesSHA256: recipes, Bundles: map[string]schema.Bundle{}}
	c, err := Resolve(context.Background(), Options{LockPath: writeLock(t, t.TempDir(), lock), CacheDir: t.TempDir(), LocalDir: root})
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Producers) != 1 || c.Producers[0].Major != 27 {
		t.Fatalf("local producers %+v", c.Producers)
	}
	if err := os.Remove(filepath.Join(dir, "file-corpus", "apfs.final.dmg")); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(context.Background(), Options{LockPath: writeLock(t, t.TempDir(), lock), CacheDir: t.TempDir(), LocalDir: root}); err == nil {
		t.Fatal("missing case file not detected")
	}
}

// redirecting routes github.com release URLs to the test server.
func redirecting(base string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r.URL.Scheme = "http"
		r.URL.Host = strings.TrimPrefix(base, "http://")
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func itoa(n int) string { // two-digit majors only
	return strings.TrimSpace(strings.ReplaceAll(string(rune('0'+n/10))+string(rune('0'+n%10)), " ", ""))
}
