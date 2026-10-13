package acceptance_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

// TestNativeVolumeInspection establishes that independent diskutil observations
// match v3's decoding of genuine native images. It does not qualify file reads.
func TestNativeVolumeInspection(t *testing.T) {
	t.Parallel()
	root := os.Getenv("APFS_NATIVE_CORPUS")
	if root == "" {
		root = "testdata/native"
	}
	manifests, err := filepath.Glob(filepath.Join(root, "*", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "manifest.json")); err == nil {
		manifests = append(manifests, filepath.Join(root, "manifest.json"))
	}
	if len(manifests) == 0 {
		t.Fatalf("no native corpus at %s; run acceptance/native/capture.py or restore the retained fixtures", root)
	}
	profiles := map[string]bool{}
	for _, path := range manifests {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			major := replay(t, path)
			if profiles[major] {
				t.Fatalf("duplicate producer for macOS %s", major)
			}
			profiles[major] = true
		})
	}
	if required := os.Getenv("APFS_REQUIRED_NATIVE_MAJORS"); required != "" {
		for _, major := range strings.Split(required, ",") {
			if !profiles[major] {
				t.Errorf("required native macOS %s producer is absent or failed", major)
			}
		}
	}
}

type observation struct {
	Filesystem    string `json:"filesystem"`
	Name          string `json:"name"`
	CaseSensitive bool   `json:"caseSensitive"`
	UUID          string `json:"uuid,omitempty"`
	BlockSize     uint32 `json:"blockSize"`
	Size          uint64 `json:"size"`
}

type corpus struct {
	Cryptography       string `json:"cryptography,omitempty"`
	CryptographySHA256 string `json:"cryptographySHA256,omitempty"`
	Schema             int    `json:"schema"`
	Scenario           string `json:"scenario"`
	Producer           struct {
		System       string `json:"system"`
		Version      string `json:"version"`
		Build        string `json:"build"`
		Architecture string `json:"architecture"`
		Source       string `json:"source"`
		SourceSHA256 string `json:"sourceSHA256"`
		Sources      []struct {
			Source string `json:"source"`
			SHA256 string `json:"sha256"`
		} `json:"sources,omitempty"`
	} `json:"producer"`
	Cases []struct {
		ID                string      `json:"id"`
		Image             string      `json:"image"`
		SHA256            string      `json:"sha256"`
		Observation       string      `json:"observation"`
		ObservationSHA256 string      `json:"observationSHA256"`
		Expected          observation `json:"expected"`
		Files             string      `json:"files,omitempty"`
		FilesSHA256       string      `json:"filesSHA256,omitempty"`
	} `json:"cases"`
}

func replay(t *testing.T, path string) string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var c corpus
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if err := d.Decode(&c); err != nil {
		t.Fatal(err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		t.Fatal("manifest must contain exactly one JSON document")
	}
	if c.Schema != 1 || c.Scenario != "volume-inspection" || c.Producer.System != "macOS" || c.Producer.Build == "" || c.Producer.Architecture == "" {
		t.Fatal("invalid corpus provenance")
	}
	major := strings.Split(c.Producer.Version, ".")[0]
	if major != "15" && major != "26" && major != "27" {
		t.Fatal("unexpected native profile", c.Producer.Version)
	}
	dir := filepath.Dir(path)
	verifyDigest(t, dir, c.Producer.Source, c.Producer.SourceSHA256)
	wantIDs := map[string]bool{"volume-inspection/apfs": false, "volume-inspection/apfs-case-sensitive": false, "volume-inspection/hfsplus": false, "volume-inspection/hfsx": false}
	if len(c.Cases) != len(wantIDs) {
		t.Fatal("incomplete native case inventory")
	}
	for _, v := range c.Cases {
		seen, known := wantIDs[v.ID]
		if !known || seen {
			t.Fatal("unknown or duplicate case", v.ID)
		}
		wantIDs[v.ID] = true
		t.Run(v.ID, func(t *testing.T) {
			verifyDigest(t, dir, v.Observation, v.ObservationSHA256)
			verifyDigest(t, dir, v.Image, v.SHA256)
			img, err := diskimage.Open(filepath.Join(dir, v.Image))
			if err != nil {
				t.Fatal(err)
			}
			r, err := inspect.Image(context.Background(), img)
			closeErr := img.Close()
			if err != nil {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			var got []observation
			for _, p := range r.Partitions {
				if p.APFS != nil {
					for _, vol := range p.APFS.Volumes {
						got = append(got, observation{Filesystem: "APFS", Name: vol.Name, CaseSensitive: vol.CaseSensitive, UUID: vol.UUID, BlockSize: p.APFS.BlockSize, Size: p.APFS.BlockCount * uint64(p.APFS.BlockSize)})
					}
				}
				if p.HFSPlus != nil {
					vol := p.HFSPlus
					got = append(got, observation{Filesystem: vol.Format, Name: vol.Name, CaseSensitive: vol.CaseSensitive, BlockSize: vol.BlockSize, Size: uint64(vol.BlockCount) * uint64(vol.BlockSize)})
				}
			}
			if !reflect.DeepEqual(got, []observation{v.Expected}) {
				t.Fatalf("native observation mismatch\nwant: %+v\n got: %+v", v.Expected, got)
			}
			verifyDigest(t, dir, v.Image, v.SHA256)
			t.Logf("%s: matched independent diskutil observation from macOS %s (%s); source SHA-256 unchanged", v.ID, c.Producer.Version, c.Producer.Build)
		})
	}
	return major
}

func verifyDigest(t *testing.T, dir, name, want string) {
	t.Helper()
	if err := checkDigest(dir, name, want); err != nil {
		t.Fatal(err)
	}
}

func checkDigest(dir, name, want string) error {
	if name == "" || name != filepath.Base(name) || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return fmt.Errorf("unsafe corpus filename %q", name)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	f, err := root.Open(name)
	if errors.Is(err, os.ErrNotExist) {
		return checkCompressedDigest(root, name, want, 32<<20)
	}
	if err != nil {
		return err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("digest mismatch for %s: want %s, got %s", name, want, got)
	}
	return nil
}

// Historical text evidence is stored compressed, without rewriting captured
// bytes. Manifest digests always describe the original decoded content. Image
// archives retain their separate compressed and decoded disk digests.
func checkCompressedDigest(root *os.Root, name, want string, bound int64) error {
	f, err := root.Open(name + ".gz")
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Size() > bound {
		return fmt.Errorf("compressed evidence exceeds bound: %s", name)
	}
	z, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer z.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(z, bound+1))
	if err != nil {
		return err
	}
	if n > bound {
		return fmt.Errorf("decoded evidence exceeds bound: %s", name)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("digest mismatch for %s: want %s, got %s", name, want, got)
	}
	return nil
}

func TestCorpusRejectsMissingAndChangedEvidence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "evidence"), []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte("original"))
	digest := hex.EncodeToString(sum[:])
	if err := checkDigest(dir, "evidence", digest); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "../evidence", "nested/evidence", "nested\\evidence"} {
		if err := checkDigest(dir, name, digest); err == nil {
			t.Fatalf("accepted %q", name)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "evidence"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkDigest(dir, "evidence", digest); err == nil {
		t.Fatal("accepted changed evidence")
	}

	// Compression must preserve the original evidence digest and still reject
	// altered or truncated captures, including a decoded size over the bound.
	var archived bytes.Buffer
	z := gzip.NewWriter(&archived)
	if _, err := z.Write([]byte("original")); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "capture.gz")
	if err := os.WriteFile(path, archived.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkDigest(dir, "capture", digest); err != nil {
		t.Fatal(err)
	}
	if err := checkDigest(dir, "capture", strings.Repeat("0", 64)); err == nil {
		t.Fatal("accepted wrong decoded evidence digest")
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := checkCompressedDigest(root, "capture", digest, 4); err == nil {
		t.Fatal("accepted oversized stored evidence")
	}
	if err := os.WriteFile(path, archived.Bytes()[:archived.Len()-4], 0600); err != nil {
		t.Fatal(err)
	}
	if err := checkDigest(dir, "capture", digest); err == nil {
		t.Fatal("accepted truncated compressed evidence")
	}
	archived.Reset()
	z = gzip.NewWriter(&archived)
	large := bytes.Repeat([]byte("a"), 1024)
	if _, err := z.Write(large); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, archived.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	sum = sha256.Sum256(large)
	if err := checkCompressedDigest(root, "capture", hex.EncodeToString(sum[:]), 128); err == nil {
		t.Fatal("accepted oversized decoded evidence")
	}
}
