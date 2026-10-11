package acceptance_test

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/pack"
)

// TestNativeImageRepacking compares every logical disk byte with a hash read
// directly from Apple's attached device. Actual outputs return to every Mac for
// native checksum checks, disk hashes, volume/snapshot readback and signatures.
func TestNativeImageRepacking(t *testing.T) {
	t.Parallel()
	root := os.Getenv("APFS_NATIVE_REPACKING")
	if root == "" {
		root = "testdata/image-repacking"
	}
	manifests, err := filepath.Glob(filepath.Join(root, "*", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) == 0 {
		t.Fatal("missing native repacking references", root)
	}
	seen := map[string]bool{}
	for _, path := range manifests {
		t.Run(filepath.Base(filepath.Dir(path)), func(t *testing.T) {
			dir := filepath.Dir(path)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			var c struct {
				corpus
				Rejections []struct {
					ID     string `json:"id"`
					Image  string `json:"image"`
					SHA256 string `json:"sha256"`
				} `json:"rejections"`
			}
			if err = json.Unmarshal(data, &c); err != nil {
				t.Fatal(err)
			}
			if c.Schema != 1 || c.Scenario != "image-repacking" || c.Producer.System != "macOS" || c.Producer.Build == "" {
				t.Fatal("invalid provenance")
			}
			major := strings.Split(c.Producer.Version, ".")[0]
			if (major != "15" && major != "26" && major != "27") || seen[major] {
				t.Fatal("invalid or duplicate producer", major)
			}
			seen[major] = true
			verifyDigest(t, dir, c.Producer.Source, c.Producer.SourceSHA256)
			if len(c.Producer.Sources) < 5 {
				t.Fatal("missing source provenance")
			}
			for _, s := range c.Producer.Sources {
				verifyDigest(t, dir, s.Source, s.SHA256)
			}
			cases := map[string]bool{"hfsplus-gpt": false, "hfsx-apm-raw": false, "hfsplus-bare": false, "apfs-snapshots": false, "apfs-volumes": false}
			if len(c.Cases) != len(cases) {
				t.Fatal("incomplete repacking inventory")
			}
			rejections := map[string]bool{"signed-container": false, "encrypted-container": false}
			if len(c.Rejections) != len(rejections) {
				t.Fatal("missing native rejection controls")
			}
			for _, r := range c.Rejections {
				if seen, ok := rejections[r.ID]; !ok || seen {
					t.Fatal("invalid rejection control", r.ID)
				}
				rejections[r.ID] = true
				verifyDigest(t, dir, r.Image, r.SHA256)
				destination := filepath.Join(t.TempDir(), "refused.dmg")
				if _, err := pack.Repack(context.Background(), filepath.Join(dir, r.Image), destination, "UDZO"); !errors.Is(err, filesystem.ErrUnsupported) {
					t.Fatalf("%s: expected refusal, got %v", r.ID, err)
				}
				if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("refused input published output", r.ID, err)
				}
				verifyDigest(t, dir, r.Image, r.SHA256)
			}
			for _, v := range c.Cases {
				id := strings.TrimPrefix(v.ID, "image-repacking/")
				if exists, ok := cases[id]; !ok || exists {
					t.Fatal("invalid case", v.ID)
				}
				cases[id] = true
				t.Run(id, func(t *testing.T) {
					verifyDigest(t, dir, v.Image, v.SHA256)
					verifyDigest(t, dir, v.Observation, v.ObservationSHA256)
					data, err := os.ReadFile(filepath.Join(dir, v.Observation))
					if err != nil {
						t.Fatal(err)
					}
					var native struct {
						DiskBytes  int64             `json:"diskBytes"`
						DiskSHA256 string            `json:"diskSHA256"`
						Markers    []json.RawMessage `json:"markers"`
						Volumes    []struct {
							Encrypted bool              `json:"encrypted"`
							Signature bool              `json:"signatureVerified"`
							Snapshots []json.RawMessage `json:"snapshots"`
						} `json:"volumes"`
					}
					if err = json.Unmarshal(data, &native); err != nil {
						t.Fatal(err)
					}
					if native.DiskBytes <= 0 || len(native.DiskSHA256) != 64 || len(native.Volumes) == 0 {
						t.Fatal("incomplete native observation")
					}
					switch id {
					case "hfsx-apm-raw":
						if len(native.Markers) == 0 {
							t.Fatal("missing unused-sector control")
						}
					case "hfsplus-gpt":
						if !native.Volumes[0].Signature {
							t.Fatal("missing native signature verification")
						}
					case "apfs-snapshots":
						if len(native.Volumes[0].Snapshots) != 2 {
							t.Fatal("missing retained historical states")
						}
					case "apfs-volumes":
						if len(native.Volumes) != 2 {
							t.Fatal("missing multiple volumes")
						}
						if native.Volumes[0].Encrypted == native.Volumes[1].Encrypted {
							t.Fatal("missing encrypted and ordinary volume controls")
						}
					}
					source := filepath.Join(dir, v.Image)
					if strings.HasSuffix(source, ".gz") {
						f, err := os.Open(source)
						if err != nil {
							t.Fatal(err)
						}
						defer f.Close()
						z, err := gzip.NewReader(f)
						if err != nil {
							t.Fatal(err)
						}
						defer z.Close()
						source = filepath.Join(t.TempDir(), "native.raw")
						out, err := os.Create(source)
						if err != nil {
							t.Fatal(err)
						}
						n, err := io.Copy(out, io.LimitReader(z, native.DiskBytes+1))
						closeErr := out.Close()
						if err != nil || closeErr != nil || n != native.DiskBytes {
							t.Fatal("invalid retained raw storage", n, err, closeErr)
						}
					}
					output := os.Getenv("APFS_REPACKING_OUTPUT")
					if output == "" {
						output = t.TempDir()
					}
					output = filepath.Join(output, "macos-"+major, id)
					if err = os.MkdirAll(output, 0700); err != nil {
						t.Fatal(err)
					}
					for _, format := range []string{"UDRO", "UDZO"} {
						t.Run(format, func(t *testing.T) {
							destination := filepath.Join(output, format+".dmg")
							report, err := pack.Repack(context.Background(), source, destination, format)
							if err != nil {
								t.Fatal(err)
							}
							if report.DiskBytes != native.DiskBytes || report.DiskSHA256 != native.DiskSHA256 {
								t.Fatalf("native disk differs: %+v", report)
							}
							repeat := filepath.Join(t.TempDir(), "repeat.dmg")
							if _, err = pack.Repack(context.Background(), source, repeat, format); err != nil {
								t.Fatal(err)
							}
							if fileDigest(t, destination) != fileDigest(t, repeat) {
								t.Fatal("repacking is not reproducible")
							}
							buildEncryptedOutput(t, destination, encryptedRepackBits(id, format), func(path string, encryption *diskimage.EncryptionOptions) error {
								r, err := pack.RepackWithOptions(context.Background(), source, path, diskimage.RepackOptions{Format: format, Encryption: encryption})
								if err == nil && (r.DiskSHA256 != native.DiskSHA256 || r.DiskBytes != native.DiskBytes) {
									t.Fatal("encryption changed native disk sectors")
								}
								return err
							})
							t.Logf("preserved every native disk sector: %d bytes; %s", report.DiskBytes, report.DiskSHA256)
						})
					}
					if id == "hfsplus-gpt" {
						// Apple encrypted this exact disk with the public corpus password.
						// The legacy credential-free refusal above remains a separate control.
						for _, r := range c.Rejections {
							if r.ID == "encrypted-container" {
								repackEncryptedInput(t, filepath.Join(dir, r.Image), output, native.DiskBytes, native.DiskSHA256)
								verifyDigest(t, dir, r.Image, r.SHA256)
							}
						}
					}
					verifyDigest(t, dir, v.Image, v.SHA256)
				})
			}
			repackNativeRawEncrypted(t, major)
		})
	}
	if required := os.Getenv("APFS_REQUIRED_NATIVE_MAJORS"); required != "" {
		for _, major := range strings.Split(required, ",") {
			if !seen[major] {
				t.Error("missing required native producer", major)
			}
		}
	}
}
