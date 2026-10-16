package acceptance_test

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

type hfsGrowthFork struct {
	LogicalSize uint64       `json:"logicalSize"`
	ClumpSize   uint32       `json:"clumpSize"`
	TotalBlocks uint32       `json:"totalBlocks"`
	Extents     [8][2]uint32 `json:"extents"`
}

type hfsGrowthHeader struct {
	Signature          string                   `json:"signature"`
	Attributes         uint32                   `json:"attributes"`
	LastMountedVersion string                   `json:"lastMountedVersion"`
	Files              uint32                   `json:"files"`
	Directories        uint32                   `json:"directories"`
	BlockSize          uint32                   `json:"blockSize"`
	TotalBlocks        uint32                   `json:"totalBlocks"`
	FreeBlocks         uint32                   `json:"freeBlocks"`
	Forks              map[string]hfsGrowthFork `json:"forks"`
}

type hfsGrowthState struct {
	Image       string `json:"image"`
	ImageSHA256 string `json:"imageSHA256"`
	DiskSHA256  string `json:"diskSHA256"`
	Geometry    struct {
		DeviceBytes int64 `json:"deviceBytes"`
	} `json:"geometry"`
	Headers struct {
		Primary, Alternate hfsGrowthHeader
	} `json:"headers"`
	Checker struct {
		Status         int
		Stdout, Stderr string
	} `json:"checker"`
}

type hfsGrowthArchive struct {
	Image              string
	SHA256             string
	UncompressedSHA256 string
	UncompressedBytes  int64
}

type hfsSectorProbe struct {
	Capacity                                      int64
	Source, WrittenShadow, ReadOnlyShadow, Shadow hfsGrowthArchive
	After                                         struct{ Image, SHA256, DiskSHA256 string }
	AllWritesSurvived                             bool
	Markers                                       []struct {
		Offset, StoredShadowOffset, WritableStoredShadowOffset                   int64
		SHA256, SameAttachmentSHA256, ReattachedSHA256, WritableReattachedSHA256 string
	}
}

// TestNativeHFSCatalogGrowth replays retained native writes without mounting.
// Whole disk hashes bind the evidence; both headers expose stale alternates,
// while the production reader must recover the native-observed surviving tree,
// metadata, data and resource forks from every successful or failing state.
// A readable primary never turns a recorded native checker failure into a pass.
func TestNativeHFSCatalogGrowth(t *testing.T) {
	t.Parallel()
	root := nativeInput(t, "APFS_NATIVE_HFS_GROWTH", "testdata/hfs-header-growth")
	manifests, err := filepath.Glob(filepath.Join(root, "*", "manifest.json"))
	if err != nil || len(manifests) == 0 {
		t.Fatal("missing retained HFS growth evidence", root, err)
	}
	if len(manifests) != 3 {
		t.Fatal("exactly macOS 15, 26 and 27 references required")
	}
	seen := map[string]bool{}
	for _, manifest := range manifests {
		seen[filepath.Base(filepath.Dir(manifest))] = true
		t.Run(filepath.Base(filepath.Dir(manifest)), func(t *testing.T) {
			var evidence struct {
				Schema         int
				Scenario       string
				Complete       bool
				CommandsSHA256 string
				Producer       struct {
					System, Version, Build, Architecture, Run, Revision string
					Sources                                             []struct{ Source, SHA256 string }
				}
				Cases []struct {
					ID, Origin, Route, Filesystem string
					Capacity                      int64
					Before, Admitted, After       hfsGrowthState
					Files, ReadbackFiles          fileObservation
					Source, Shadow                hfsGrowthArchive
				}
				SectorProbes []hfsSectorProbe
				Retention    struct {
					Recipe, RecipeSHA256 string
					NativeCapture        hfsGrowthArchive
				}
			}
			data, err := os.ReadFile(manifest)
			if err != nil || len(data) > 16<<20 {
				t.Fatal("invalid growth manifest", err)
			}
			var index struct {
				Schema   int
				Scenario string
				Producer map[string]any
				Evidence hfsGrowthArchive
				Cases    []struct {
					ID                  string
					NativeCheckerStatus int
					CatalogBlocks       struct{ Before, PrimaryAfter, AlternateAfter uint32 }
				}
				SectorProbes []struct {
					Capacity               int64
					AllWritesSurvived      bool
					OmittedReadOnlyOffsets []int64
				}
			}
			if err = json.Unmarshal(data, &index); err != nil {
				t.Fatal(err)
			}
			if index.Scenario == "hfs-header-growth-reference" {
				archive := openGrowthArchive(t, filepath.Dir(manifest), index.Evidence)
				data, err = io.ReadAll(io.NewSectionReader(archive, 0, archive.Size()))
				if err != nil || len(data) > 16<<20 {
					t.Fatal("retained evidence document", err)
				}
			}
			if err = json.Unmarshal(data, &evidence); err != nil {
				t.Fatal(err)
			}
			if index.Scenario == "hfs-header-growth-reference" {
				var document struct{ Producer map[string]any }
				if err = json.Unmarshal(data, &document); err != nil {
					t.Fatal(err)
				}
				delete(document.Producer, "sources")
				if index.Schema != 1 || !reflect.DeepEqual(index.Producer, document.Producer) || len(index.Cases) != len(evidence.Cases) || len(index.SectorProbes) != len(evidence.SectorProbes) {
					t.Fatal("retained index is incomplete")
				}
				for i, c := range index.Cases {
					want := evidence.Cases[i]
					if c.ID != want.ID || c.NativeCheckerStatus != want.After.Checker.Status || c.CatalogBlocks.Before != want.Before.Headers.Primary.Forks["catalog"].TotalBlocks || c.CatalogBlocks.PrimaryAfter != want.After.Headers.Primary.Forks["catalog"].TotalBlocks || c.CatalogBlocks.AlternateAfter != want.After.Headers.Alternate.Forks["catalog"].TotalBlocks {
						t.Fatal("retained index changes native catalog growth or verdict")
					}
				}
				for i, p := range index.SectorProbes {
					want := evidence.SectorProbes[i]
					omitted := []int64{}
					for _, marker := range want.Markers {
						if marker.ReattachedSHA256 != marker.SHA256 {
							omitted = append(omitted, marker.Offset)
						}
					}
					if p.Capacity != want.Capacity || p.AllWritesSurvived != want.AllWritesSurvived || !reflect.DeepEqual(p.OmittedReadOnlyOffsets, omitted) {
						t.Fatal("retained index changes native sector replay")
					}
				}
			}
			p := evidence.Producer
			major := strings.Split(p.Version, ".")[0]
			if evidence.Schema != 1 || evidence.Scenario != "hfs-header-growth" || !evidence.Complete || p.System != "macOS" || p.Build == "" || p.Architecture == "" || p.Run == "" || len(p.Revision) != 40 || filepath.Base(filepath.Dir(manifest)) != "macos-"+major {
				t.Fatal("incomplete or duplicate native provenance")
			}
			dir := filepath.Dir(manifest)
			if len(p.Sources) != 6 || len(evidence.Cases) != 16 || len(evidence.SectorProbes) != 7 {
				t.Fatal("incomplete source/control inventory")
			}
			recipes := map[string]bool{"hfs_header_growth.py": false, "capture.py": false, "container_building.py": false, "image_repacking.py": false, "verify_preservation.py": false, "file_compression.py": false}
			for _, source := range p.Sources {
				if used, ok := recipes[source.Source]; !ok || used {
					t.Fatal("unknown or duplicate capture recipe")
				}
				recipes[source.Source] = true
				verifyDigest(t, dir, source.Source, source.SHA256)
			}
			verifyDigest(t, dir, "commands.json", evidence.CommandsSHA256)
			if evidence.Retention.Recipe != "" {
				verifyDigest(t, dir, evidence.Retention.Recipe, evidence.Retention.RecipeSHA256)
				original := openGrowthArchive(t, dir, evidence.Retention.NativeCapture)
				compareRetainedNativeManifest(t, original, data)
			}
			capacities := map[int64]bool{10936320: false, 10944512: false, 10960896: false, 10977280: false, 11010048: false, 11534336: false, 16777216: false}
			for _, probe := range evidence.SectorProbes {
				if used, ok := capacities[probe.Capacity]; !ok || used {
					t.Fatal("unknown or duplicate sector boundary control")
				}
				capacities[probe.Capacity] = true
				t.Run(fmt.Sprintf("unmounted-sectors-%d", probe.Capacity), func(t *testing.T) { compareSectorProbe(t, dir, probe) })
			}
			ids := map[string]bool{}
			for _, c := range evidence.Cases {
				t.Run(c.ID, func(t *testing.T) {
					if ids[c.ID] || c.ID != fmt.Sprintf("%s-%d-%s-%s", c.Filesystem, c.Capacity, c.Origin, c.Route) || (c.Origin != "apple" && c.Origin != "go") || (c.Route != "direct" && c.Route != "shadow") || (c.Filesystem != "hfsplus" && c.Filesystem != "hfsx") || (c.Capacity != 10936320 && c.Capacity != 16777216) {
						t.Fatal("invalid matched control")
					}
					ids[c.ID] = true
					verifyGrowthEnvelope(t, dir, c.Source, c.Before.DiskSHA256, c.Capacity)
					if c.Route == "shadow" {
						openGrowthArchive(t, dir, c.Shadow)
					}
					if c.Before.DiskSHA256 != c.Admitted.DiskSHA256 || c.Before.Geometry.DeviceBytes != c.Capacity || c.Admitted.Geometry.DeviceBytes != c.Capacity || c.Before.Checker.Status != 0 || c.Admitted.Checker.Status != 0 {
						t.Fatal("write route did not start with identical admitted sectors")
					}
					before := c.Before.Headers.Primary.Forks["catalog"]
					primary := c.After.Headers.Primary.Forks["catalog"]
					alternate := c.After.Headers.Alternate.Forks["catalog"]
					if primary.TotalBlocks <= before.TotalBlocks || len(c.Files.Entries) != 69 || !reflect.DeepEqual(c.Files, c.ReadbackFiles) {
						t.Fatal("missing actual catalog growth or independent remount observations")
					}
					if c.After.Checker.Status != 0 {
						if primary.TotalBlocks == alternate.TotalBlocks || !strings.Contains(c.After.Checker.Stdout+c.After.Checker.Stderr, "total blocks") {
							t.Fatal("unexplained retained checker failure")
						}
						t.Logf("retained native checker failure: primary catalog %d, alternate %d", primary.TotalBlocks, alternate.TotalBlocks)
					} else if !reflect.DeepEqual(primary, alternate) {
						t.Fatal("successful native check has disagreeing catalog geometry")
					}
					for _, state := range []hfsGrowthState{c.Before, c.Admitted, c.After} {
						source := openGrowthSnapshot(t, dir, state)
						for _, h := range []struct {
							offset int64
							want   hfsGrowthHeader
						}{{1024, state.Headers.Primary}, {source.Size() - 1024, state.Headers.Alternate}} {
							if got := readGrowthHeader(t, source, h.offset); !reflect.DeepEqual(got, h.want) {
								t.Fatalf("retained header differs at %d: got %+v want %+v", h.offset, got, h.want)
							}
						}
						if state.Image == c.After.Image {
							volume, err := hfsplus.Open(source)
							if err != nil {
								t.Fatal(err)
							}
							if volume.BlockSize != state.Headers.Primary.BlockSize || volume.BlockCount != state.Headers.Primary.TotalBlocks || volume.FreeBlocks != state.Headers.Primary.FreeBlocks || volume.CaseSensitive != (c.Filesystem == "hfsx") {
								t.Fatal("portable interpretation differs from native volume geometry")
							}
							compareFiles(t, volume, c.ReadbackFiles)
						}
						if state.Image == c.Before.Image && c.Origin == "apple" && c.Route == "direct" {
							compareGrowthConstruction(t, c.Before.Headers.Primary, c.Capacity, c.Filesystem == "hfsx")
						}
					}
				})
			}
		})
	}
	for _, major := range []string{"15", "26", "27"} {
		if !seen["macos-"+major] {
			t.Errorf("missing macOS %s retained HFS growth references", major)
		}
	}
}

func compareSectorProbe(t *testing.T, dir string, p hfsSectorProbe) {
	t.Helper()
	if p.Capacity < 8<<20 || p.Capacity > 16<<20 || len(p.Markers) < 4 {
		t.Fatal("incomplete unmounted sector control")
	}
	source := openGrowthArchive(t, dir, p.Source)
	image, err := diskimage.New(source)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	disk, err := image.Partition(0)
	if err != nil || disk.Size() != p.Capacity {
		t.Fatal("sector control geometry", err)
	}
	after := openGrowthSnapshot(t, dir, hfsGrowthState{Image: p.After.Image, ImageSHA256: p.After.SHA256, DiskSHA256: p.After.DiskSHA256, Geometry: struct {
		DeviceBytes int64 `json:"deviceBytes"`
	}{p.Capacity}})
	written := openGrowthArchive(t, dir, p.WrittenShadow)
	openGrowthArchive(t, dir, p.ReadOnlyShadow)
	final := openGrowthArchive(t, dir, p.Shadow)
	survived := true
	for _, m := range p.Markers {
		if m.Offset < 0 || m.Offset > p.Capacity-512 || m.SHA256 != m.SameAttachmentSHA256 {
			t.Fatal("unacknowledged or invalid native sector write")
		}
		if m.WritableReattachedSHA256 != m.SHA256 && m.WritableReattachedSHA256 != growthSectorDigest(t, disk, m.Offset) {
			t.Fatal("unexplained writable reattachment result")
		}
		if got := growthSectorDigest(t, after, m.Offset); got != m.ReattachedSHA256 {
			t.Fatal("retained reopened sector differs from native readback")
		}
		if m.StoredShadowOffset >= 0 && growthSectorDigest(t, written, m.StoredShadowOffset) != m.SHA256 {
			t.Fatal("retained shadow lacks acknowledged write")
		}
		if m.WritableStoredShadowOffset >= 0 && growthSectorDigest(t, final, m.WritableStoredShadowOffset) != m.SHA256 {
			t.Fatal("retained writable shadow differs")
		}
		if m.ReattachedSHA256 != m.SHA256 {
			survived = false
			if m.ReattachedSHA256 != growthSectorDigest(t, disk, m.Offset) {
				t.Fatal("omitted write did not expose original sector")
			}
			t.Logf("native shadow replay omitted sector at %d; write retained at shadow offset %d", m.Offset, m.StoredShadowOffset)
		}
	}
	if survived != p.AllWritesSurvived {
		t.Fatal("native persistence verdict differs from retained sectors")
	}
}

func compareRetainedNativeManifest(t *testing.T, source block.Source, retained []byte) {
	t.Helper()
	decode := func(r io.Reader) any {
		d := json.NewDecoder(r)
		d.UseNumber()
		var value any
		if err := d.Decode(&value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	original := decode(io.NewSectionReader(source, 0, source.Size()))
	canonical := decode(strings.NewReader(string(retained)))
	delete(canonical.(map[string]any), "retention")
	var normalize func(any)
	normalize = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			// Retention can share only archive filenames; every hash, observation,
			// command verdict, nanosecond and provenance field remains exact.
			if _, ok := value["imageSHA256"]; ok {
				delete(value, "image")
			}
			if _, ok := value["sha256"]; ok {
				delete(value, "image")
			}
			for _, child := range value {
				normalize(child)
			}
		case []any:
			for _, child := range value {
				normalize(child)
			}
		}
	}
	normalize(original)
	normalize(canonical)
	if !reflect.DeepEqual(original, canonical) {
		t.Fatal("retention changed original native expectations or provenance")
	}
}

func growthSectorDigest(t *testing.T, source block.Source, offset int64) string {
	t.Helper()
	data := make([]byte, 512)
	if err := block.ReadFull(source, data, offset); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func verifyGrowthEnvelope(t *testing.T, dir string, archive hfsGrowthArchive, want string, size int64) {
	t.Helper()
	source := openGrowthArchive(t, dir, archive)
	image, err := diskimage.New(source)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	disk, err := image.Partition(0)
	if err != nil || disk.Size() != size {
		t.Fatal("retained envelope device size", err)
	}
	digest := sha256.New()
	if _, err = io.Copy(digest, io.NewSectionReader(disk, 0, disk.Size())); err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(digest.Sum(nil)) != want {
		t.Fatal("portable UDIF interpretation differs from native complete disk hash")
	}
}

func openGrowthArchive(t *testing.T, dir string, archive hfsGrowthArchive) *block.File {
	t.Helper()
	verifyDigest(t, dir, archive.Image, archive.SHA256)
	input, err := os.Open(filepath.Join(dir, archive.Image))
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	z, err := gzip.NewReader(input)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	path := filepath.Join(t.TempDir(), "retained.bin")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, digest), io.LimitReader(z, (32<<20)+1))
	closeErr := out.Close()
	if err != nil || closeErr != nil || n == 0 || n > 32<<20 || (archive.UncompressedBytes != 0 && n != archive.UncompressedBytes) || hex.EncodeToString(digest.Sum(nil)) != archive.UncompressedSHA256 {
		t.Fatal("retained archive integrity", n, err, closeErr)
	}
	source, err := block.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	return source
}

// Apple's freshly formatted empty volumes independently supply the system-fork
// geometry and implementation identifier for the same construction options.
func compareGrowthConstruction(t *testing.T, native hfsGrowthHeader, capacity int64, sensitive bool) {
	t.Helper()
	ctx := context.Background()
	clock := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
	r, err := session.Create(ctx, filepath.Join(t.TempDir(), "empty-session"), session.Options{Names: filesystem.NameRules{Format: "HFS+", CaseSensitive: sensitive, NormalizationInsensitive: true}, Time: &clock})
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	plan, err := hfsplus.Plan(ctx, r, hfsplus.BuildOptions{Name: "Growth", Capacity: capacity, CaseSensitive: sensitive, Time: clock})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "built.raw")
	out, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	err = plan.Write(ctx, out)
	closeErr := out.Close()
	if err != nil || closeErr != nil {
		t.Fatal(err, closeErr)
	}
	built, err := block.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer built.Close()
	h := readGrowthHeader(t, built, 1024)
	if h.LastMountedVersion != native.LastMountedVersion || h.BlockSize != native.BlockSize || h.TotalBlocks != native.TotalBlocks || h.Signature != native.Signature {
		t.Fatalf("construction differs from Apple format: got %+v want %+v", h, native)
	}
	for _, name := range []string{"allocation", "catalog", "extents", "attributes"} {
		got, want := h.Forks[name], native.Forks[name]
		if got.TotalBlocks != want.TotalBlocks || got.ClumpSize != want.ClumpSize || got.LogicalSize != want.LogicalSize {
			t.Fatalf("%s initial geometry differs from Apple format: got %+v want %+v", name, got, want)
		}
	}
}

func openGrowthSnapshot(t *testing.T, dir string, state hfsGrowthState) *block.File {
	t.Helper()
	if state.Geometry.DeviceBytes < 8<<20 || state.Geometry.DeviceBytes > 16<<20 || len(state.DiskSHA256) != 64 {
		t.Fatal("invalid retained device bounds")
	}
	return openGrowthArchive(t, dir, hfsGrowthArchive{Image: state.Image, SHA256: state.ImageSHA256, UncompressedSHA256: state.DiskSHA256, UncompressedBytes: state.Geometry.DeviceBytes})
}

func readGrowthHeader(t *testing.T, source block.Source, offset int64) hfsGrowthHeader {
	t.Helper()
	raw := make([]byte, 512)
	if err := block.ReadFull(source, raw, offset); err != nil {
		t.Fatal(err)
	}
	be := binary.BigEndian
	h := hfsGrowthHeader{Signature: string(raw[:2]), Attributes: be.Uint32(raw[4:]), LastMountedVersion: string(raw[8:12]), Files: be.Uint32(raw[32:]), Directories: be.Uint32(raw[36:]), BlockSize: be.Uint32(raw[40:]), TotalBlocks: be.Uint32(raw[44:]), FreeBlocks: be.Uint32(raw[48:]), Forks: map[string]hfsGrowthFork{}}
	for name, offset := range map[string]int{"allocation": 112, "extents": 192, "catalog": 272, "attributes": 352, "startup": 432} {
		f := hfsGrowthFork{LogicalSize: be.Uint64(raw[offset:]), ClumpSize: be.Uint32(raw[offset+8:]), TotalBlocks: be.Uint32(raw[offset+12:])}
		for i := range f.Extents {
			f.Extents[i] = [2]uint32{be.Uint32(raw[offset+16+i*8:]), be.Uint32(raw[offset+20+i*8:])}
		}
		h.Forks[name] = f
	}
	return h
}
