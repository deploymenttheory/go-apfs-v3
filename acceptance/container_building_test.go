package acceptance_test

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

type containerObservation struct {
	Size          int64  `json:"size"`
	ContainerUUID string `json:"containerUUID"`
	Allocation    struct {
		IndependentWritesAndReuse bool
		Quota, Reserve            *struct {
			Errno        int
			WrittenBytes int64
		}
	}
	Volumes []struct {
		Name, UUID, Group string
		Sensitive, Empty  bool
		Roles             []string
		Reserve, Quota    int64
		Files             fileObservation
	} `json:"volumes"`
}

// TestNativeContainerBuilding extends the image-building family with shared
// allocation, mixed case policies and native System/Data group identities.
func TestNativeContainerBuilding(t *testing.T) {
	root := os.Getenv("APFS_NATIVE_IMAGE_BUILDING")
	if root == "" {
		root = "testdata/image-building"
	}
	manifests, err := filepath.Glob(filepath.Join(root, "*", "containers", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) == 0 {
		t.Fatal("missing native container-building references")
	}
	profiles := map[string]bool{}
	for _, manifest := range manifests {
		t.Run(filepath.Base(filepath.Dir(filepath.Dir(manifest))), func(t *testing.T) {
			var c struct {
				Schema   int
				Scenario string
				Producer struct{ System, Version, Build, Architecture string }
				Sources  []struct{ Source, SHA256 string }
				Cases    []struct{ ID, Image, SHA256, Observation, ObservationSHA256, Groups, GroupsSHA256, Inventory, InventorySHA256 string }
			}
			decodeEvidence(t, manifest, &c)
			major := strings.Split(c.Producer.Version, ".")[0]
			if c.Schema != 1 || c.Scenario != "image-building/containers" || c.Producer.System != "macOS" || c.Producer.Build == "" || c.Producer.Architecture == "" || (major != "15" && major != "26" && major != "27") || profiles[major] {
				t.Fatal("invalid native container provenance")
			}
			profiles[major] = true
			required := []string{"container_building.py", "capture.py", "image_building.py", "file_compression.py", "preservation.py", "metadata_edits.py", "content_replacement.py"}
			if len(c.Sources) != len(required) || len(c.Cases) != 2 {
				t.Fatal("incomplete native cases or source provenance")
			}
			dir := filepath.Dir(manifest)
			for i, s := range c.Sources {
				if s.Source != required[i] {
					t.Fatal("wrong capture source")
				}
				verifyDigest(t, dir, s.Source, s.SHA256)
			}
			seen := map[string]bool{}
			for _, tc := range c.Cases {
				if (tc.ID != "shared" && tc.ID != "group") || seen[tc.ID] {
					t.Fatal("wrong container case inventory")
				}
				seen[tc.ID] = true
				for _, item := range [][2]string{{tc.Image, tc.SHA256}, {tc.Observation, tc.ObservationSHA256}, {tc.Groups, tc.GroupsSHA256}, {tc.Inventory, tc.InventorySHA256}} {
					verifyDigest(t, dir, item[0], item[1])
				}
				t.Run(tc.ID, func(t *testing.T) {
					var want containerObservation
					decodeEvidence(t, filepath.Join(dir, tc.Observation), &want)
					buildNativeContainer(t, filepath.Join(dir, tc.Image), want, major, tc.ID)
				})
			}
		})
	}
	if required := os.Getenv("APFS_REQUIRED_NATIVE_MAJORS"); required != "" {
		for _, major := range strings.Split(required, ",") {
			if major != "" && !profiles[major] {
				t.Fatal("missing producer", major)
			}
		}
	}
}

func nativeUUID(t *testing.T, s string) [16]byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, "-", ""))
	if err != nil || len(b) != 16 {
		t.Fatal("invalid native UUID", s)
	}
	var id [16]byte
	copy(id[:], b)
	return id
}

func buildNativeContainer(t *testing.T, image string, want containerObservation, major, caseID string) {
	t.Helper()
	ctx := context.Background()
	before := fileDigest(t, image)
	img, err := diskimage.Open(image)
	if err != nil {
		t.Fatal(err)
	}
	defer img.Close()
	if len(img.Partitions) != 1 {
		t.Fatal("one native APFS partition required")
	}
	section, err := img.Partition(img.Partitions[0].Index)
	if err != nil {
		t.Fatal(err)
	}
	container, err := apfs.Open(section)
	if err != nil {
		t.Fatal(err)
	}
	count := 2
	if caseID == "shared" {
		count = 3
	}
	if len(want.Volumes) != count || len(container.Volumes) != count {
		t.Fatal("wrong native volume count")
	}
	if !want.Allocation.IndependentWritesAndReuse {
		t.Fatal("missing native allocation and reuse control")
	}
	if caseID == "shared" {
		for i, control := range []*struct {
			Errno        int
			WrittenBytes int64
		}{want.Allocation.Quota, want.Allocation.Reserve} {
			if control == nil || control.Errno == 0 || control.WrittenBytes <= 0 || control.WrittenBytes >= []int64{16 << 20, 64 << 20}[i] {
				t.Fatal("missing native bounded space enforcement")
			}
		}
	}
	clock := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
	options := pack.ContainerOptions{APFS: apfs.ContainerBuildOptions{Capacity: want.Size, Time: clock, UUID: nativeUUID(t, want.ContainerUUID)}}
	var inputs []apfs.VolumeSpec
	for i, w := range want.Volumes {
		v := &container.Volumes[i]
		role := uint16(0)
		if len(w.Roles) == 1 {
			switch w.Roles[0] {
			case "System":
				role = apfs.VolumeRoleSystem
			case "Data":
				role = apfs.VolumeRoleData
			default:
				t.Fatal("unsupported native role")
			}
		} else if len(w.Roles) > 1 {
			t.Fatal("unexpected native roles")
		}
		if v.Name != w.Name || v.UUID != w.UUID || v.CaseSensitive != w.Sensitive || v.Role != role {
			t.Fatal("native volume metadata mismatch")
		}
		if v.ReserveBlocks*uint64(container.BlockSize) != uint64(w.Reserve) || v.QuotaBlocks*uint64(container.BlockSize) != uint64(w.Quota) || len(w.Files.Lookups) != 3 || len(w.Files.RawAttributes) != len(w.Files.Entries) {
			t.Fatal("incomplete or mismatched native space and file observations")
		}
		if w.Group != "" && v.VolumeGroup != w.Group {
			t.Fatal("native group mismatch")
		}
		compareFiles(t, v, w.Files)
		root, err := filesystem.LookupExact(ctx, v, w.Files.Root)
		if err != nil {
			t.Fatal(err)
		}
		s, err := session.Capture(ctx, buildRoot{v, root}, filepath.Join(t.TempDir(), "session"), session.Options{Time: &clock})
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		inputs = append(inputs, apfs.VolumeSpec{Reader: s, Name: w.Name, CaseSensitive: w.Sensitive, UUID: nativeUUID(t, w.UUID), Role: role, Reserve: w.Reserve, Quota: w.Quota})
	}
	if caseID == "group" {
		if want.Volumes[0].Group == "" || want.Volumes[0].Group != want.Volumes[1].Group {
			t.Fatal("missing native group pair")
		}
		options.APFS.Groups = []apfs.VolumeGroupSpec{{System: 1, Data: 0, UUID: nativeUUID(t, want.Volumes[0].Group)}}
	}
	output := os.Getenv("APFS_IMAGE_BUILDING_OUTPUT")
	if output == "" {
		output = t.TempDir()
	}
	output = filepath.Join(output, "macos-"+major, "containers", caseID)
	if err = os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	for _, encoding := range []string{"UDRO", "UDZO"} {
		t.Run(encoding, func(t *testing.T) {
			options.Format = encoding
			destination := filepath.Join(output, encoding+".dmg")
			report, err := pack.CreateContainer(ctx, destination, inputs, options)
			if err != nil {
				t.Fatal(err)
			}
			if report.VolumeCount != count || report.ContainerBytes != want.Size {
				t.Fatal("wrong container report")
			}
			repeat := filepath.Join(t.TempDir(), "repeat.dmg")
			if _, err = pack.CreateContainer(ctx, repeat, inputs, options); err != nil {
				t.Fatal(err)
			}
			digest := fileDigest(t, destination)
			if digest != fileDigest(t, repeat) {
				t.Fatal("nondeterministic container output")
			}
			built, err := diskimage.Open(destination)
			if err != nil {
				t.Fatal(err)
			}
			defer built.Close()
			if len(built.Partitions) != 1 {
				t.Fatal("one built APFS container required")
			}
			view, err := built.Partition(built.Partitions[0].Index)
			if err != nil {
				t.Fatal(err)
			}
			c, err := apfs.Open(view)
			if err != nil {
				t.Fatal(err)
			}
			if len(c.Volumes) != count || c.UUID != want.ContainerUUID {
				t.Fatal("wrong built container")
			}
			for i, w := range want.Volumes {
				v := &c.Volumes[i]
				if v.Name != w.Name || v.UUID != w.UUID || v.CaseSensitive != w.Sensitive || v.Role != inputs[i].Role || w.Group != "" && v.VolumeGroup != w.Group {
					t.Fatal("wrong built volume")
				}
				if v.ReserveBlocks*4096 != uint64(w.Reserve) || v.QuotaBlocks*4096 != uint64(w.Quota) {
					t.Fatal("wrong built volume space limits")
				}
				compareBuiltFiles(t, v, w.Files)
				if inputs[i].Role == apfs.VolumeRoleSystem {
					// Preserve the native System inode namespace, independently of
					// the bijection used for newly assigned individual inode IDs.
					for _, entry := range w.Files.Entries {
						if entry.Path == w.Files.Root {
							continue
						}
						id, err := filesystem.LookupExact(ctx, v, strings.TrimPrefix(entry.Path, w.Files.Root+"/"))
						if err != nil || id>>32 != entry.Object>>32 {
							t.Fatal("System inode namespace differs from Apple reference", entry.Path, id, entry.Object, err)
						}
					}
				}
			}
			if digest != fileDigest(t, destination) {
				t.Fatal("readback changed output")
			}
		})
	}
	if before != fileDigest(t, image) {
		t.Fatal("source image changed")
	}
}
