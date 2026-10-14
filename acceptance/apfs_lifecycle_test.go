package acceptance_test

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
)

type lifecycleCorpus struct {
	Schema   int    `json:"schema"`
	Contract string `json:"contract"`
	Producer struct {
		System, Version, Build, Architecture string
		Sources                              []struct{ Source, SHA256 string }
		Tools                                []struct{ Path, SHA256 string }
	} `json:"producer"`
	CommandsSHA256 string          `json:"commandsSHA256"`
	Cases          []lifecycleCase `json:"cases"`
	Limits         []string        `json:"limits"`
}

type lifecycleCase struct {
	ID, Kind, SelectedName, ParentManifestSHA256, ParentImage, ParentImageSHA256 string
	SelectedXID                                                                  apfs.XID
	States                                                                       []lifecycleState
	CrossVolumeCopy                                                              *struct {
		Status            int
		Stderr            string
		DestinationExists bool
	}
}

type lifecycleState struct {
	Label, Image, SHA256 string
	Volumes              []lifecycleVolume
}

type lifecycleVolume struct {
	Name, UUID                     string
	CaseSensitive, Encrypted       bool
	PublicFixturePassword          *string
	RejectedPublicFixturePasswords []string
	NativeInfo, CryptoUsers        json.RawMessage
	Files                          fileObservation
	Snapshots                      []lifecycleSnapshot
	Storage                        map[string]lifecycleStorage
	CheckerStatus                  int
	SignatureStatus                *int
}

type lifecycleSnapshot struct {
	Name, UUID string
	XID        apfs.XID
	Attributes struct {
		Name                         string
		CreateNS, ModifyNS, ChangeNS *int64
	}
	Files fileObservation
}

type lifecycleStorage struct {
	Schema       int
	API          string
	Object, Size uint64
	Ranges       []struct {
		Logical, Physical, Length uint64
		Flags                     uint32
	}
}

// TestNativeAPFSLifecycleControls reads actual before/after Apple states. The
// native F_LOG2PHYS_EXT observations prove sharing independently of equal bytes.
// This qualifies the reader and supplies future writer controls; it does not
// claim that portable snapshot/clone/encryption mutation has been implemented.
func TestNativeAPFSLifecycleControls(t *testing.T) {
	t.Parallel()
	root := os.Getenv("APFS_NATIVE_LIFECYCLE")
	if root == "" {
		root = "testdata/apfs-lifecycle"
	}
	manifests, err := filepath.Glob(filepath.Join(root, "*", "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(manifests) == 0 {
		t.Fatal("native APFS lifecycle evidence is missing", root)
	}
	majors := map[string]bool{}
	for _, manifest := range manifests {
		t.Run(filepath.Base(filepath.Dir(manifest)), func(t *testing.T) {
			dir := filepath.Dir(manifest)
			var corpus lifecycleCorpus
			decodeEvidence(t, manifest, &corpus)
			major := strings.Split(corpus.Producer.Version, ".")[0]
			if corpus.Schema != 1 || corpus.Contract != "apfs-native-lifecycle" || corpus.Producer.System != "macOS" || corpus.Producer.Build == "" || corpus.Producer.Architecture == "" || (major != "15" && major != "26" && major != "27") || majors[major] {
				t.Fatal("invalid native lifecycle provenance")
			}
			majors[major] = true
			required := []string{"apfs_lifecycle.py", "apfs_storage.c", "capture.py", "container_building.py", "image_repacking.py", "snapshot_reading.py", "verify_preservation.py", "file_compression.py", "image_building.py", "metadata_edits.py", "content_replacement.py", "preservation.py"}
			if len(corpus.Producer.Sources) != len(required) || len(corpus.Producer.Tools) != 6 || len(corpus.Limits) != 3 {
				t.Fatal("incomplete lifecycle source/tool/profile provenance")
			}
			for i, source := range corpus.Producer.Sources {
				if source.Source != required[i] {
					t.Fatal("unexpected native collector source", source.Source)
				}
				verifyDigest(t, dir, source.Source, source.SHA256)
			}
			verifyDigest(t, dir, "commands.json", corpus.CommandsSHA256)
			ids := map[string]bool{"apfs": false, "apfs-case-sensitive": false, "snapshot-apfs": false, "snapshot-apfs-case-sensitive": false}
			if len(corpus.Cases) != len(ids) {
				t.Fatal("incomplete native lifecycle cases")
			}
			for _, c := range corpus.Cases {
				if seen, exists := ids[c.ID]; !exists || seen {
					t.Fatal("unknown or repeated lifecycle case", c.ID)
				}
				ids[c.ID] = true
				if c.Kind == "clone-encryption" {
					legacy := major == "15"
					if c.CrossVolumeCopy == nil || c.CrossVolumeCopy.DestinationExists == legacy ||
						(legacy && (c.CrossVolumeCopy.Status != 1 || !strings.Contains(c.CrossVolumeCopy.Stderr, "Cross-device link"))) ||
						(!legacy && c.CrossVolumeCopy.Status != 0) {
						t.Fatal("native cross-volume clone-copy outcome differs from source-version control", major)
					}
				}
				t.Run(c.ID, func(t *testing.T) { replayLifecycle(t, dir, c) })
			}
		})
	}
	for _, major := range strings.Split(os.Getenv("APFS_REQUIRED_NATIVE_MAJORS"), ",") {
		if major != "" && !majors[major] {
			t.Error("required native lifecycle producer missing", major)
		}
	}
}

func replayLifecycle(t *testing.T, dir string, c lifecycleCase) {
	t.Helper()
	labels := []string{"clone-shared", "clone-diverged", "clone-truncated", "clone-final-owner", "encrypted", "password-changed", "encrypted-edited", "decrypted"}
	if c.Kind == "snapshot-revert" {
		labels = []string{"retained", "reverted"}
		if c.SelectedName == "" || c.SelectedXID == 0 || len(c.ParentImageSHA256) != 64 {
			t.Fatal("snapshot revert source/selection missing")
		}
		parent := filepath.Join(dir, "snapshot-reference")
		verifyDigest(t, parent, "manifest.json", c.ParentManifestSHA256)
		verifyDigest(t, parent, c.ParentImage, c.ParentImageSHA256)
	} else if c.Kind != "clone-encryption" {
		t.Fatal("unknown lifecycle case kind")
	}
	if len(c.States) != len(labels) {
		t.Fatal("incomplete native lifecycle states")
	}
	identities := map[string]string{}
	for i, state := range c.States {
		if state.Label != labels[i] {
			t.Fatal("unexpected native lifecycle order", state.Label)
		}
		t.Run(state.Label, func(t *testing.T) {
			verifyDigest(t, dir, state.Image, state.SHA256)
			image, err := diskimage.Open(filepath.Join(dir, state.Image))
			if err != nil {
				t.Fatal(err)
			}
			defer image.Close()
			result, err := inspect.Image(context.Background(), image)
			if err != nil || len(result.Partitions) != 1 || result.Partitions[0].APFS == nil {
				t.Fatal("native lifecycle container rejected", err)
			}
			container := result.Partitions[0].APFS
			if len(container.Volumes) != len(state.Volumes) {
				t.Fatal("native lifecycle volume inventory differs")
			}
			for _, expected := range state.Volumes {
				if prior := identities[expected.Name]; prior != "" && prior != expected.UUID {
					t.Fatal("native lifecycle changed volume UUID", expected.Name)
				}
				identities[expected.Name] = expected.UUID
				var volume *apfs.Volume
				for j := range container.Volumes {
					if container.Volumes[j].UUID == expected.UUID {
						volume = &container.Volumes[j]
					}
				}
				if volume == nil || volume.Name != expected.Name || volume.CaseSensitive != expected.CaseSensitive || volume.Encrypted != expected.Encrypted || expected.CheckerStatus != 0 || (expected.SignatureStatus != nil && *expected.SignatureStatus != 0) {
					t.Fatal("native lifecycle volume/checker observation differs", expected.Name)
				}
				if expected.Encrypted {
					if expected.PublicFixturePassword == nil || len(expected.RejectedPublicFixturePasswords) == 0 || volume.Flags&8 == 0 {
						t.Fatal("software-encryption control missing")
					}
					for _, password := range expected.RejectedPublicFixturePasswords {
						if unlocked, err := volume.Unlock(context.Background(), []byte(password)); unlocked != nil || !errors.Is(err, filesystem.ErrAuthentication) {
							t.Fatal("native-rejected credential accepted", err)
						}
					}
					unlocked, err := volume.Unlock(context.Background(), []byte(*expected.PublicFixturePassword))
					if err != nil {
						t.Fatal("native-accepted lifecycle password rejected", err)
					}
					t.Cleanup(func() { _ = unlocked.Close() })
					volume = unlocked
				} else if expected.PublicFixturePassword != nil {
					t.Fatal("plaintext native state declares a password")
				}
				compareFiles(t, volume, expected.Files)
				compareLifecycleSnapshots(t, volume, expected.Snapshots)
				validateLifecycleStorage(t, expected)
			}
			verifyDigest(t, dir, state.Image, state.SHA256)
		})
	}
	if c.Kind == "clone-encryption" {
		for _, v := range c.States[0].Volumes {
			if v.Name == "Primary" {
				data, clone, alias := v.Storage["data"], v.Storage["clone"], v.Storage["alias"]
				if data.Object == clone.Object || data.Object != alias.Object {
					t.Fatal("native clone/hard-link identities are not distinct")
				}
				for _, suffix := range []string{"", "/..namedfork/rsrc"} {
					if !lifecycleOverlap(v.Storage["data"+suffix], v.Storage["clone"+suffix]) || lifecycleOverlap(v.Storage["data"+suffix], v.Storage["ordinary-copy"+suffix]) {
						t.Fatal("native physical sharing control differs", suffix)
					}
				}
			}
		}
	} else {
		before, after := c.States[0].Volumes[0], c.States[1].Volumes[0]
		if len(before.Snapshots) != 2 || len(after.Snapshots) != 1 || after.Snapshots[0].XID != c.SelectedXID || after.Snapshots[0].Name != c.SelectedName {
			t.Fatal("native revert history incomplete")
		}
	}
}

func compareLifecycleSnapshots(t *testing.T, volume *apfs.Volume, expected []lifecycleSnapshot) {
	t.Helper()
	ctx := context.Background()
	got := map[apfs.XID]apfs.Snapshot{}
	if err := volume.ListSnapshots(ctx, func(s apfs.Snapshot) error { got[s.XID] = s; return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != len(expected) {
		t.Fatal("native lifecycle snapshot inventory differs")
	}
	for _, want := range expected {
		snapshot, exists := got[want.XID]
		if !exists || snapshot.Name != want.Name || snapshot.UUID.State != filesystem.Present || snapshot.UUID.Value != want.UUID || want.Attributes.Name != want.Name {
			t.Fatal("native lifecycle snapshot identity differs", want.Name)
		}
		if (want.Attributes.CreateNS != nil && snapshot.CreateTime.UnixNano() != *want.Attributes.CreateNS) || (want.Attributes.ChangeNS != nil && snapshot.ChangeTime.UnixNano() != *want.Attributes.ChangeNS) {
			t.Fatal("native lifecycle snapshot timestamp differs", want.Name)
		}
		reader, err := volume.OpenSnapshot(ctx, want.XID)
		if err != nil {
			t.Fatal(err)
		}
		byName, err := volume.OpenSnapshotName(ctx, want.Name)
		if err != nil {
			t.Fatal(err)
		}
		left, err := reader.Stat(ctx, reader.Root())
		if err != nil {
			t.Fatal(err)
		}
		right, err := byName.Stat(ctx, byName.Root())
		if err != nil || !reflect.DeepEqual(left, right) {
			t.Fatal("native lifecycle snapshot selectors disagree", err)
		}
		compareFiles(t, reader, want.Files)
	}
	if _, err := volume.OpenSnapshotName(ctx, "absent-lifecycle-snapshot"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("missing native lifecycle snapshot accepted", err)
	}
}

func validateLifecycleStorage(t *testing.T, v lifecycleVolume) {
	t.Helper()
	for name, mapped := range v.Storage {
		if mapped.Schema != 1 || mapped.API != "F_LOG2PHYS_EXT" || mapped.Object == 0 || mapped.Size == 0 || len(mapped.Ranges) == 0 || len(mapped.Ranges) > 4096 {
			t.Fatal("invalid native physical storage mapping", name)
		}
		var logical uint64
		for _, r := range mapped.Ranges {
			if r.Logical != logical || r.Length == 0 || r.Length > mapped.Size-logical || r.Physical+r.Length < r.Physical {
				t.Fatal("invalid native physical extent bounds", name)
			}
			logical += r.Length
		}
		if logical != mapped.Size {
			t.Fatal("incomplete native physical storage mapping", name)
		}
	}
}

func lifecycleOverlap(a, b lifecycleStorage) bool {
	for _, x := range a.Ranges {
		for _, y := range b.Ranges {
			if max(x.Physical, y.Physical) < min(x.Physical+x.Length, y.Physical+y.Length) {
				return true
			}
		}
	}
	return false
}
