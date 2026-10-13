package acceptance_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

type phase5VolumeState struct {
	Name, UUID                     string
	ReserveBytes, QuotaBytes       uint64
	Files                          fileObservation
	CheckerStatus, SignatureStatus int
}
type phase5APFSCase struct {
	ID, TargetVolume    string
	CapacityBytes       int64
	Source, NativeAfter hfsGrowthArchive
	Before, After       []phase5VolumeState
	Operations          []string
}
type phase5Manifest struct {
	Schema, Major            int
	Contract, CommandsSHA256 string
	Producer                 struct {
		System, Version, Build, Architecture, Revision, Run string
		Sources, Tools                                      map[string]string
	}
	Cases []phase5APFSCase
}

// Large original evidence is decoded sparsely into ordinary files. Every byte,
// including holes, participates in the independent captured disk digest.
func openPhase5Archive(t *testing.T, dir string, archive hfsGrowthArchive) string {
	t.Helper()
	if archive.UncompressedBytes <= 0 || archive.UncompressedBytes > 2<<30 {
		t.Fatal("native phase-5 archive bound")
	}
	verifyDigest(t, dir, archive.Image, archive.SHA256)
	in, err := os.Open(filepath.Join(dir, archive.Image))
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	z, err := gzip.NewReader(in)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	name := filepath.Join(t.TempDir(), "native.raw")
	out, err := os.Create(name)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	buffer := make([]byte, 128<<10)
	var offset int64
	for {
		n, readErr := z.Read(buffer)
		if int64(n) > archive.UncompressedBytes-offset {
			out.Close()
			t.Fatal("oversized native archive")
		}
		data := buffer[:n]
		digest.Write(data)
		if bytes.Count(data, []byte{0}) != len(data) {
			written, e := out.WriteAt(data, offset)
			if e != nil || written != n {
				out.Close()
				t.Fatal("native archive write", e)
			}
		}
		offset += int64(n)
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			out.Close()
			t.Fatal(readErr)
		}
	}
	err = out.Truncate(offset)
	closeErr := out.Close()
	if err != nil || closeErr != nil || offset != archive.UncompressedBytes || hex.EncodeToString(digest.Sum(nil)) != archive.UncompressedSHA256 {
		t.Fatal("native disk hash/size", err, closeErr)
	}
	return name
}

func phase5APFSChanges() []imageedit.Change {
	payload := make([]byte, 65537)
	for i := range payload {
		payload[i] = byte(i)
	}
	return []imageedit.Change{
		{Path: "/Fixture/alias", Data: bytes.NewReader(payload)},
		{Operation: "chmod", Path: "/Fixture/mode", Mode: "0755"},
		{Operation: "xattr", Path: "/Fixture/data", Attribute: "org.go-apfs.created", Data: bytes.NewReader([]byte("New attribute\x00\xff"))},
		{Operation: "mkdir", Path: "/Fixture/created", Mode: "0755"},
		{Operation: "cp", Path: "/Fixture/created/nested", Data: bytes.NewReader([]byte("New nested contents\n"))},
		{Operation: "mv", Path: "/Fixture/mode", Destination: "/Fixture/renamed"},
		{Operation: "ln", Path: "/Fixture/data", Destination: "/Fixture/another-alias"},
	}
}

func phase5Volume(t *testing.T, c *apfs.Container, id string) *apfs.Volume {
	t.Helper()
	for i := range c.Volumes {
		if c.Volumes[i].UUID == id {
			return &c.Volumes[i]
		}
	}
	t.Fatal("original volume UUID missing", id)
	return nil
}

func comparePhase5APFS(t *testing.T, v *apfs.Volume, before, want fileObservation, when time.Time) {
	t.Helper()
	want.Entries = append([]nativeFile(nil), want.Entries...)
	original := map[string]nativeFile{}
	originalIDs := map[uint64]bool{}
	for _, entry := range before.Entries {
		original[entry.Path] = entry
		originalIDs[entry.Object] = true
	}
	forward, reverse := map[uint64]uint64{}, map[uint64]uint64{}
	for i := range want.Entries {
		entry := &want.Entries[i]
		id, err := filesystem.LookupExact(context.Background(), v, entry.Path)
		if err != nil {
			t.Fatal(err)
		}
		if old, ok := forward[entry.Object]; ok && old != id {
			t.Fatal("native aliases separated")
		}
		if old, ok := reverse[id]; ok && old != entry.Object {
			t.Fatal("native objects conflated")
		}
		forward[entry.Object], reverse[id] = id, entry.Object
		oldPath := entry.Path
		if oldPath == "Fixture/renamed" {
			oldPath = "Fixture/mode"
		}
		if oldPath == "Fixture/another-alias" {
			oldPath = "Fixture/data"
		}
		if old, ok := original[oldPath]; ok {
			if id != old.Object {
				t.Fatal("original identity changed", entry.Path)
			}
		} else {
			if originalIDs[id] {
				t.Fatal("new object reused original identity")
			}
			entry.BirthSeconds = when.Unix()
			entry.BirthNS = nil
			entry.ModifyNS, entry.AccessNS = when.UnixNano(), when.UnixNano()
		}
		entry.Object = id
		if entry.Path == "Fixture" || id == original["Fixture/data"].Object || entry.Path == "Fixture/renamed" || strings.HasPrefix(entry.Path, "Fixture/created") {
			entry.ChangeNS = when.UnixNano()
			if entry.Mode&0170000 == 0040000 {
				entry.ModifyNS = when.UnixNano()
			}
		}
	}
	compareMetadataState(t, v, want, "apfs")
}

// TestNativePhase5APFS compares larger/container-wide edits with Apple before
// and after observations. Native output verification is a separate CI program.
func TestNativePhase5APFS(t *testing.T) {
	root := os.Getenv("APFS_NATIVE_PHASE5_APFS")
	if root == "" {
		root = "testdata/phase5-apfs"
	}
	paths, err := filepath.Glob(filepath.Join(root, "macos-*", "manifest.json"))
	if err != nil || len(paths) == 0 {
		t.Fatal("phase-5 native references absent", err)
	}
	majors := map[int]bool{}
	for _, name := range paths {
		var manifest phase5Manifest
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &manifest); err != nil {
			t.Fatal(err)
		}
		if manifest.Schema != 1 || manifest.Contract != "phase5-offline-editing" || len(manifest.Cases) != 4 || manifest.Producer.System != "macOS" || manifest.Producer.Build == "" || manifest.Producer.Architecture == "" || len(manifest.Producer.Revision) != 40 || manifest.Producer.Run == "" || len(manifest.Producer.Sources) != 14 || len(manifest.Producer.Tools) != 3 || majors[manifest.Major] {
			t.Fatal("native completion inventory/provenance")
		}
		majors[manifest.Major] = true
		dir := filepath.Dir(name)
		verifyDigest(t, dir, "commands.json", manifest.CommandsSHA256)
		for name, hash := range manifest.Producer.Sources {
			verifyDigest(t, dir, name, hash)
		}
		for _, c := range manifest.Cases {
			t.Run(filepath.Base(dir)+"/"+c.ID, func(t *testing.T) {
				if c.CapacityBytes != c.Source.UncompressedBytes || len(c.Operations) != 7 {
					t.Fatal("native case geometry/operations")
				}
				verifyDigest(t, dir, c.NativeAfter.Image, c.NativeAfter.SHA256)
				source := openPhase5Archive(t, dir, c.Source)
				original := openAPFSEditVolume(t, source)
				var target phase5VolumeState
				for _, state := range c.Before {
					if state.CheckerStatus != 0 || state.SignatureStatus != 0 {
						t.Fatal("failed native source observation")
					}
					compareMetadataState(t, phase5Volume(t, original, state.UUID), state.Files, "apfs")
					if state.Name == c.TargetVolume {
						target = state
					}
				}
				if target.UUID == "" {
					t.Fatal("native target absent")
				}
				output := os.Getenv("APFS_PHASE5_APFS_OUTPUT")
				if output == "" {
					output = t.TempDir()
				}
				output = filepath.Join(output, filepath.Base(dir), c.ID)
				if err = os.MkdirAll(output, 0700); err != nil {
					t.Fatal(err)
				}
				when := time.Unix(1749283750, 0).UTC()
				for _, format := range []string{"UDRO", "UDZO"} {
					destination := filepath.Join(output, "edited-"+format+".dmg")
					options := imageedit.Options{Volume: target.UUID, Format: format, Time: when}
					var report imageedit.Report
					if format == "UDZO" {
						report, err = imageedit.Edit(context.Background(), source, destination, options, func(editor *imageedit.Editor) error {
							for _, change := range phase5APFSChanges() {
								if _, err := editor.Apply([]imageedit.Change{change}); err != nil {
									return err
								}
							}
							return nil
						})
					} else {
						report, err = imageedit.Apply(context.Background(), source, destination, options, phase5APFSChanges())
					}
					if err != nil {
						t.Fatal(err)
					}
					got := openAPFSEditVolume(t, destination)
					if got.UUID != original.UUID || got.BlockCount != original.BlockCount || report.VolumeID != target.UUID {
						t.Fatal("container geometry/identity changed")
					}
					for _, state := range c.After {
						volume := phase5Volume(t, got, state.UUID)
						if state.Name == c.TargetVolume {
							comparePhase5APFS(t, volume, target.Files, state.Files, when)
						} else {
							for _, before := range c.Before {
								if before.UUID == state.UUID {
									compareMetadataState(t, volume, before.Files, "apfs")
								}
							}
						}
						if volume.ReserveBlocks*4096 != state.ReserveBytes || volume.QuotaBlocks*4096 != state.QuotaBytes {
							t.Fatal("space policy changed")
						}
					}
				}
				digest := fileDigest(t, source)
				if hex.EncodeToString(digest[:]) != c.Source.UncompressedSHA256 {
					t.Fatal("original native evidence changed")
				}
			})
		}
	}
	requireNativeVersions(t, majors)
}

func requireNativeVersions(t *testing.T, majors map[int]bool) {
	t.Helper()
	required := os.Getenv("APFS_REQUIRED_NATIVE_MAJORS")
	if required == "" {
		required = "15,26,27"
	}
	for _, value := range strings.Split(required, ",") {
		major, err := strconv.Atoi(value)
		if err != nil || (major != 15 && major != 26 && major != 27) || !majors[major] {
			t.Fatal("required native major absent or invalid", value)
		}
	}
}
