package acceptance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

type nativeCopyOperation struct {
	Sources                                                             []string
	Destination, Op, Path                                               string
	Archive, Recursive, Preserve, NoAttributes, FromHost, PreserveLinks bool
}
type nativeCopyState struct {
	nativeEditState
	Operations  []nativeCopyOperation
	ClockFields map[string][]string
}
type nativeCopyManifest struct {
	nativeEditManifest
	Producer struct {
		Sources                 map[string]string
		ReferenceManifestSHA256 string
	}
	HostInputs []struct {
		File, SHA256 string
		Size         int64
	}
	Cases []struct {
		ID     string
		Source hfsGrowthArchive
		Before nativeEditState
		States map[string]nativeCopyState
	}
}

func copyHostInput(t *testing.T, dir string, m nativeCopyManifest) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "host-source")
	// These empty-directory inputs are part of the retained producer recipe;
	// GitHub artifact archives store files, not otherwise empty directories.
	for _, name := range []string{"", "Nested", "Empty"} {
		if err := os.MkdirAll(filepath.Join(root, name), 0755); err != nil {
			t.Fatal(err)
		}
	}
	if len(m.HostInputs) != 3 {
		t.Fatal("complete native host input inventory required")
	}
	for _, input := range m.HostInputs {
		name, err := filepath.Rel("host-source", input.File)
		if err != nil || !filepath.IsLocal(name) {
			t.Fatal("native host input path", err)
		}
		if fmt.Sprintf("%x", fileDigest(t, filepath.Join(dir, input.File))) != input.SHA256 {
			t.Fatal("native host input digest")
		}
		data, err := os.ReadFile(filepath.Join(dir, input.File))
		if err != nil || int64(len(data)) != input.Size {
			t.Fatal("native host input", err)
		}
		if err = os.WriteFile(filepath.Join(root, name), data, 0644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func applyImageCopies(t *testing.T, source, destination, host, format string, when time.Time, ops []nativeCopyOperation) imageedit.CopyReport {
	t.Helper()
	var commands []imageedit.CopyCommand
	var changes []imageedit.Change
	for _, op := range ops {
		if op.Op != "" {
			changes = append(changes, imageedit.Change{Operation: op.Op, Path: "/Fixture/" + op.Path, Destination: func() string {
				if op.Destination == "" {
					return ""
				}
				return "/Fixture/" + op.Destination
			}(), Recursive: op.Recursive})
			continue
		}
		if len(changes) != 0 {
			t.Fatal("copy recipe must finish ordinary removals after copying")
		}
		sources := make([]string, len(op.Sources))
		for i, text := range op.Sources {
			if text == "@host-source" {
				sources[i] = host
			} else {
				sources[i] = "/Fixture/" + text
			}
		}
		commands = append(commands, imageedit.CopyCommand{Sources: sources, Destination: "/Fixture/" + op.Destination, Options: imageedit.CopyOptions{Archive: op.Archive, Recursive: op.Recursive, Preserve: op.Preserve, NoAttributes: op.NoAttributes, FromHost: op.FromHost, PreserveLinks: op.PreserveLinks}})
	}
	output := destination
	if len(changes) > 0 {
		output = filepath.Join(t.TempDir(), "copied.dmg")
	}
	o := imageedit.Options{Format: format, Time: when}
	report, err := imageedit.CopyBatch(context.Background(), source, output, o, commands)
	if err != nil {
		t.Fatal("image copy", err)
	}
	if report.Copied == 0 {
		t.Fatal("copy report omitted completed paths")
	}
	if len(changes) > 0 {
		if _, err := imageedit.Apply(context.Background(), output, destination, o, changes); err != nil {
			t.Fatal("copy final edits", err)
		}
	}
	return report
}

func TestNativeAPFSImageCopy(t *testing.T) {
	testImageCopy(t, "apfs", "APFS_NATIVE_APFS_COPY", "APFS_APFS_COPY_OUTPUT", "testdata/apfs-copy")
}
func TestNativeHFSImageCopy(t *testing.T) {
	testImageCopy(t, "hfs", "APFS_NATIVE_HFS_COPY", "APFS_HFS_COPY_OUTPUT", "testdata/hfs-copy")
}
func TestNativeHFSJournaledImageCopy(t *testing.T) {
	testImageCopy(t, "hfs", "APFS_NATIVE_HFS_JOURNALED_COPY", "APFS_HFS_JOURNALED_COPY_OUTPUT", "testdata/hfs-journaled-copy")
}

func testImageCopy(t *testing.T, kind, rootEnv, outputEnv, retained string) {
	t.Helper()
	root := nativeInput(t, rootEnv, retained)
	paths, err := filepath.Glob(filepath.Join(root, "macos-*", "manifest.json"))
	if err != nil || len(paths) == 0 {
		t.Fatal("native copy evidence absent", err)
	}
	majors := map[int]bool{}
	for _, manifestPath := range paths {
		var m nativeCopyManifest
		data, err := os.ReadFile(manifestPath)
		if err != nil {
			t.Fatal(err)
		}
		if err = json.Unmarshal(data, &m); err != nil {
			t.Fatal(err)
		}
		if m.Schema != 1 || m.Contract != "existing-"+kind+"-copy" || len(m.Cases) != 2 || majors[m.Major] || len(m.Producer.Sources) < 12 {
			t.Fatal("native copy inventory")
		}
		majors[m.Major] = true
		dir := filepath.Dir(manifestPath)
		verifyDigest(t, dir, "commands.json", m.CommandsSHA256)
		verifyDigest(t, dir, "reference-manifest.json", m.Producer.ReferenceManifestSHA256)
		for name, hash := range m.Producer.Sources {
			verifyDigest(t, dir, name, hash)
		}
		host := copyHostInput(t, dir, m)
		seen := map[string]bool{}
		for _, c := range m.Cases {
			valid := false
			for _, id := range imageLinkCases(kind) {
				valid = valid || id == c.ID
			}
			if !valid || seen[c.ID] {
				t.Fatal("native copy case")
			}
			seen[c.ID] = true
			t.Run(filepath.Base(dir)+"/"+c.ID, func(t *testing.T) {
				open := openEditArchive
				if kind == "apfs" {
					open = openAPFSEditArchive
				}
				source := open(t, dir, c.Source)
				digest := fileDigest(t, source)
				compareMetadataState(t, metadataReader(t, source, kind), c.Before.Files, kind)
				compressedFork := false
				for _, entry := range c.Before.Files.Entries {
					if entry.Path == "Fixture/inline-fork-compressed" {
						_, fork := entry.RawAttributes["com.apple.ResourceFork"]
						_, storage := entry.RawAttributes["com.apple.decmpfs"]
						compressedFork = entry.Flags&32 != 0 && fork && storage
					}
				}
				if !compressedFork {
					t.Fatal("independent fork must belong to an actually compressed native source")
				}
				when := time.Unix(m.ModificationSeconds, 0)
				for _, phase := range []string{"copy", "copy-final"} {
					state, ok := c.States[phase]
					if !ok || state.CheckerStatus != 0 || len(state.Operations) == 0 {
						t.Fatal("complete native copy states required")
					}
					native := open(t, dir, state.Archive)
					compareMetadataState(t, metadataReader(t, native, kind), state.Files, kind)
				}
				out := os.Getenv(outputEnv)
				if out == "" {
					out = t.TempDir()
				}
				out = filepath.Join(out, filepath.Base(dir), c.ID)
				if err = os.MkdirAll(out, 0700); err != nil {
					t.Fatal(err)
				}
				for _, format := range []string{"UDRO", "UDZO"} {
					t.Run(format, func(t *testing.T) {
						current, ids := source, newLinkIdentities(c.Before.Files)
						for _, phase := range []string{"copy", "copy-final"} {
							state := c.States[phase]
							destination := filepath.Join(out, phase+"-"+format+".dmg")
							report := applyImageCopies(t, current, destination, host, format, when, state.Operations)
							omissions := 0
							if phase == "copy" {
								omissions = 2
							}
							if len(report.OmittedAttributes) != omissions {
								t.Fatal("native copy-view omissions not reported", report.OmittedAttributes)
							}
							if omissions == 2 && (report.OmittedAttributes[0].Source != "/Fixture/inline-fork-compressed" || report.OmittedAttributes[0].Destination != "/Fixture/Copies/inline-fork" || report.OmittedAttributes[0].Attribute != "com.apple.ResourceFork" || report.OmittedAttributes[0].Reason == "" || report.OmittedAttributes[1].Source != "/Fixture/inactive-malformed" || report.OmittedAttributes[1].Attribute != "com.apple.decmpfs" || report.OmittedAttributes[1].Reason == "") {
								t.Fatal("incorrect compressed-copy omission", report.OmittedAttributes)
							}
							repeat := filepath.Join(t.TempDir(), "repeat.dmg")
							applyImageCopies(t, current, repeat, host, format, when, state.Operations)
							if fileDigest(t, repeat) != fileDigest(t, destination) {
								t.Fatal("nonreproducible copying")
							}
							want := metadataExpected(nativeImageMetadataState{nativeEditState: state.nativeEditState, ClockFields: state.ClockFields}, m.ModificationSeconds)
							ids.compare(t, metadataReader(t, destination, kind), want, kind)
							if c.Before.Journal != nil {
								image, err := diskimage.Open(destination)
								if err != nil {
									t.Fatal(err)
								}
								part, err := image.Partition(0)
								if err != nil {
									t.Fatal(err)
								}
								verifyEditJournal(t, part, c.Before.Journal)
								image.Close()
							}
							current = destination
						}
					})
				}
				for _, command := range []imageedit.CopyCommand{{Sources: []string{"/Fixture/CopySource"}, Destination: "/Fixture/CopySource/Nested", Options: imageedit.CopyOptions{Archive: true}}, {Sources: []string{"/Fixture/independent"}, Destination: "/Fixture/independent"}, {Sources: []string{"/Fixture/independent"}, Destination: "/Fixture/empty", Options: imageedit.CopyOptions{NoClobber: true}}} {
					rejected := filepath.Join(t.TempDir(), "rejected.dmg")
					if _, err = imageedit.CopyBatch(context.Background(), source, rejected, imageedit.Options{Time: when}, []imageedit.CopyCommand{command}); err == nil {
						t.Fatal("unsafe copy admitted")
					}
					if _, err = os.Stat(rejected); !errors.Is(err, fs.ErrNotExist) {
						t.Fatal("failed copy published output", err)
					}
				}
				if fileDigest(t, source) != digest {
					t.Fatal("copy changed its source")
				}
			})
		}
	}
	required := os.Getenv("APFS_REQUIRED_NATIVE_MAJORS")
	if required == "" {
		required = "15,26,27"
	}
	for _, text := range strings.Split(required, ",") {
		major, err := strconv.Atoi(text)
		if err != nil {
			t.Fatal(err)
		}
		if !majors[major] {
			t.Fatal("native copy source version absent", major)
		}
	}
}

func TestNativeImageCopyContinuation(t *testing.T) {
	root := os.Getenv("APFS_IMAGE_COPY_CONTINUATION")
	if root == "" {
		t.Skip("native continuation inputs are supplied by the required image-edit pipelines")
	}
	kind := os.Getenv("APFS_IMAGE_COPY_KIND")
	if kind != "apfs" && kind != "hfs" {
		t.Fatal("explicit continuation filesystem required")
	}
	paths, err := filepath.Glob(filepath.Join(root, "*.raw"))
	expected := map[string]bool{}
	for _, major := range []int{15, 26, 27} {
		for _, id := range imageLinkCases(kind) {
			expected[fmt.Sprintf("macos-%d-%s.raw", major, id)] = true
		}
	}
	if err != nil || len(paths) != len(expected) {
		t.Fatal("complete copy continuations required", len(paths), err)
	}
	output := os.Getenv("APFS_IMAGE_COPY_CONTINUED_OUTPUT")
	if output == "" {
		t.Fatal("continued copy output required")
	}
	if err = os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	for _, source := range paths {
		if !expected[filepath.Base(source)] {
			t.Fatal("unexpected continuation source", source)
		}
		delete(expected, filepath.Base(source))
		t.Run(filepath.Base(source), func(t *testing.T) {
			var control struct {
				Before   fileObservation
				Expected nativeCopyState
			}
			data, err := os.ReadFile(strings.TrimSuffix(source, ".raw") + ".json")
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(data, &control); err != nil {
				t.Fatal(err)
			}
			if control.Expected.CheckerStatus != 0 || len(control.Expected.Operations) != 2 {
				t.Fatal("complete native continuation required")
			}
			digest := fileDigest(t, source)
			compareMetadataState(t, metadataReader(t, source, kind), control.Before, kind)
			out := filepath.Join(output, strings.TrimSuffix(filepath.Base(source), ".raw")+".dmg")
			const stamp = 1749283750
			applyImageCopies(t, source, out, "", "UDZO", time.Unix(stamp, 0), control.Expected.Operations)
			want := metadataExpected(nativeImageMetadataState{nativeEditState: control.Expected.nativeEditState, ClockFields: control.Expected.ClockFields}, stamp)
			newLinkIdentities(control.Before).compare(t, metadataReader(t, out, kind), want, kind)
			if fileDigest(t, source) != digest {
				t.Fatal("continued copying changed native source")
			}
		})
	}
}
