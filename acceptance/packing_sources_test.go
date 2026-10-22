package acceptance_test

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

// TestPackingReopenedPreservationSourcesMatchesNativeFiles proves that the
// public workspace reader and the CLI's persisted session input preserve the
// same construction inputs as the original native filesystem reader. One image
// per case returns to Apple tools; all three paths must produce identical bytes.
func TestPackingReopenedPreservationSourcesMatchesNativeFiles(t *testing.T) {
	cases, _ := loadCorpus(t)
	recipes := recipesByName(t)
	binary := portableCommandBinary(t)
	profiles := map[string]bool{"apfs": true, "apfsx": true, "hfsplus": true, "hfsx": true}
	seen := map[string]bool{}
	for _, k := range cases {
		if k.Recipe != "file-corpus" || k.Stage != "final" || !profiles[k.Profile] {
			continue
		}
		key := fmt.Sprintf("macos-%d/%s", k.Producer, k.Profile)
		if seen[key] {
			t.Fatalf("duplicate packing source %s", key)
		}
		seen[key] = true
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			sourceDigest := packingFileDigest(t, k.Image())
			_, nativeReader, closeSource := openSingleVolume(t, ctx, k, recipes[k.Recipe])
			defer closeSource()
			root, err := filesystem.LookupExact(ctx, nativeReader, "Fixture")
			if err != nil {
				t.Fatal(err)
			}
			nativeRoot, err := nativeReader.Stat(ctx, root)
			if err != nil {
				t.Fatal(err)
			}
			options := pack.Options{Format: "UDZO", FileCompression: "preserve", Volume: pack.VolumeOptions{
				Name: "Example", Time: fixedClock, Capacity: 160 << 20, CaseSensitive: nativeReader.NameRules().CaseSensitive,
			}}
			baseline := filepath.Join(t.TempDir(), "native-reader.dmg")
			if _, err := pack.Create(ctx, baseline, buildRoot{nativeReader, root}, options); err != nil {
				t.Fatal(err)
			}
			wantDigest := packingFileDigest(t, baseline)

			directory := filepath.Join(t.TempDir(), "workspace")
			if _, err := workspace.Extract(ctx, nativeReader, root, directory, workspace.Limits{}); err != nil {
				t.Fatal(err)
			}
			workspaceFiles := packingSourceInventory(t, directory)
			w, err := workspace.Open(ctx, directory)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = w.Close() }()
			packingSourceIdentity(t, ctx, w, nativeReader.NameRules(), nativeRoot.Identity)
			compareViewWith(t, ctx, "reopened workspace", w, k.Observation.Views[0], compareOptions{subtree: "Fixture"})
			fromWorkspace := filepath.Join(t.TempDir(), "workspace-reader.dmg")
			if _, err := pack.Create(ctx, fromWorkspace, w, options); err != nil {
				t.Fatal(err)
			}
			if got := packingFileDigest(t, fromWorkspace); got != wantDigest {
				t.Fatalf("workspace and native reader produced different images: %s, %s", got, wantDigest)
			}

			scratch := t.TempDir()
			sessionDir := filepath.Join(scratch, "build")
			s, err := session.Capture(ctx, w, sessionDir, session.Options{Time: &fixedClock})
			if err != nil {
				t.Fatal(err)
			}
			packingSourceIdentity(t, ctx, s, nativeReader.NameRules(), nativeRoot.Identity)
			if err := s.Verify(ctx); err != nil {
				_ = s.Close()
				t.Fatal(err)
			}
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			// Release the API session before starting the separate CLI process.
			// The command must reopen persisted metadata and verify owned blobs.
			sessionFiles := packingSourceInventory(t, sessionDir)
			name := outputName(k, "build.session.UDZO.dmg")
			image := produceTwice(t, name, true, func(destination string) error {
				args := []string{"pack", "--scratch-dir", scratch, "--session", "build", "--volume-name", "Example",
					"--format", "UDZO", "--capacity", "160MiB", "--time", fixedClock.Format(time.RFC3339), destination}
				data, err := exec.Command(binary, args...).CombinedOutput()
				if err != nil {
					return fmt.Errorf("pack reopened session: %w: %s", err, data)
				}
				return nil
			})
			if got := packingFileDigest(t, image); got != wantDigest {
				t.Fatalf("CLI session and native reader produced different images: %s, %s", got, wantDigest)
			}
			checkBuiltImage(t, ctx, image, k, "Fixture", "preserve")
			recordOutput(t, schema.Output{Name: name, File: filepath.Base(image), Operation: "build", Format: "UDZO",
				Source: caseRef(k), Expect: schema.Expectation{Subtree: "Fixture", Codesign: builtBundles(k)}})
			if got := packingSourceInventory(t, directory); !reflect.DeepEqual(got, workspaceFiles) {
				t.Fatal("packing changed the workspace inventory or retained values")
			}
			if got := packingSourceInventory(t, sessionDir); !reflect.DeepEqual(got, sessionFiles) {
				t.Fatal("packing changed the persisted session inventory or revision")
			}
			if got := packingFileDigest(t, k.Image()); got != sourceDigest {
				t.Fatal("packing changed the original native image")
			}
		})
	}
	for _, producer := range []int{15, 26, 27} {
		for profile := range profiles {
			if !seen[fmt.Sprintf("macos-%d/%s", producer, profile)] {
				t.Fatalf("corpus has no packing source for macOS %d/%s", producer, profile)
			}
		}
	}
}

func packingFileDigest(t *testing.T, filename string) string {
	t.Helper()
	sum, err := schema.FileDigest(filename)
	if err != nil {
		t.Fatal(err)
	}
	return sum
}

func packingSourceIdentity(t *testing.T, ctx context.Context, reader filesystem.Reader, rules filesystem.NameRules, identity filesystem.Identity) {
	t.Helper()
	node, err := reader.Stat(ctx, reader.Root())
	if err != nil {
		t.Fatal(err)
	}
	if node.Identity != identity || reader.NameRules() != rules {
		t.Fatal("preservation source lost its native root identity or filename policy")
	}
}

// packingSourceInventory checks names, entry types, modes and complete values
// without following any projected symlink or depending on access timestamps.
func packingSourceInventory(t *testing.T, root string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(root, func(filename string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, filename)
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		value := info.Mode().String()
		switch {
		case info.Mode().IsRegular():
			value += ":" + packingFileDigest(t, filename)
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(filename)
			if err != nil {
				return err
			}
			value += ":" + target
		}
		files[filepath.ToSlash(rel)] = value
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
