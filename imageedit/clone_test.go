package imageedit_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/hfsplus"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/internal/filesec"
)

func cloneImageReader(t *testing.T, name, kind string) filesystem.Reader {
	t.Helper()
	image, err := diskimage.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := image.Close(); err != nil {
			t.Error(err)
		}
	})
	part, err := image.Partition(0)
	if err != nil {
		t.Fatal(err)
	}
	if kind == "APFS" || kind == "APFSX" {
		c, err := apfs.Open(part)
		if err != nil {
			t.Fatal(err)
		}
		return &c.Volumes[0]
	}
	v, err := hfsplus.Open(part)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func cloneImageValue(t *testing.T, r filesystem.Reader, p, attribute string) []byte {
	t.Helper()
	ctx := context.Background()
	id, err := filesystem.Lookup(ctx, r, p)
	if err != nil {
		t.Fatal(err)
	}
	var value filesystem.Value
	if attribute == "" {
		value, err = r.OpenData(ctx, id)
	} else {
		value, err = r.OpenAttribute(ctx, id, attribute)
	}
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
	if err != nil {
		t.Fatal(err)
	}
	if err := value.Close(); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestImageCloneCopyReportsStorageChoiceAndReplacesOnlyNamedDestination(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"APFS", "APFSX", "HFS+", "HFSX"} {
		t.Run(kind, func(t *testing.T) {
			source := fixture(t, kind)
			prepared := filepath.Join(t.TempDir(), "prepared.dmg")
			_, err := imageedit.Apply(ctx, source, prepared, imageedit.Options{Time: clock, ActorUID: filesystem.Observed(uint32(0))}, []imageedit.Change{{Path: "/file", ResourceFork: true, Data: bytes.NewReader([]byte("source fork"))}, {Operation: "xattr", Path: "/file", Attribute: "org.go-apfs.attr", Data: bytes.NewReader(bytes.Repeat([]byte("attribute"), 600))}, {Path: "/target", Data: bytes.NewReader([]byte("old destination"))}, {Operation: "ln", Path: "/target", Destination: "/old-alias"}})
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(prepared)
			if err != nil {
				t.Fatal(err)
			}
			for _, format := range []string{"UDRO", "UDZO"} {
				t.Run(format, func(t *testing.T) {
					output := filepath.Join(t.TempDir(), "cloned.dmg")
					report, err := imageedit.Copy(ctx, prepared, output, imageedit.Options{Time: clock, Format: format, ActorUID: filesystem.Observed(uint32(0))}, []string{"/file"}, "/target", imageedit.CopyOptions{Clone: true, Preserve: true})
					if err != nil {
						t.Fatal(err)
					}
					cloned := kind == "APFS" || kind == "APFSX"
					if len(report.Clones) != 1 || report.Clones[0].Cloned != cloned || (report.Clones[0].Fallback != "") == cloned {
						t.Fatal("copy storage choice was not reported", report.Clones)
					}
					r := cloneImageReader(t, output, kind)
					fileID, _ := filesystem.Lookup(ctx, r, "/file")
					targetID, _ := filesystem.Lookup(ctx, r, "/target")
					oldID, _ := filesystem.Lookup(ctx, r, "/old-alias")
					if fileID == targetID || targetID == oldID || fileID == 0 || targetID == 0 || oldID == 0 {
						t.Fatal("clone/fallback reused source or overwritten hardlink inode")
					}
					if got := cloneImageValue(t, r, "/target", ""); string(got) != "existing" {
						t.Fatal(string(got))
					}
					if got := cloneImageValue(t, r, "/old-alias", ""); string(got) != "old destination" {
						t.Fatal("copy altered another destination hardlink", string(got))
					}
					if got := cloneImageValue(t, r, "/target", filesystem.ResourceFork); string(got) != "source fork" {
						t.Fatal("fork", string(got))
					}
					if got := cloneImageValue(t, r, "/target", "org.go-apfs.attr"); !bytes.Equal(got, bytes.Repeat([]byte("attribute"), 600)) {
						t.Fatal("attribute mismatch")
					}
					after, err := os.ReadFile(prepared)
					if err != nil || sha256.Sum256(after) != sha256.Sum256(before) {
						t.Fatal("copy changed original image", err)
					}
				})
			}
		})
	}
}

func TestImageCloneCopyFailuresPublishNothingAndPreserveSource(t *testing.T) {
	ctx := context.Background()
	base := fixture(t, "APFS")
	source := filepath.Join(t.TempDir(), "source.dmg")
	if _, err := imageedit.Apply(ctx, base, source, imageedit.Options{Time: clock}, []imageedit.Change{{Path: "/occupied", Data: bytes.NewReader([]byte("keep destination"))}}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, to string
		options  imageedit.CopyOptions
		want     error
	}{
		{"self", "/file", imageedit.CopyOptions{Clone: true}, filesystem.ErrConflict},
		{"no-clobber", "/occupied", imageedit.CopyOptions{Clone: true, NoClobber: true}, fs.ErrExist},
		{"no-attributes", "/new", imageedit.CopyOptions{Clone: true, NoAttributes: true}, fs.ErrInvalid},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "absent.dmg")
			_, err := imageedit.Copy(ctx, source, out, imageedit.Options{Time: clock}, []string{"/file"}, tc.to, tc.options)
			if !errors.Is(err, tc.want) {
				t.Fatal(err)
			}
			if _, err := os.Stat(out); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("failed clone published output", err)
			}
		})
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(after, before) {
		t.Fatal("failed clone changed original", err)
	}
}

func TestOrderedCopyBatchMaterializesSourceAttributesBeforeCloning(t *testing.T) {
	ctx := context.Background()
	base := fixture(t, "APFS")
	source := filepath.Join(t.TempDir(), "source.dmg")
	if _, err := imageedit.Apply(ctx, base, source, imageedit.Options{Time: clock}, []imageedit.Change{{Path: "/file", ResourceFork: true, Data: bytes.NewReader([]byte("pending copied fork"))}, {Operation: "xattr", Path: "/file", Attribute: "org.go-apfs.pending", Data: bytes.NewReader([]byte("pending copied attribute"))}}); err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(t.TempDir(), "batch.dmg")
	report, err := imageedit.CopyBatch(ctx, source, output, imageedit.Options{Time: clock}, []imageedit.CopyCommand{{Sources: []string{"/file"}, Destination: "/copied", Options: imageedit.CopyOptions{Preserve: true}}, {Sources: []string{"/copied"}, Destination: "/cloned", Options: imageedit.CopyOptions{Clone: true}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Clones) != 1 || !report.Clones[0].Cloned {
		t.Fatal(report.Clones)
	}
	r := cloneImageReader(t, output, "APFS")
	if got := cloneImageValue(t, r, "/cloned", ""); string(got) != "existing" {
		t.Fatal(string(got))
	}
	if got := cloneImageValue(t, r, "/cloned", filesystem.ResourceFork); string(got) != "pending copied fork" {
		t.Fatal("clone preceded source fork materialization", string(got))
	}
	if got := cloneImageValue(t, r, "/cloned", "org.go-apfs.pending"); string(got) != "pending copied attribute" {
		t.Fatal("clone preceded source attribute materialization", string(got))
	}
}

func TestFailedClonePublicationDoesNotReportPublishedSharing(t *testing.T) {
	ctx := context.Background()
	source := fixture(t, "APFS")
	original, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	for _, failure := range []string{"callback", "ignored command", "existing destination"} {
		t.Run(failure, func(t *testing.T) {
			output := filepath.Join(t.TempDir(), "output.dmg")
			clonedScratch := false
			report, err := imageedit.Edit(ctx, source, output, imageedit.Options{Time: clock}, func(editor *imageedit.Editor) error {
				copied, err := editor.Copy([]imageedit.CopyCommand{{Sources: []string{"/file"}, Destination: "/clone", Options: imageedit.CopyOptions{Clone: true}}})
				if err != nil {
					return err
				}
				clonedScratch = len(copied.Clones) == 1 && copied.Clones[0].Cloned
				if failure == "callback" {
					return errors.New("stop before publication")
				}
				if failure == "ignored command" {
					_, _ = editor.Apply([]imageedit.Change{{Path: "/missing/file", Data: bytes.NewReader([]byte("refused"))}})
				}
				if failure == "existing destination" {
					return os.WriteFile(output, []byte("keep existing output"), 0600)
				}
				return nil
			})
			if err == nil || !clonedScratch || len(report.Clones) != 0 {
				t.Fatal("failed image publication reported completed clone sharing", err, clonedScratch, report.Clones)
			}
			data, statErr := os.ReadFile(output)
			if failure == "existing destination" {
				if statErr != nil || string(data) != "keep existing output" {
					t.Fatal("publication replaced existing output", statErr)
				}
			} else if !errors.Is(statErr, fs.ErrNotExist) {
				t.Fatal("failed edit published output", statErr)
			}
		})
	}
	after, err := os.ReadFile(source)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("failed edit changed original", err)
	}
}

func TestImageSymlinkCreationDoesNotInheritRegularFileACL(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"APFS", "HFS+"} {
		t.Run(kind, func(t *testing.T) {
			prepared := filepath.Join(t.TempDir(), "prepared.dmg")
			options := imageedit.Options{Time: clock, ActorUID: filesystem.Observed(uint32(0))}
			_, err := imageedit.Apply(ctx, fixture(t, kind), prepared, options, []imageedit.Change{
				{Operation: "mkdir", Path: "/destination"}, {Operation: "mkdir", Path: "/tree"},
				{Path: "/tree/leaf", Data: bytes.NewReader([]byte("leaf"))},
				{Operation: "ln", Symbolic: true, Path: "leaf", Destination: "/tree/link"},
			})
			if err != nil {
				t.Fatal(err)
			}
			r := cloneImageReader(t, prepared, kind)
			id, err := filesystem.Lookup(ctx, r, "/destination")
			if err != nil {
				t.Fatal(err)
			}
			node, err := r.Stat(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			metadata := node.Metadata
			metadata.ChangeTime = filesystem.Observation[time.Time]{}
			acl := make([]byte, 68)
			binary.BigEndian.PutUint32(acl, filesec.Magic)
			binary.BigEndian.PutUint32(acl[36:], 1)
			binary.BigEndian.PutUint32(acl[60:], 1|filesec.File|filesec.Directory)
			binary.BigEndian.PutUint32(acl[64:], 0x000a82)
			withACL := filepath.Join(t.TempDir(), "parent-acl.dmg")
			if _, err := imageedit.Apply(ctx, prepared, withACL, options, []imageedit.Change{{Operation: "copy-metadata", Path: "/destination", Metadata: &metadata, Attributes: map[string]block.Source{filesec.Attribute: bytes.NewReader(acl)}}}); err != nil {
				t.Fatal(err)
			}
			output := filepath.Join(t.TempDir(), "copied.dmg")
			if _, err := imageedit.Edit(ctx, withACL, output, options, func(editor *imageedit.Editor) error {
				if _, err := editor.Copy([]imageedit.CopyCommand{{Sources: []string{"/tree"}, Destination: "/destination/copied", Options: imageedit.CopyOptions{Clone: true, Recursive: true}}}); err != nil {
					return err
				}
				_, err := editor.Apply([]imageedit.Change{{Operation: "ln", Symbolic: true, Path: "copied/leaf", Destination: "/destination/direct-link"}})
				return err
			}); err != nil {
				t.Fatal(err)
			}
			r = cloneImageReader(t, output, kind)
			for _, name := range []string{"/destination/copied/link", "/destination/direct-link", "/destination/copied/leaf", "/destination/copied"} {
				id, err := filesystem.LookupExact(ctx, r, name)
				if err != nil {
					t.Fatal(err)
				}
				value, err := r.OpenAttribute(ctx, id, filesec.Attribute)
				if strings.HasSuffix(name, "link") {
					if !errors.Is(err, fs.ErrNotExist) {
						t.Error("new symlink inherited an ACL", name, err)
					}
				} else if err != nil {
					t.Fatal("regular file/directory lost inherited ACL", name, err)
				}
				if value != nil {
					if err := value.Close(); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
}
