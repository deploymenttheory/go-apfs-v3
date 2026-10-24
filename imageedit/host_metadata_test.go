package imageedit_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
	"github.com/deploymenttheory/go-apfs-v3/inspect"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestHostImageCopyOmissionsDescribeTheirEditorCallAndRemainUnpublishedOnFailure(t *testing.T) {
	ctx := context.Background()
	for _, format := range []string{"APFS", "HFS+"} {
		t.Run(format, func(t *testing.T) {
			source := fixture(t, format)
			before, err := os.ReadFile(source)
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(before)
			host := filepath.Join(t.TempDir(), "host")
			input := []byte("host preservation input")
			if err := os.WriteFile(host, input, 0600); err != nil {
				t.Fatal(err)
			}
			destination := filepath.Join(t.TempDir(), "edited.dmg")
			var outcomes []filesystem.MetadataOmissionRecord
			report, err := imageedit.Edit(ctx, source, destination, imageedit.Options{Time: clock}, func(e *imageedit.Editor) error {
				if _, err := e.Apply([]imageedit.Change{{Operation: "mkdir", Path: "/target"}}); err != nil {
					return err
				}
				copy, err := e.Copy([]imageedit.CopyCommand{{Sources: []string{host}, Destination: "/target/imported", Options: imageedit.CopyOptions{FromHost: true, Archive: true}}})
				if err != nil {
					return err
				}
				outcomes = copy.MetadataOmissions
				for _, v := range outcomes {
					if v.Command != 2 || v.ClockNS != clock.UnixNano() || v.Path != "/target/imported" {
						t.Fatal("COPY outcome has ambiguous call/path/clock", v)
					}
				}
				if runtime.GOOS != "darwin" && len(outcomes) == 0 {
					t.Fatal("foreign metadata omission control was not established")
				}
				_, err = e.Apply([]imageedit.Change{{Operation: "rm", Path: "/target/imported"}})
				return err
			})
			if err != nil || !reflect.DeepEqual(report.MetadataOmissions, outcomes) {
				t.Fatal("later removal rewrote an earlier COPY outcome", err, report.MetadataOmissions, outcomes)
			}
			img, err := diskimage.Open(destination)
			if err != nil {
				t.Fatal(err)
			}
			inspected, err := inspect.Image(ctx, img)
			if err != nil {
				img.Close()
				t.Fatal(err)
			}
			var reader filesystem.Reader
			for _, p := range inspected.Partitions {
				if p.APFS != nil {
					reader = &p.APFS.Volumes[0]
				} else if p.HFSPlus != nil {
					reader = p.HFSPlus
				}
			}
			if reader == nil {
				img.Close()
				t.Fatal("edited image lost filesystem")
			}
			if _, err := filesystem.Lookup(ctx, reader, "/target/imported"); !errors.Is(err, fs.ErrNotExist) {
				img.Close()
				t.Fatal("removed COPY outcome was presented as a surviving path", err)
			}
			if err := img.Close(); err != nil {
				t.Fatal(err)
			}
			failed := filepath.Join(t.TempDir(), "failed.dmg")
			cause := errors.New("later callback refused publication")
			report, err = imageedit.Edit(ctx, source, failed, imageedit.Options{Time: clock}, func(e *imageedit.Editor) error {
				if _, err := e.Copy([]imageedit.CopyCommand{{Sources: []string{host}, Destination: "/imported", Options: imageedit.CopyOptions{FromHost: true, Archive: true}}}); err != nil {
					return err
				}
				return cause
			})
			if !errors.Is(err, cause) || len(report.MetadataOmissions) != 0 {
				t.Fatal("unpublished image claimed committed COPY outcomes", err, report.MetadataOmissions)
			}
			if _, err := os.Lstat(failed); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("failed copy published a partial image", err)
			}
			after, err := os.ReadFile(source)
			if err != nil || sha256.Sum256(after) != digest {
				t.Fatal("copy changed original image", err)
			}
			if after, err := os.ReadFile(host); err != nil || string(after) != string(input) {
				t.Fatal("copy changed original host bytes", err)
			}
		})
	}
}
