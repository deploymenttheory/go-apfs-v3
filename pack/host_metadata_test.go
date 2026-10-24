package pack_test

import (
	"bytes"
	"context"
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type omissionSource struct {
	filesystem.Reader
	id    uint64
	value filesystem.MetadataOmission
}

func (r omissionSource) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	n, err := r.Reader.Stat(ctx, id)
	if id == r.id && err == nil {
		n.MetadataOmissions = []filesystem.MetadataOmission{r.value}
	}
	return n, err
}

func TestPackingReportsHostMetadataOmissionsAndRefusesFalseProvenanceBeforeOutput(t *testing.T) {
	ctx := context.Background()
	clock := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
	for _, format := range []string{"APFS", "HFS+"} {
		t.Run(format, func(t *testing.T) {
			s, err := session.Create(ctx, filepath.Join(t.TempDir(), "session"), session.Options{Names: filesystem.NameRules{Format: format, NormalizationInsensitive: true}, Time: &clock})
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			host := filepath.Join(t.TempDir(), "host")
			if err := os.WriteFile(host, []byte("independent host payload"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Copy(ctx, []string{host}, "/file", session.CopyOptions{FromHost: true, NoAttributes: true}); err != nil {
				t.Fatal(err)
			}
			id, err := s.LookupPath(ctx, "/file", false)
			if err != nil {
				t.Fatal(err)
			}
			omission := filesystem.MetadataOmission{Field: "acl", SourceFormat: "linux-posix-acl", Status: filesystem.MetadataUnsupported, Reason: "captured POSIX ACL conversion unsupported; destination ACL retained"}
			source := omissionSource{s, id, omission}
			want := []filesystem.MetadataOmissionRecord{{Object: id, Path: "/file", MetadataOmission: omission}}
			for _, encoding := range []string{"UDRO", "UDZO"} {
				var out bytes.Buffer
				report, err := pack.Write(ctx, &out, source, pack.Options{Format: encoding, Volume: pack.VolumeOptions{Name: "Host Archive", Capacity: 16 << 20, Time: clock}})
				if err != nil || !reflect.DeepEqual(report.MetadataOmissions, want) || out.Len() == 0 {
					t.Fatal("pack lost durable source metadata provenance", encoding, report.MetadataOmissions, err)
				}
			}
			source.value.Status = "absent"
			var out bytes.Buffer
			if _, err := pack.Write(ctx, &out, source, pack.Options{Volume: pack.VolumeOptions{Name: "Host Archive", Capacity: 16 << 20, Time: clock}}); !errors.Is(err, filesystem.ErrCorrupt) || out.Len() != 0 {
				t.Fatal("false absence provenance reached output", err, out.Len())
			}
			source.value = omission
			destination := filepath.Join(t.TempDir(), "occupied")
			if err := os.WriteFile(destination, []byte("original"), 0600); err != nil {
				t.Fatal(err)
			}
			report, err := pack.Create(ctx, destination, source, pack.Options{Volume: pack.VolumeOptions{Name: "Host Archive", Capacity: 16 << 20, Time: clock}})
			if !errors.Is(err, fs.ErrExist) || len(report.MetadataOmissions) != 0 {
				t.Fatal("unpublished pack reported completed metadata transfer", report, err)
			}
			if got, _ := os.ReadFile(destination); string(got) != "original" {
				t.Fatal("pack replaced an existing destination")
			}
		})
	}
}
