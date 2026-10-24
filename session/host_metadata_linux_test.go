package session

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"golang.org/x/sys/unix"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestHostPOSIXACLIsReportedAsUnsupportedSecurityWhileBinaryAndEmptyXattrsSurvive(t *testing.T) {
	ctx := context.Background()
	s, _ := newSession(t)
	source := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(source, []byte("source data"), 0640); err != nil {
		t.Fatal(err)
	}
	// Linux xattr ABI v2: owner rw, named UID60001 read, group read,
	// mask read, other none. This is not Darwin filesec.
	acl, _ := hex.DecodeString("0200000001000600ffffffff0200040061ea000004000400ffffffff10000400ffffffff20000000ffffffff")
	if err := unix.Lsetxattr(source, "system.posix_acl_access", acl, 0); err != nil {
		t.Fatal("ordinary Linux ACL control", err)
	}
	values := map[string][]byte{"user.binary": {0, 255, 1, 0}, "user.empty": {}}
	for name, value := range values {
		if err := unix.Lsetxattr(source, name, value, 0); err != nil {
			t.Fatal(err)
		}
	}
	report, err := s.Copy(ctx, []string{source}, "/file", CopyOptions{FromHost: true, Archive: true})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, v := range report.MetadataOmissions {
		if v.Field == "acl" {
			found = v.SourceFormat == "linux-posix-acl" && v.Status == filesystem.MetadataUnsupported
		}
	}
	if !found || len(report.OmittedAttributes) != 1 {
		t.Fatal("captured POSIX ACL was silently lost or claimed Darwin-compatible", report)
	}
	id, err := s.LookupPath(ctx, "/file", false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.OpenAttribute(ctx, id, "system.posix_acl_access"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("foreign ACL was copied as an ordinary Darwin xattr", err)
	}
	for name, want := range values {
		v, err := s.OpenAttribute(ctx, id, name)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, v.Size())
		_, err = v.ReadAt(got, 0)
		if err != nil && !errors.Is(err, io.EOF) {
			t.Fatal(err)
		}
		if err := v.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatal("binary/empty host attribute changed", name, got)
		}
	}
	got := make([]byte, len(acl))
	n, err := unix.Lgetxattr(source, "system.posix_acl_access", got)
	if err != nil || n != len(acl) || !bytes.Equal(got, acl) {
		t.Fatal("source ACL changed", err)
	}
	absent := filepath.Join(t.TempDir(), "absent")
	if err := os.WriteFile(absent, nil, 0600); err != nil {
		t.Fatal(err)
	}
	report, err = s.Copy(ctx, []string{absent}, "/absent", CopyOptions{FromHost: true, Archive: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range report.MetadataOmissions {
		if v.Path == "/absent" && v.Field == "acl" {
			t.Fatal("observed ACL absence was treated as unsupported", v)
		}
	}
}
