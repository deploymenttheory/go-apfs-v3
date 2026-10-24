package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestHostArchiveCLIReportsPersistentMetadataAndKeepsSameInputPackingDeterministic(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "file"), []byte("host input"), 0640); err != nil {
		t.Fatal(err)
	}
	clock := time.Date(2025, 6, 7, 8, 9, 10, 0, time.UTC)
	access := time.Now().Add(48 * time.Hour)
	for _, path := range []string{filepath.Join(source, "file"), source} {
		if err := os.Chtimes(path, access, clock); err != nil {
			t.Fatal(err)
		}
	}
	invoke := func(args ...string) []byte {
		t.Helper()
		var out, diag bytes.Buffer
		if err := run(ctx, args, nil, &out, &diag); err != nil {
			t.Fatal(args, err, diag.String())
		}
		return out.Bytes()
	}
	var first pack.Report
	var firstImage [32]byte
	for i, name := range []string{"first.dmg", "second.dmg"} {
		destination := filepath.Join(root, name)
		data := invoke("pack", "--filesystem", "apfs", "--time", clock.Format(time.RFC3339), "--json", source, destination)
		var report pack.Report
		if err := json.Unmarshal(data, &report); err != nil {
			t.Fatal(err, string(data))
		}
		if runtime.GOOS != "darwin" && len(report.MetadataOmissions) == 0 {
			t.Fatal("pack discarded host metadata conversion outcomes", string(data))
		}
		for _, v := range report.MetadataOmissions {
			if v.Command != 0 || v.ClockNS != 0 || v.Path == "" {
				t.Fatal("pack invented command-event provenance", v)
			}
		}
		image, err := os.ReadFile(destination)
		if err != nil {
			t.Fatal(err)
		}
		if i == 0 {
			first = report
			firstImage = sha256.Sum256(image)
		} else if !reflect.DeepEqual(first.MetadataOmissions, report.MetadataOmissions) || firstImage != sha256.Sum256(image) {
			t.Fatal("same host input changed plaintext bytes or provenance")
		}
	}
	scratch := filepath.Join(root, "scratch")
	invoke("session", "create", "--filesystem", "apfs", "--scratch-dir", scratch, "--time", clock.Format(time.RFC3339), "build")
	data := invoke("cp", "--scratch-dir", scratch, "--session", "build", "--from-host", "-a", "--json", source+string(filepath.Separator), "/")
	var copied session.Report
	if err := json.Unmarshal(data, &copied); err != nil {
		t.Fatal(err, string(data))
	}
	data = invoke("pack", "--scratch-dir", scratch, "--session", "build", "--time", clock.Format(time.RFC3339), "--json", filepath.Join(root, "reopened.dmg"))
	var packed pack.Report
	if err := json.Unmarshal(data, &packed); err != nil {
		t.Fatal(err, string(data))
	}
	if !reflect.DeepEqual(copied.MetadataOmissions, packed.MetadataOmissions) {
		t.Fatal("CLI reopen/pack lost precise host metadata outcomes", copied.MetadataOmissions, packed.MetadataOmissions)
	}
	for _, v := range copied.MetadataOmissions {
		if v.Status != filesystem.MetadataUnavailable && v.Status != filesystem.MetadataUnsupported {
			t.Fatal("invented metadata availability", v)
		}
	}
}
