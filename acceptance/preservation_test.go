package acceptance_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/appledouble"
	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

type nativePreservation struct {
	RawAttributes []nativeRawAttributes `json:"rawAttributes"`
	AppleDouble   []struct {
		Path               string                 `json:"path"`
		File               string                 `json:"file"`
		SHA256             string                 `json:"sha256"`
		UnpackedAttributes map[string]nativeValue `json:"unpackedAttributes"`
	} `json:"appleDouble"`
}

// TestNativePreservation proves a portable extraction can be reopened without
// losing the native tree, metadata or bytes. CI retains each host's actual output
// for independent Python verification and Apple copyfile unpack on all three Macs.
func TestNativePreservation(t *testing.T) {
	testFileCorpus(t, "preservation", "APFS_NATIVE_PRESERVATION", "testdata/preservation", 120, nil)
}

func comparePreservation(t *testing.T, reader filesystem.Reader, want fileObservation, dir, caseID, major string) {
	t.Helper()
	ctx := context.Background()
	if want.Preservation == nil || len(want.Preservation.RawAttributes) != len(want.Entries) || len(want.Preservation.AppleDouble) != 3 {
		t.Fatal("incomplete native preservation observations")
	}
	output := os.Getenv("APFS_WORKSPACE_OUTPUT")
	if output == "" {
		output = t.TempDir()
	}
	output = filepath.Join(output, "macos-"+major, strings.TrimPrefix(caseID, "preservation/"))
	if err := os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	rootID, err := filesystem.LookupExact(ctx, reader, want.Root)
	if err != nil {
		t.Fatal(err)
	}
	report, err := workspace.Extract(ctx, reader, rootID, filepath.Join(output, "workspace"), workspace.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if report.MappedNames < 8 || report.SymlinksRecorded < 3 || report.HardLinks+report.HardLinksCopied != 2 {
		t.Fatalf("fixture did not exercise preservation outcomes: %+v", report)
	}
	reopened, err := workspace.Open(ctx, filepath.Join(output, "workspace"))
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	relative := want
	relative.Root = "."
	relative.Entries = append([]nativeFile(nil), want.Entries...)
	for i := range relative.Entries {
		p := strings.TrimPrefix(relative.Entries[i].Path, want.Root+"/")
		if p == want.Root {
			p = "."
		}
		relative.Entries[i].Path = p
	}
	compareFiles(t, reopened, relative)
	if reopened.NameRules() != reader.NameRules() {
		t.Fatal("filename rules changed")
	}
	for _, query := range []string{"EXAMPLE.TXT", "case-pair/NAME", "caf\u00e9", "cafe\u0301", "absent"} {
		original, sourceErr := filesystem.Lookup(ctx, reader, want.Root+"/"+query)
		restored, restoredErr := filesystem.Lookup(ctx, reopened, query)
		if original != restored || (sourceErr == nil) != (restoredErr == nil) || errors.Is(sourceErr, fs.ErrNotExist) != errors.Is(restoredErr, fs.ErrNotExist) {
			t.Fatalf("workspace lookup %q differs from source: %d/%v, %d/%v", query, original, sourceErr, restored, restoredErr)
		}
	}

	for _, raw := range want.Preservation.RawAttributes {
		for name, expected := range raw.Attributes {
			value, err := reopened.OpenAttribute(ctx, raw.Object, name)
			if err != nil {
				t.Fatal(err)
			}
			compareValue(t, name, value, expected)
		}
	}
	// Raw fork reading is qualified independently by the compression family. Here
	// it must survive storage even when it differs from logical file contents.
	for _, n := range want.Entries {
		if n.Mode&0170000 != 0100000 {
			continue
		}
		original, err := reader.OpenRawData(ctx, n.Object)
		if err != nil {
			t.Fatal(err)
		}
		expected := digestSource(t, original)
		if err = original.Close(); err != nil {
			t.Fatal(err)
		}
		value, err := reopened.OpenRawData(ctx, n.Object)
		if err != nil {
			t.Fatal(err)
		}
		compareValue(t, n.Path+" raw data", value, expected)
	}
	if err := os.Mkdir(filepath.Join(output, "appledouble"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, control := range want.Preservation.AppleDouble {
		verifyDigest(t, dir, control.File, control.SHA256)
		source, err := block.Open(filepath.Join(dir, control.File))
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := appledouble.Decode(ctx, source)
		if err != nil {
			source.Close()
			t.Fatal(err)
		}
		// The ordinary fixture avoids native ACL/quarantine packing policy. Compare
		// the dedicated slots and ordinary serialized attributes with native results.
		seen := map[string]nativeValue{}
		for _, a := range decoded.Attributes {
			seen[string(a.Name)] = digestSource(t, a.Value)
		}
		if decoded.ResourceFork.Size() > 0 {
			seen["com.apple.ResourceFork"] = digestSource(t, decoded.ResourceFork)
		}
		if decoded.FinderInfo != [32]byte{} {
			sum := sha256.Sum256(decoded.FinderInfo[:])
			seen["com.apple.FinderInfo"] = nativeValue{32, hex.EncodeToString(sum[:])}
		}
		for name, value := range control.UnpackedAttributes {
			if seen[name] != value {
				t.Fatalf("native AppleDouble %s %s differs: got %+v want %+v", control.File, name, seen[name], value)
			}
		}
		dest, err := os.OpenFile(filepath.Join(output, "appledouble", control.File), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			source.Close()
			t.Fatal(err)
		}
		writeErr := appledouble.Write(ctx, dest, decoded)
		closeErr := dest.Close()
		sourceErr := source.Close()
		if writeErr != nil || closeErr != nil || sourceErr != nil {
			t.Fatal(writeErr, closeErr, sourceErr)
		}
	}
	t.Logf("preserved %d objects, %d entries, %d mapped names; native unpack output retained", report.Objects, report.Entries, report.MappedNames)
}

func digestSource(t *testing.T, source block.Source) nativeValue {
	t.Helper()
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(source, 0, source.Size())); err != nil {
		t.Fatal(err)
	}
	return nativeValue{source.Size(), hex.EncodeToString(h.Sum(nil))}
}

// A small composition check covers historical selection and nested encryption
// without multiplying the large extraction fixture across every reader profile.
func compareHistoricalExtraction(t *testing.T, reader filesystem.Reader, observation fileObservation, view uint64) {
	t.Helper()
	for _, expected := range observation.Entries {
		if expected.Path != "Fixture/generation.txt" {
			continue
		}
		destination := filepath.Join(t.TempDir(), "historical-file")
		if _, err := workspace.Extract(context.Background(), reader, expected.Object, destination, workspace.Limits{}); err != nil {
			t.Fatal(err)
		}
		reopened, err := workspace.Open(context.Background(), destination)
		if err != nil {
			t.Fatal(err)
		}
		defer reopened.Close()
		n, err := reopened.Stat(context.Background(), reopened.Root())
		if err != nil || n.Identity.View != view {
			t.Fatal("extraction lost historical view", n, err)
		}
		expected.Path = "."
		compareFiles(t, reopened, fileObservation{Root: ".", Entries: []nativeFile{expected}})
		return
	}
	t.Fatal("native historical generation file missing")
}

type nativeRawAttributes struct {
	Object     uint64                 `json:"object"`
	Attributes map[string]nativeValue `json:"attributes"`
}
