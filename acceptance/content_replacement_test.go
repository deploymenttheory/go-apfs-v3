package acceptance_test

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

type nativeReplacement struct {
	After       string `json:"after"`
	AfterSHA256 string `json:"afterSHA256"`
	Image       string `json:"image"`
	ImageSHA256 string `json:"imageSHA256"`
	Operations  []struct {
		Path    string `json:"path"`
		Object  uint64 `json:"object"`
		Payload string `json:"payload"`
		SHA256  string `json:"sha256"`
		Size    int64  `json:"size"`
	} `json:"operations"`
}

// Native O_TRUNC writes establish the content/fork/link cleanup outcome. The
// preservation API retains source timestamps and marks edited data explicitly;
// native wall-clock write times are retained as evidence, not portable defaults.
func TestNativeContentReplacement(t *testing.T) {
	t.Parallel()
	testFileCorpus(t, "content-replacement", "APFS_NATIVE_REPLACEMENT", "testdata/replacement", 14, nil)
}

func compareReplacement(t *testing.T, reader filesystem.Reader, before fileObservation, dir, caseID, major string) {
	t.Helper()
	ctx := context.Background()
	reference := before.Replacement
	if reference == nil || len(reference.Operations) != 7 || len(before.RawAttributes) != len(before.Entries) {
		t.Fatal("incomplete replacement evidence")
	}
	verifyDigest(t, dir, reference.After, reference.AfterSHA256)
	verifyDigest(t, dir, reference.Image, reference.ImageSHA256)
	var after fileObservation
	decodeEvidence(t, filepath.Join(dir, reference.After), &after)
	if after.Schema != 1 || after.Root != before.Root || len(after.Entries) != len(before.Entries) || len(after.RawAttributes) != len(after.Entries) {
		t.Fatal("incomplete native replacement outcome")
	}
	output := os.Getenv("APFS_REPLACEMENT_OUTPUT")
	if output == "" {
		output = t.TempDir()
	}
	output = filepath.Join(output, "macos-"+major, strings.TrimPrefix(caseID, "content-replacement/"))
	if err := os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	id, err := filesystem.LookupExact(ctx, reader, before.Root)
	if err != nil {
		t.Fatal(err)
	}
	baseline := filepath.Join(output, "before")
	destination := filepath.Join(output, "after")
	if _, err = workspace.Extract(ctx, reader, id, baseline, workspace.Limits{}); err != nil {
		t.Fatal(err)
	}
	source, err := workspace.Open(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var changes []workspace.DataReplacement
	changed := map[uint64]bool{}
	for _, op := range reference.Operations {
		verifyDigest(t, dir, op.Payload, op.SHA256)
		id, err := filesystem.LookupExact(ctx, source, strings.TrimPrefix(op.Path, before.Root+"/"))
		if err != nil || id != op.Object || changed[id] {
			t.Fatal("invalid native operation identity", op, err)
		}
		data, err := block.Open(filepath.Join(dir, op.Payload))
		if err != nil {
			t.Fatal(err)
		}
		defer data.Close()
		if data.Size() != op.Size {
			t.Fatal("replacement input size")
		}
		changes = append(changes, workspace.DataReplacement{Object: id, Data: data})
		changed[id] = true
	}
	report, err := source.ReplaceData(ctx, changes, destination, workspace.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if report.ModifiedFiles != len(changed) {
		t.Fatal("missing modification report", report)
	}
	result, err := workspace.Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if result.ParentManifestSHA256() != source.ManifestSHA256() {
		t.Fatal("missing source provenance")
	}
	beforeByID := map[uint64]nativeFile{}
	for _, entry := range before.Entries {
		beforeByID[entry.Object] = entry
	}
	// Preserve native before timestamps by explicit API policy. Every other field
	// and every content/fork result comes from the actual native after observation.
	expected := after
	expected.Root = "."
	expected.Entries = append([]nativeFile(nil), after.Entries...)
	for i := range expected.Entries {
		n := &expected.Entries[i]
		original, ok := beforeByID[n.Object]
		if !ok {
			t.Fatal("native replacement changed inode identity")
		}
		if changed[n.Object] {
			n.BirthSeconds = original.BirthSeconds
			n.ModifyNS = original.ModifyNS
			n.ChangeNS = original.ChangeNS
			n.AccessNS = original.AccessNS
		}
		n.Path = strings.TrimPrefix(n.Path, before.Root+"/")
		if n.Path == before.Root {
			n.Path = "."
		}
		got, err := result.Stat(ctx, n.Object)
		if err != nil || got.DataModified != changed[n.Object] {
			t.Fatal("replacement provenance flag", n.Path, err)
		}
		originalNode, err := reader.Stat(ctx, n.Object)
		if err != nil || got.Identity != originalNode.Identity {
			t.Fatal("source identity/view changed", err)
		}
	}
	compareFiles(t, result, expected)
	rawAfter := map[uint64]map[string]nativeValue{}
	for _, raw := range after.RawAttributes {
		rawAfter[raw.Object] = raw.Attributes
	}
	for _, raw := range before.RawAttributes {
		for name := range raw.Attributes {
			if _, exists := rawAfter[raw.Object][name]; exists {
				continue
			}
			value, err := result.OpenAttribute(ctx, raw.Object, name)
			if err == nil {
				value.Close()
			}
			if !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("native-removed compression storage survived", name, err)
			}
		}
	}
	for _, raw := range after.RawAttributes {
		for name, want := range raw.Attributes {
			value, err := result.OpenAttribute(ctx, raw.Object, name)
			if err != nil {
				t.Fatal(err)
			}
			compareValue(t, name, value, want)
		}
	}
	for _, entry := range after.Entries {
		if !changed[entry.Object] {
			continue
		}
		raw, err := result.OpenRawData(ctx, entry.Object)
		if err != nil {
			t.Fatal(err)
		}
		compareValue(t, entry.Path+" replacement storage", raw, nativeValue{int64(entry.Size), entry.SHA256})
	}
	// Original workspace remains independently verifiable and byte-for-byte intact.
	unchanged, err := workspace.Open(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	defer unchanged.Close()
	if unchanged.ManifestSHA256() != source.ManifestSHA256() || unchanged.Report().ModifiedFiles != 0 {
		t.Fatal("baseline changed")
	}
	t.Logf("matched %d native replacements across %d entries; source timestamps and baseline preserved", len(changes), len(after.Entries))
}
