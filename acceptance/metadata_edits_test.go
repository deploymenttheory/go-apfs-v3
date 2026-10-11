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
	"slices"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

type nativeMetadataOperation struct {
	workspace.Change
	DataFile string `json:"data,omitempty"`
	Object   uint64 `json:"object"`
	Errno    int    `json:"errno,omitempty"`
	Effects  struct {
		Metadata   []string `json:"metadata"`
		Attributes []string `json:"attributes"`
	} `json:"effects"`
}
type nativeMetadataEdits struct {
	Operations []nativeMetadataOperation `json:"operations"`
	Rejections []nativeMetadataOperation `json:"rejections"`
	Inputs     []struct {
		File   string `json:"file"`
		SHA256 string `json:"sha256"`
		Size   int64  `json:"size"`
	} `json:"inputs"`
	Ownership   string `json:"ownership"`
	After       string `json:"after"`
	AfterSHA256 string `json:"afterSHA256"`
	Image       string `json:"image"`
	ImageSHA256 string `json:"imageSHA256"`
}

func TestNativeMetadataEdits(t *testing.T) {
	t.Parallel()
	testFileCorpus(t, "metadata-edits", "APFS_NATIVE_METADATA_EDITS", "testdata/metadata-edits", 16, nil)
}
func metadataChange(t *testing.T, op nativeMetadataOperation, dir string) workspace.Change {
	t.Helper()
	c := op.Change
	if op.DataFile != "" {
		f, err := block.Open(filepath.Join(dir, op.DataFile))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})
		c.Data = f
	}
	return c
}
func unionNames(a, b []string) []string {
	a = append(slices.Clone(a), b...)
	slices.Sort(a)
	return slices.Compact(a)
}

func compareMetadataEdits(t *testing.T, reader filesystem.Reader, before fileObservation, dir, caseID, major string) {
	t.Helper()
	ctx := context.Background()
	ref := before.MetadataEdits
	if ref == nil || len(ref.Operations) != 29 || len(ref.Rejections) != 7 || len(ref.Inputs) != 6 {
		t.Fatal("incomplete metadata-edit evidence")
	}
	if os.Getenv("APFS_REQUIRED_NATIVE_MAJORS") != "" && ref.Ownership != "changed-with-sudo" {
		t.Fatal("required native matrix must include actual UID/GID changes")
	}
	verifyDigest(t, dir, ref.After, ref.AfterSHA256)
	verifyDigest(t, dir, ref.Image, ref.ImageSHA256)
	inputs := map[string]bool{}
	for _, input := range ref.Inputs {
		verifyDigest(t, dir, input.File, input.SHA256)
		info, err := os.Stat(filepath.Join(dir, input.File))
		if err != nil || info.Size() != input.Size {
			t.Fatal("input size", input, err)
		}
		inputs[input.File] = true
	}
	var after fileObservation
	decodeEvidence(t, filepath.Join(dir, ref.After), &after)
	if after.Schema != 1 || after.Root != before.Root || len(after.Entries) != 17 || len(after.RawAttributes) != 17 {
		t.Fatal("incomplete native after")
	}
	output := os.Getenv("APFS_METADATA_EDIT_OUTPUT")
	if output == "" {
		output = t.TempDir()
	}
	output = filepath.Join(output, "macos-"+major, strings.TrimPrefix(caseID, "metadata-edits/"))
	if err := os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	id, err := filesystem.LookupExact(ctx, reader, before.Root)
	if err != nil {
		t.Fatal(err)
	}
	baseline, destination := filepath.Join(output, "before"), filepath.Join(output, "after")
	if _, err := workspace.Extract(ctx, reader, id, baseline, workspace.Limits{}); err != nil {
		t.Fatal(err)
	}
	source, err := workspace.Open(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	changes := []workspace.Change{}
	metadata, attrs := map[uint64][]string{}, map[uint64][]string{}
	modified := map[uint64]bool{}
	for _, op := range ref.Operations {
		if op.DataFile != "" && !inputs[op.DataFile] {
			t.Fatal("unverified operation input")
		}
		if op.Object == 0 {
			t.Fatal("missing operation identity")
		}
		changes = append(changes, metadataChange(t, op, dir))
		if len(op.Effects.Metadata) != 0 {
			metadata[op.Object] = unionNames(metadata[op.Object], op.Effects.Metadata)
		}
		if len(op.Effects.Attributes) != 0 {
			attrs[op.Object] = unionNames(attrs[op.Object], op.Effects.Attributes)
		}
		if op.Op == workspace.ReplaceFileData {
			modified[op.Object] = true
		}
	}
	report, err := source.Edit(ctx, changes, destination, workspace.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if report.MetadataObjects != len(metadata) || report.AttributeObjects != len(attrs) || report.ModifiedFiles != 1 || report.CreatedObjects != 0 {
		t.Fatal("metadata edit report", report, len(metadata), len(attrs))
	}
	result, err := workspace.Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if result.ParentManifestSHA256() != source.ManifestSHA256() {
		t.Fatal("parent provenance")
	}
	originals := map[uint64]nativeFile{}
	for _, n := range before.Entries {
		originals[n.Object] = n
	}
	expected := after
	expected.Root = "."
	expected.Entries = append([]nativeFile(nil), after.Entries...)
	for i := range expected.Entries {
		n := &expected.Entries[i]
		n.Path = strings.TrimPrefix(n.Path, before.Root+"/")
		if n.Path == before.Root {
			n.Path = "."
		}
		original, ok := originals[n.Object]
		if !ok || n.BirthNS == nil || original.BirthNS == nil {
			t.Fatal("missing original or precise time")
		}
		fields := metadata[n.Object]
		if !slices.Contains(fields, "birthTime") {
			n.BirthSeconds, n.BirthNS = original.BirthSeconds, original.BirthNS
		}
		if !slices.Contains(fields, "modifyTime") {
			n.ModifyNS = original.ModifyNS
		}
		if !slices.Contains(fields, "accessTime") {
			n.AccessNS = original.AccessNS
		}
		n.ChangeNS = original.ChangeNS
		got, err := result.Stat(ctx, n.Object)
		if err != nil {
			t.Fatal(err)
		}
		old, err := source.Stat(ctx, n.Object)
		if err != nil {
			t.Fatal(err)
		}
		if got.Identity != old.Identity || got.Created || got.DataModified != modified[n.Object] ||
			!slices.Equal(got.MetadataModified, fields) || !slices.Equal(got.AttributesModified, attrs[n.Object]) ||
			got.LinksModified != (n.Mode&0170000 != 0040000 && original.Links != n.Links) {
			t.Fatal("metadata provenance", n.Path, got, fields, attrs[n.Object])
		}
	}
	compareFiles(t, result, expected)
	// Compare the complete raw attribute inventory, including removals. Values
	// hidden by native listxattr retain their exact original workspace bytes.
	rawBefore := map[uint64]map[string]nativeValue{}
	for _, raw := range before.RawAttributes {
		rawBefore[raw.Object] = raw.Attributes
	}
	for _, raw := range after.RawAttributes {
		want := map[string]nativeValue{}
		if err := source.ListAttributes(ctx, raw.Object, func(name string) error {
			if _, native := rawBefore[raw.Object][name]; !native {
				v, err := source.OpenAttribute(ctx, raw.Object, name)
				if err != nil {
					return err
				}
				want[name] = nativeValue{Size: v.Size(), SHA256: valueDigest(t, v)}
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		for name, value := range raw.Attributes {
			want[name] = value
		}
		actual := []string{}
		if err := result.ListAttributes(ctx, raw.Object, func(name string) error {
			actual = append(actual, name)
			expected, ok := want[name]
			if !ok {
				t.Fatalf("unexpected retained attribute %d %q", raw.Object, name)
			}
			v, err := result.OpenAttribute(ctx, raw.Object, name)
			if err != nil {
				return err
			}
			compareValue(t, name, v, expected)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		if len(actual) != len(want) {
			t.Fatal("missing attribute")
		}
		original := originals[raw.Object]
		if original.Mode&0170000 == 0100000 {
			v, err := result.OpenRawData(ctx, raw.Object)
			if err != nil {
				t.Fatal(err)
			}
			if modified[raw.Object] {
				for _, n := range after.Entries {
					if n.Object == raw.Object {
						compareValue(t, "replaced raw", v, nativeValue{int64(n.Size), n.SHA256})
						break
					}
				}
			} else {
				old, err := source.OpenRawData(ctx, raw.Object)
				if err != nil {
					t.Fatal(err)
				}
				size := old.Size()
				digest := valueDigest(t, old)
				compareValue(t, "unchanged raw", v, nativeValue{size, digest})
			}
		}
	}
	for _, op := range ref.Rejections {
		if op.Errno == 0 || (op.DataFile != "" && !inputs[op.DataFile]) {
			t.Fatal("missing rejection evidence")
		}
		dest := filepath.Join(t.TempDir(), "rejected")
		if _, err := result.Edit(ctx, []workspace.Change{metadataChange(t, op, dir)}, dest, workspace.Limits{}); err == nil {
			t.Fatal("native rejection admitted", op)
		}
		if _, err := os.Stat(dest); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("preflight published output", err)
		}
	}
	unchanged, err := workspace.Open(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	defer unchanged.Close()
	if unchanged.ManifestSHA256() != source.ManifestSHA256() {
		t.Fatal("baseline changed")
	}
	t.Logf("matched %d native metadata operations, %d rejections and %d final entries", len(changes), len(ref.Rejections), len(after.Entries))
}

func valueDigest(t *testing.T, value filesystem.Value) string {
	t.Helper()
	defer value.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.NewSectionReader(value, 0, value.Size())); err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
