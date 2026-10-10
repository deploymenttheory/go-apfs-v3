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

type nativeTreeOperation struct {
	Attributes []struct {
		Name   string `json:"name"`
		Data   string `json:"data"`
		SHA256 string `json:"sha256"`
	} `json:"attributes,omitempty"`
	Op       workspace.Operation  `json:"op"`
	Path     string               `json:"path"`
	From     string               `json:"from,omitempty"`
	To       string               `json:"to,omitempty"`
	Target   string               `json:"target,omitempty"`
	Data     string               `json:"data,omitempty"`
	Metadata *filesystem.Metadata `json:"metadata,omitempty"`
	Object   uint64               `json:"nativeObject,omitempty"`
	Errno    int                  `json:"errno,omitempty"`
	Stored   string               `json:"stored,omitempty"`
}
type nativeTreeEdits struct {
	Operations    []nativeTreeOperation `json:"operations"`
	Rejections    []nativeTreeOperation `json:"rejections"`
	Names         []nativeTreeOperation `json:"nameProbes"`
	After         string                `json:"after"`
	AfterSHA256   string                `json:"afterSHA256"`
	Image         string                `json:"image"`
	ImageSHA256   string                `json:"imageSHA256"`
	Payload       string                `json:"payload"`
	PayloadSHA256 string                `json:"payloadSHA256"`
}

func TestNativeTreeEdits(t *testing.T) {
	testFileCorpus(t, "tree-edits", "APFS_NATIVE_TREE_EDITS", "testdata/tree-edits", 18, nil)
}
func treeChange(t *testing.T, op nativeTreeOperation, dir string) workspace.Change {
	t.Helper()
	c := workspace.Change{Op: op.Op, Path: op.Path, To: op.To, Target: op.Target, Metadata: op.Metadata}
	if c.Op == workspace.CreateHardLink {
		c.Path = op.From
		c.To = op.Path
	}
	if op.Data != "" {
		f, err := block.Open(filepath.Join(dir, op.Data))
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
	for _, a := range op.Attributes {
		verifyDigest(t, dir, a.Data, a.SHA256)
		f, err := block.Open(filepath.Join(dir, a.Data))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			if err := f.Close(); err != nil {
				t.Error(err)
			}
		})
		if c.Attributes == nil {
			c.Attributes = map[string]block.Source{}
		}
		c.Attributes[a.Name] = f
	}
	return c
}
func compareTreeEdits(t *testing.T, reader filesystem.Reader, before fileObservation, dir, caseID, major string) {
	t.Helper()
	ctx := context.Background()
	ref := before.TreeEdits
	if ref == nil || len(ref.Operations) != 18 || len(ref.Rejections) != 8 || len(ref.Names) != 6 {
		t.Fatal("incomplete tree edit evidence")
	}
	verifyDigest(t, dir, ref.After, ref.AfterSHA256)
	verifyDigest(t, dir, ref.Image, ref.ImageSHA256)
	verifyDigest(t, dir, ref.Payload, ref.PayloadSHA256)
	var after fileObservation
	decodeEvidence(t, filepath.Join(dir, ref.After), &after)
	if after.Schema != 1 || after.Root != before.Root || len(after.RawAttributes) != len(after.Entries) {
		t.Fatal("incomplete native after observation")
	}
	output := os.Getenv("APFS_TREE_EDIT_OUTPUT")
	if output == "" {
		output = t.TempDir()
	}
	output = filepath.Join(output, "macos-"+major, strings.TrimPrefix(caseID, "tree-edits/"))
	if err := os.MkdirAll(output, 0700); err != nil {
		t.Fatal(err)
	}
	id, err := filesystem.LookupExact(ctx, reader, before.Root)
	if err != nil {
		t.Fatal(err)
	}
	baseline := filepath.Join(output, "before")
	destination := filepath.Join(output, "after")
	if _, err := workspace.Extract(ctx, reader, id, baseline, workspace.Limits{}); err != nil {
		t.Fatal(err)
	}
	source, err := workspace.Open(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	var changes []workspace.Change
	creation := map[uint64]filesystem.Metadata{}
	for _, op := range ref.Operations {
		changes = append(changes, treeChange(t, op, dir))
		if op.Metadata != nil {
			if op.Object == 0 {
				t.Fatal("missing native creation identity")
			}
			creation[op.Object] = *op.Metadata
		}
	}
	report, err := source.Edit(ctx, changes, destination, workspace.Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if report.CreatedObjects != 5 || report.ModifiedFiles != 4 {
		t.Fatal("edit report", report)
	}
	result, err := workspace.Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if result.ParentManifestSHA256() != source.ManifestSHA256() {
		t.Fatal("lost parent provenance")
	}
	originals := map[uint64]nativeFile{}
	for _, e := range before.Entries {
		originals[e.Object] = e
	}
	mapped := map[uint64]uint64{}
	reverse := map[uint64]uint64{}
	expected := after
	expected.Root = "."
	expected.Entries = append([]nativeFile(nil), after.Entries...)
	modified := map[uint64]bool{}
	for i := range expected.Entries {
		n := &expected.Entries[i]
		nativeID := n.Object
		n.Path = strings.TrimPrefix(n.Path, before.Root+"/")
		if n.Path == before.Root {
			n.Path = "."
		}
		id, err := filesystem.LookupExact(ctx, result, n.Path)
		if err != nil {
			t.Fatal(n.Path, err)
		}
		got, err := result.Stat(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if previous, ok := mapped[nativeID]; ok && previous != id {
			t.Fatal("split native hard-link identity")
		}
		if previous, ok := reverse[id]; ok && previous != nativeID {
			t.Fatal("merged unrelated native objects")
		}
		mapped[nativeID] = id
		reverse[id] = nativeID
		n.Object = id
		if m, created := creation[nativeID]; created {
			if !got.Created || !strings.HasPrefix(got.Identity.Volume, "workspace:") || got.Identity.View != 0 {
				t.Fatal("created object impersonates native inode", got)
			}
			n.BirthSeconds = m.BirthTime.Value.Unix()
			n.ModifyNS = m.ModifyTime.Value.UnixNano()
			n.ChangeNS = m.ChangeTime.Value.UnixNano()
			n.AccessNS = m.AccessTime.Value.UnixNano()
			if got.DataModified != (n.Mode&0170000 == 0100000) {
				t.Fatal("creation contents provenance")
			}
			if got.LinksModified != (n.Mode&0170000 == 0100000 && n.Links > 1) {
				t.Fatal("new link provenance")
			}
		} else {
			original, ok := originals[nativeID]
			if !ok {
				t.Fatal("unexpected native object")
			}
			old, err := source.Stat(ctx, nativeID)
			if err != nil {
				t.Fatal(err)
			}
			if got.Created || got.Identity != old.Identity {
				t.Fatal("source identity changed")
			}
			n.BirthSeconds = original.BirthSeconds
			n.ModifyNS = original.ModifyNS
			n.ChangeNS = original.ChangeNS
			n.AccessNS = original.AccessNS
			if got.DataModified != (original.SHA256 != n.SHA256 && n.Mode&0170000 == 0100000) {
				t.Fatal("replacement provenance")
			}
			if got.LinksModified != (n.Mode&0170000 != 0040000 && original.Links != n.Links) {
				t.Fatal("link change provenance")
			}
		}
		if got.DataModified {
			modified[id] = true
		}
	}
	compareFiles(t, result, expected)
	for _, raw := range after.RawAttributes {
		id, ok := mapped[raw.Object]
		if !ok {
			t.Fatal("missing raw attribute object")
		}
		for name, want := range raw.Attributes {
			value, err := result.OpenAttribute(ctx, id, name)
			if err != nil {
				t.Fatal(err)
			}
			compareValue(t, name, value, want)
		}
		if modified[id] {
			value, err := result.OpenRawData(ctx, id)
			if err != nil {
				t.Fatal(err)
			}
			for _, e := range expected.Entries {
				if e.Object == id {
					compareValue(t, "edited raw data", value, nativeValue{int64(e.Size), e.SHA256})
					break
				}
			}
		}
	}
	for _, op := range ref.Rejections {
		c := treeChange(t, op, dir)
		if c.Op == workspace.CreateFile {
			m := *creationMetadata(creation)
			m.Mode = filesystem.Observed(uint32(0100640))
			c.Metadata = &m
		}
		dest := filepath.Join(t.TempDir(), "rejected")
		if op.Errno == 0 {
			t.Fatal("missing native rejection")
		}
		if _, err := result.Edit(ctx, []workspace.Change{c}, dest, workspace.Limits{}); err == nil {
			t.Fatal("native rejected operation admitted", op)
		}
		if _, err := os.Stat(dest); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("failed preflight wrote output", err)
		}
	}
	for _, op := range ref.Names {
		c := treeChange(t, op, dir)
		if c.Metadata == nil {
			m := *creationMetadata(creation)
			m.Mode = filesystem.Observed(uint32(0100640))
			c.Metadata = &m
		}
		dest := filepath.Join(t.TempDir(), "name")
		_, err := source.Edit(ctx, []workspace.Change{c}, dest, workspace.Limits{})
		if op.Errno != 0 {
			if !errors.Is(err, filesystem.ErrLimit) {
				t.Fatal("native name length rejection", err)
			}
			continue
		}
		if err != nil {
			t.Fatal("native admitted name rejected", err)
		}
		w, err := workspace.Open(ctx, dest)
		if err != nil {
			t.Fatal(err)
		}
		_, err = filesystem.LookupExact(ctx, w, op.Stored)
		w.Close()
		if err != nil {
			t.Fatal("native stored spelling", err)
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
	t.Logf("matched %d native tree operations, %d rejections, %d filename boundaries and %d final entries", len(changes), len(ref.Rejections), len(ref.Names), len(after.Entries))
}
func creationMetadata(values map[uint64]filesystem.Metadata) *filesystem.Metadata {
	for _, v := range values {
		return &v
	}
	return nil
}
