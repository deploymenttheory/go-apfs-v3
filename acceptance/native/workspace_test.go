package native

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func workspaceEvidence() (workspaceDocument, map[string][]byte, schema.View) {
	when := time.Unix(1234, 0).UTC()
	data := []byte("hello")
	digest := sha256.Sum256(data)
	sum := hex.EncodeToString(digest[:])
	var root workspaceObject
	root.Node.Identity.Object, root.Node.Identity.Volume = 2, "native-volume"
	root.Node.Metadata.Mode = workspaceField[uint32]{2, 0040755}
	root.Node.Metadata.UID = workspaceField[uint32]{2, 501}
	root.Node.Metadata.GID = workspaceField[uint32]{2, 20}
	root.Node.Metadata.BSDFlags = workspaceField[uint32]{2, 0}
	root.Node.Metadata.BirthTime = workspaceField[time.Time]{2, when}
	root.Node.Metadata.ModifyTime = root.Node.Metadata.BirthTime
	root.Node.Metadata.ChangeTime = root.Node.Metadata.BirthTime
	root.Node.Metadata.AccessTime = root.Node.Metadata.BirthTime
	file := root
	file.Node.Identity.Object = 3
	file.Node.Metadata.Mode.Value = 0100644
	file.Node.Size = 5
	file.Node.Links = workspaceField[uint32]{2, 1}
	file.Node.Compression.State = 1
	file.Data = &workspaceBlob{sum, 5}
	file.Raw = &workspaceBlob{sum, 5}
	doc := workspaceDocument{Schema: 1, Root: 2, Objects: []workspaceObject{root, file}, Entries: []workspaceEntry{{Object: 2, Host: "files", Materialized: "directory"}, {Parent: 2, Name: []byte("hello.txt"), Object: 3, Host: "files/hello.txt", Materialized: "file"}}}
	doc.Names.Format = "APFS"
	doc.Names.NormalizationInsensitive = true
	files := map[string][]byte{"files/": nil, "metadata/": nil, "metadata/blobs/": nil, "files/hello.txt": data, "metadata/blobs/" + sum: data}
	e := schema.Entry{Path: "Fixture", NameBytes: hex.EncodeToString([]byte("Fixture")), Kind: "dir", ID: 2, Mode: 0755, UID: 501, GID: 20, Times: schema.Times{Birth: when.UnixNano(), Modify: when.UnixNano(), Change: when.UnixNano(), Access: when.UnixNano()}}
	f := e
	f.Path, f.NameBytes, f.Kind, f.ID, f.Mode, f.Links, f.Size, f.SHA256 = "Fixture/hello.txt", hex.EncodeToString([]byte("hello.txt")), "file", 3, 0644, 1, 5, sum
	return doc, files, schema.View{Entries: []schema.Entry{e, f}}
}

func TestEveryHostsWorkspaceReceivesAnIndependentVerdict(t *testing.T) {
	ref := schema.CaseRef{Producer: 15, Recipe: "workspace-edits", Profile: "apfs", Stage: "before"}
	expect := schema.Expectation{Subtree: "Fixture", Workspace: &schema.WorkspaceExpectation{Policy: "preserve"}}
	hosts := map[string]HostOutputs{}
	var view schema.View
	for _, host := range []string{"darwin", "linux", "windows"} {
		doc, files, native := workspaceEvidence()
		view = native
		if host == "windows" {
			doc.Objects[1].Node.Metadata.UID.Value = 99
		}
		filename := writeWorkspaceEvidence(t, doc, files)
		sum, err := schema.FileDigest(filename)
		if err != nil {
			t.Fatal(err)
		}
		output := schema.Output{Name: "workspace", File: filepath.Base(filename), Source: ref, Operation: "workspace-extract", Format: "workspace", SHA256: sum, Expect: expect}
		hosts[host] = HostOutputs{Dir: filepath.Dir(filename), Manifest: schema.Outputs{Host: host, Lock: "same", Outputs: []schema.Output{output}}}
	}
	pairs, err := Pair(hosts)
	if err != nil {
		t.Fatal(err)
	}
	v := Verifier{Cases: map[string]corpus.Case{CaseKey(ref): {Producer: 15, Recipe: ref.Recipe, Profile: ref.Profile, Stage: ref.Stage, Observation: &schema.Observation{Views: []schema.View{view}}}}}
	diffs, err := v.VerifyOutput(context.Background(), pairs[0])
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(diffs, func(d Difference) bool { return strings.HasPrefix(d.Path, "windows:") && d.Field == "uid" }) {
		t.Fatal("non-primary host's incorrect workspace escaped verification", diffs)
	}
	changed := hosts["windows"]
	changed.Manifest.Outputs[0].Expect.Workspace = &schema.WorkspaceExpectation{Policy: "commands", ClockNS: 99}
	hosts["windows"] = changed
	if _, err := Pair(hosts); err == nil {
		t.Fatal("different workspace policies paired")
	}
}

func TestMissingWorkspaceOutputsCannotDisappearFromNativeVerification(t *testing.T) {
	ref := schema.CaseRef{Producer: 15, Recipe: "workspace-edits", Profile: "apfs", Stage: "before"}
	cases := map[string]corpus.Case{CaseKey(ref): {Producer: 15, Recipe: ref.Recipe, Profile: ref.Profile, Stage: ref.Stage}}
	if err := requireWorkspaceOutputs(nil, cases, 15); err == nil {
		t.Fatal("all hosts omitted the workspace consumer")
	}
	output := schema.Output{Source: ref, Operation: "workspace-extract", Format: "workspace", Expect: schema.Expectation{Subtree: "Fixture", Workspace: &schema.WorkspaceExpectation{Policy: "preserve"}}}
	if err := requireWorkspaceOutputs([]Paired{{Output: output}}, cases, 15); err != nil {
		t.Fatal(err)
	}
	output.Operation = "repack"
	if err := requireWorkspaceOutputs([]Paired{{Output: output}}, cases, 15); err == nil {
		t.Fatal("a sector repack impersonated an extraction consumer")
	}
}

func writeWorkspaceEvidence(t *testing.T, doc workspaceDocument, files map[string][]byte) string {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	files["metadata/manifest.json"] = b
	filename := filepath.Join(t.TempDir(), "workspace.tar.gz")
	f, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	z := gzip.NewWriter(f)
	w := tar.NewWriter(z)
	var names []string
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		h := &tar.Header{Name: name, Mode: 0600, Typeflag: tar.TypeReg, Size: int64(len(files[name]))}
		if strings.HasSuffix(name, "/") {
			h.Name = strings.TrimSuffix(name, "/")
			h.Typeflag = tar.TypeDir
			h.Size = 0
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(files[name]); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return filename
}

func TestWorkspaceVerdictRejectsCorruptAndMisrepresentedExports(t *testing.T) {
	expect := schema.Expectation{Subtree: "Fixture", Workspace: &schema.WorkspaceExpectation{Policy: "preserve"}}
	doc, files, native := workspaceEvidence()
	filename := writeWorkspaceEvidence(t, doc, files)
	if diffs, err := VerifyWorkspaceArchive(filename, "apfs", native, native, expect); err != nil || len(diffs) != 0 {
		t.Fatal("valid independent evidence rejected", diffs, err)
	}
	cases := map[string]func(*workspaceDocument, map[string][]byte){
		"changed blob": func(d *workspaceDocument, f map[string][]byte) {
			f["metadata/blobs/"+d.Objects[1].Data.SHA256] = []byte("wrong")
		},
		"missing raw fork":   func(d *workspaceDocument, f map[string][]byte) { d.Objects[1].Raw = nil },
		"missing projection": func(d *workspaceDocument, f map[string][]byte) { delete(f, "files/hello.txt") },
		"wrong portable spelling": func(d *workspaceDocument, f map[string][]byte) {
			d.Entries[1].Host = "files/other.txt"
			f["files/other.txt"] = f["files/hello.txt"]
			delete(f, "files/hello.txt")
		},
		"unsafe parent":     func(d *workspaceDocument, f map[string][]byte) { d.Entries[1].Host = "files/../metadata/other" },
		"missing directory": func(d *workspaceDocument, f map[string][]byte) { delete(f, "files/") },
		"wrong owner":       func(d *workspaceDocument, f map[string][]byte) { d.Objects[1].Node.Metadata.UID.Value = 99 },
		"wrong timestamp": func(d *workspaceDocument, f map[string][]byte) {
			d.Objects[1].Node.Metadata.ModifyTime.Value = time.Unix(5678, 0)
		},
		"uncaptured metadata":        func(d *workspaceDocument, f map[string][]byte) { d.Objects[1].Node.Metadata.GID.State = 0 },
		"replaced original identity": func(d *workspaceDocument, f map[string][]byte) { d.Objects[1].Node.Created = true },
		"missing graph parent":       func(d *workspaceDocument, f map[string][]byte) { d.Entries[1].Parent = 99 },
		"unexpected source binding":  func(d *workspaceDocument, f map[string][]byte) { d.Parent = strings.Repeat("f", 64) },
		"unreachable object": func(d *workspaceDocument, f map[string][]byte) {
			o := d.Objects[1]
			o.Node.Identity.Object = 4
			d.Objects = append(d.Objects, o)
		},
		"unreferenced bytes": func(d *workspaceDocument, f map[string][]byte) { f["files/extra"] = []byte("unobserved") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			doc, files, native := workspaceEvidence()
			mutate(&doc, files)
			filename := writeWorkspaceEvidence(t, doc, files)
			if diffs, err := VerifyWorkspaceArchive(filename, "apfs", native, native, expect); err == nil && len(diffs) == 0 {
				t.Fatal("invalid workspace received a native verdict")
			}
		})
	}
}

func TestWorkspaceTimestampPolicyRetainsNativeEvidence(t *testing.T) {
	_, _, before := workspaceEvidence()
	after := before
	after.Entries = slices.Clone(before.Entries)
	after.Entries[1].Times.Modify += 100
	expect := schema.Expectation{Subtree: "Fixture", Workspace: &schema.WorkspaceExpectation{Policy: "preserve"}}
	want, err := WorkspaceReference(before, after, expect)
	if err != nil {
		t.Fatal(err)
	}
	if want.Entries[1].Times != before.Entries[1].Times {
		t.Fatal("preservation changed recorded source clocks")
	}
	if after.Entries[1].Times.Modify == before.Entries[1].Times.Modify {
		t.Fatal("projection rewrote captured native evidence")
	}
	expect.Workspace = &schema.WorkspaceExpectation{Policy: "commands", ClockNS: time.Unix(9000, 0).UnixNano()}
	want, err = WorkspaceReference(before, after, expect)
	if err != nil {
		t.Fatal(err)
	}
	if want.Entries[1].Times.Modify != expect.Workspace.ClockNS || want.Entries[1].Times.Birth != before.Entries[1].Times.Birth {
		t.Fatal("command clock changed unrelated source times")
	}
}
