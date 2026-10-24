package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

func TestHostArchiveOmissionsRemainVisibleAfterReopen(t *testing.T) {
	s, directory := newSession(t)
	source := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(source, []byte("host archive input"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err := s.Copy(context.Background(), []string{source}, "/imported", CopyOptions{FromHost: true, Archive: true})
	if err != nil {
		t.Fatal(err)
	}
	acl := false
	for _, v := range report.MetadataOmissions {
		if v.Path != "/imported" || v.Object == 0 {
			t.Fatal("metadata omission has no logical location", v)
		}
		acl = acl || v.Field == "acl"
	}
	if (len(report.OmittedAttributes) != 0) != acl {
		t.Fatal("legacy and typed ACL availability disagree", report)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if !reflect.DeepEqual(reopened.Report().MetadataOmissions, report.MetadataOmissions) {
		t.Fatal("reopening lost precise host metadata outcomes")
	}
	if (len(reopened.Report().OmittedAttributes) != 0) != acl {
		t.Fatal("reopening silently lost the legacy ACL warning")
	}
}

type hostOmissionReader struct {
	filesystem.Reader
	object    uint64
	omissions []filesystem.MetadataOmission
}

func (r hostOmissionReader) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	n, err := r.Reader.Stat(ctx, id)
	if err == nil && id == r.object {
		n.MetadataOmissions = append([]filesystem.MetadataOmission(nil), r.omissions...)
		for _, v := range r.omissions {
			if v.Field == "attributes" {
				n.AttributesUnavailable = true
			}
		}
	}
	return n, err
}

func TestHostMetadataProvenanceSurvivesCaptureCopyReopenAndExportWithoutAliasing(t *testing.T) {
	ctx := context.Background()
	source, _ := newSession(t)
	host := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(host, []byte("original bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Copy(ctx, []string{host}, "/file", CopyOptions{FromHost: true, NoAttributes: true}); err != nil {
		t.Fatal(err)
	}
	id, err := source.LookupPath(ctx, "/file", false)
	if err != nil {
		t.Fatal(err)
	}
	// This is supplied logical source provenance, not a simulated native ACL.
	want := []filesystem.MetadataOmission{{Field: "acl", SourceFormat: "linux-posix-acl", Status: filesystem.MetadataUnsupported, Reason: "captured POSIX ACL conversion unsupported; destination ACL retained"}}
	captured, err := Capture(ctx, hostOmissionReader{source, id, want}, filepath.Join(t.TempDir(), "captured"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	directory := captured.Report().Location
	check := func(r filesystem.Reader, path string) {
		t.Helper()
		id, err := filesystem.Lookup(ctx, r, path)
		if err != nil {
			t.Fatal(err)
		}
		n, err := r.Stat(ctx, id)
		if err != nil || !reflect.DeepEqual(n.MetadataOmissions, want) {
			t.Fatal("host provenance changed", path, n.MetadataOmissions, err)
		}
		n.MetadataOmissions[0].Reason = "caller mutation"
		again, err := r.Stat(ctx, id)
		if err != nil || !reflect.DeepEqual(again.MetadataOmissions, want) {
			t.Fatal("Stat exposed borrowed provenance", err)
		}
	}
	check(captured, "/file")
	if _, err := captured.Copy(ctx, []string{"/file"}, "/copy", CopyOptions{Archive: true}); err != nil {
		t.Fatal(err)
	}
	check(captured, "/file")
	check(captured, "/copy")
	if _, err := captured.Copy(ctx, []string{"/file"}, "/clone", CopyOptions{Clone: true}); err != nil {
		t.Fatal(err)
	}
	check(captured, "/file")
	check(captured, "/clone")
	if err := captured.Close(); err != nil {
		t.Fatal(err)
	}
	captured, err = Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer captured.Close()
	check(captured, "/file")
	check(captured, "/copy")
	report := captured.Report()
	if len(report.MetadataOmissions) != 3 {
		t.Fatal("reopened omission report incomplete", report.MetadataOmissions)
	}
	report.MetadataOmissions[0].Reason = "report mutation"
	if captured.Report().MetadataOmissions[0].Reason != want[0].Reason {
		t.Fatal("Report exposed borrowed provenance")
	}
	exported := filepath.Join(t.TempDir(), "workspace")
	if _, err := captured.Export(ctx, exported); err != nil {
		t.Fatal(err)
	}
	w, err := workspace.Open(ctx, exported)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	check(w, "/file")
	check(w, "/copy")
}

func TestHostMetadataProvenanceRejectsLegacySchemaDowngrades(t *testing.T) {
	ctx := context.Background()
	s, directory := newSession(t)
	document := s.document
	omission := filesystem.MetadataOmission{Field: "acl", SourceFormat: "linux-posix-acl", Status: filesystem.MetadataUnsupported, Reason: "captured foreign ACL conversion unsupported"}
	document.Objects[0].Node.MetadataOmissions = []filesystem.MetadataOmission{omission}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, schema := range []int{1, 2} {
		document.Schema = schema
		data, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(directory, "current"), data, 0600); err != nil {
			t.Fatal(err)
		}
		opened, err := Open(ctx, directory)
		if opened != nil {
			opened.Close()
		}
		if !errors.Is(err, filesystem.ErrCorrupt) {
			t.Fatal("old session schema silently admitted host provenance", schema, err)
		}
	}
}

func TestHostMetadataProvenanceFollowsOnlyFieldsActuallyReplaced(t *testing.T) {
	ctx := context.Background()
	source, _ := newSession(t)
	host := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(host, []byte("source bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/source", "/destination"} {
		if _, err := source.Copy(ctx, []string{host}, path, CopyOptions{FromHost: true, NoAttributes: true}); err != nil {
			t.Fatal(err)
		}
	}
	id, err := source.LookupPath(ctx, "/destination", false)
	if err != nil {
		t.Fatal(err)
	}
	old := []filesystem.MetadataOmission{
		{Field: "acl", SourceFormat: "windows-security-descriptor", Status: filesystem.MetadataUnsupported, Reason: "prior DACL conversion unsupported"},
		{Field: "attributes", SourceFormat: "windows-named-streams", Status: filesystem.MetadataUnsupported, Reason: "prior named stream conversion unsupported"},
	}
	s, err := Capture(ctx, hostOmissionReader{source, id, old}, filepath.Join(t.TempDir(), "session"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	check := func(wantACL, wantAttrs bool) {
		t.Helper()
		id, err := s.LookupPath(ctx, "/destination", false)
		if err != nil {
			t.Fatal(err)
		}
		n, err := s.Stat(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		found := map[string]filesystem.MetadataOmission{}
		for _, v := range n.MetadataOmissions {
			found[v.Field] = v
		}
		if _, ok := found["acl"]; ok != wantACL {
			t.Fatal("copy changed untouched ACL provenance", n.MetadataOmissions)
		}
		if _, ok := found["attributes"]; ok != wantAttrs || n.AttributesUnavailable != wantAttrs {
			t.Fatal("attribute availability/provenance disagrees with actual replacement", n.MetadataOmissions, n.AttributesUnavailable)
		}
		if wantAttrs && found["attributes"] != old[1] {
			t.Fatal("retained attribute provenance changed", found["attributes"])
		}
	}
	if _, err := s.Copy(ctx, []string{"/source"}, "/destination", CopyOptions{NoAttributes: true}); err != nil {
		t.Fatal(err)
	}
	check(true, true)
	if _, err := s.Copy(ctx, []string{"/source"}, "/destination", CopyOptions{Preserve: true, NoAttributes: true}); err != nil {
		t.Fatal(err)
	}
	check(false, true)
	if _, err := s.Copy(ctx, []string{"/source"}, "/destination", CopyOptions{}); err != nil {
		t.Fatal(err)
	}
	check(false, false)
}

func TestHostAttributeUncertaintyTracksRetainedQuarantineOnly(t *testing.T) {
	ctx := context.Background()
	base, _ := newSession(t)
	host := filepath.Join(t.TempDir(), "source")
	if err := os.WriteFile(host, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/source", "/destination"} {
		if _, err := base.Copy(ctx, []string{host}, path, CopyOptions{FromHost: true, NoAttributes: true}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := base.SetAttribute(ctx, []string{"/destination"}, "com.apple.quarantine", bytes.NewReader([]byte("retained")), AttributeOptions{}); err != nil {
		t.Fatal(err)
	}
	id, err := base.LookupPath(ctx, "/destination", false)
	if err != nil {
		t.Fatal(err)
	}
	omission := filesystem.MetadataOmission{Field: "attributes", SourceFormat: "windows-named-streams", Status: filesystem.MetadataUnsupported, Reason: "prior named streams unsupported"}
	s, err := Capture(ctx, hostOmissionReader{base, id, []filesystem.MetadataOmission{omission}}, filepath.Join(t.TempDir(), "session"), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	check := func(unavailable bool, want string) {
		t.Helper()
		id, err := s.LookupPath(ctx, "/destination", false)
		if err != nil {
			t.Fatal(err)
		}
		n, err := s.Stat(ctx, id)
		if err != nil || n.AttributesUnavailable != unavailable {
			t.Fatal("retained quarantine availability changed", n, err)
		}
		found := false
		for _, v := range n.MetadataOmissions {
			found = found || v.Field == "attributes"
		}
		if found != unavailable {
			t.Fatal("retained quarantine provenance changed", n.MetadataOmissions)
		}
		v, err := s.OpenAttribute(ctx, id, "com.apple.quarantine")
		if err != nil {
			t.Fatal(err)
		}
		got := make([]byte, v.Size())
		_, err = v.ReadAt(got, 0)
		if err != nil {
			t.Fatal(err)
		}
		if err := v.Close(); err != nil {
			t.Fatal(err)
		}
		if string(got) != want {
			t.Fatal("quarantine copy policy changed", string(got), want)
		}
	}
	if _, err := s.Copy(ctx, []string{"/source"}, "/destination", CopyOptions{}); err != nil {
		t.Fatal(err)
	}
	check(true, "retained")
	if _, err := s.SetAttribute(ctx, []string{"/source"}, "com.apple.quarantine", bytes.NewReader([]byte("supplied")), AttributeOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Copy(ctx, []string{"/source"}, "/destination", CopyOptions{}); err != nil {
		t.Fatal(err)
	}
	check(false, "supplied")
}
