package corpus

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentCaptureInspectionDoesNotApproveOrRewriteOriginals(t *testing.T) {
	root, retained, defs := fixture(t, false)
	definition := defs[0]
	definition.Manifests = nil
	got, err := InspectCapture(context.Background(), root, definition)
	if err != nil {
		t.Fatal(err)
	}
	if got.Entries[0].TreeSHA256 != retained.Entries[0].TreeSHA256 {
		t.Fatal("transport-independent identity changed")
	}
	original := filepath.Join(root, "fixtures/native/manifest.json")
	bytes, err := os.ReadFile(original)
	if err != nil {
		t.Fatal(err)
	}
	resolved := resolve(t, got, Options{Repository: root})
	manifest, err := resolved.Manifest("manifest.json")
	if err != nil || string(manifest) != string(bytes) {
		t.Fatal("original document differs", err)
	}
	if _, err = resolved.Manifest("images/source.dmg"); err == nil {
		t.Fatal("undeclared document admitted")
	}
	if err = os.WriteFile(original, append(bytes, ' '), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = resolved.Manifest("manifest.json"); err == nil {
		t.Fatal("changed manifest returned as verified")
	}
	if err = resolved.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = InspectCapture(context.Background(), root, defs[0]); err == nil {
		t.Fatal("retained pins silently replaced")
	}
}

func TestCaptureInspectionRequiresBoundedOrdinaryManifestFiles(t *testing.T) {
	root, _, defs := fixture(t, false)
	definition := defs[0]
	definition.Manifests = nil
	name := filepath.Join(root, "fixtures/native/manifest.json")
	if err := os.WriteFile(name, []byte(`{"schema":1,"schema":2}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCapture(context.Background(), root, definition); err == nil {
		t.Fatal("duplicate JSON fields admitted")
	}
	if err := os.Remove(name); err != nil {
		t.Fatal(err)
	}
	if _, err := InspectCapture(context.Background(), root, definition); err == nil {
		t.Fatal("capture without original manifests admitted")
	}
}
