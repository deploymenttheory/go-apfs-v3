package replay

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCorpusIdentitySeparatesSharedOverrides(t *testing.T) {
	root := t.TempDir()
	name := filepath.Join(root, "inputs.json")
	inputs := Inputs{Schema: 1, Bindings: []Binding{
		{ID: "hfs-editing", Environment: "APFS_NATIVE_HFS_EDITS", Path: filepath.Join(root, "files"), TreeSHA256: strings.Repeat("a", 64)},
		{ID: "hfs-catalog-editing", Environment: "APFS_NATIVE_HFS_EDITS", Path: filepath.Join(root, "catalog"), TreeSHA256: strings.Repeat("b", 64)},
	}}
	data, err := json.Marshal(inputs)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(name, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("APFS_REPLAY_INPUTS", name)
	t.Setenv("APFS_NATIVE_HFS_EDITS", "unverified-path")
	for _, binding := range inputs.Bindings {
		got, err := InputPath(binding.Environment, "testdata/"+binding.ID)
		if err != nil || got != binding.Path {
			t.Fatal("shared override conflated original corpora", got, err)
		}
	}
	if _, err = InputPath("APFS_NATIVE_HFS_EDITS", "testdata/missing"); err == nil {
		t.Fatal("missing admitted corpus fell back")
	}
	if _, err = InputPath("OTHER_OVERRIDE", "testdata/hfs-editing"); err == nil {
		t.Fatal("override contract changed silently")
	}
}

func TestReplayBindingsRefuseInvalidDocuments(t *testing.T) {
	for _, document := range []string{`{}`, `{"schema":1,"bindings":[]}`, `{"schema":1,"schema":2,"bindings":[]}`, `{"schema":1,"bindings":[{"id":"files","environment":"APFS_NATIVE_FILES","path":"/tmp/input","tree_sha256":"wrong"}]}`, `{"schema":1,"bindings":[],"unknown":true}`} {
		name := filepath.Join(t.TempDir(), "inputs.json")
		if err := os.WriteFile(name, []byte(document), 0600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("APFS_REPLAY_INPUTS", name)
		if _, err := InputPath("APFS_NATIVE_FILES", "testdata/files"); err == nil {
			t.Fatal("invalid document admitted", document)
		}
	}
}

func TestDirectAcceptanceKeepsOrdinaryInputSelection(t *testing.T) {
	t.Setenv("APFS_REPLAY_INPUTS", "")
	t.Setenv("APFS_NATIVE_FILES", "")
	if got, err := InputPath("APFS_NATIVE_FILES", "testdata/files"); err != nil || got != "testdata/files" {
		t.Fatal(got, err)
	}
	t.Setenv("APFS_NATIVE_FILES", "custom-reference")
	if got, err := InputPath("APFS_NATIVE_FILES", "testdata/files"); err != nil || got != "custom-reference" {
		t.Fatal(got, err)
	}
}
