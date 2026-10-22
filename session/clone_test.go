package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type partialCloneReader struct {
	filesystem.Reader
	object uint64
}

func (r partialCloneReader) CloneStreams(context.Context, uint64) (map[uint64]filesystem.CloneStreams, error) {
	return map[uint64]filesystem.CloneStreams{r.object: {Partial: []string{"", filesystem.ResourceFork, "org.go-apfs.large"}}}, nil
}

func cloneSessionNode(t *testing.T, s *Session, name string) filesystem.Node {
	t.Helper()
	id, err := s.LookupPath(context.Background(), name, true)
	if err != nil {
		t.Fatal(err)
	}
	node, err := s.Stat(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return node
}

func cloneSessionBytes(t *testing.T, s *Session, name, attribute string) []byte {
	t.Helper()
	node := cloneSessionNode(t, s, name)
	var value filesystem.Value
	var err error
	if attribute == "" {
		value, err = s.OpenData(context.Background(), node.Identity.Object)
	} else {
		value, err = s.OpenAttribute(context.Background(), node.Identity.Object, attribute)
	}
	if err != nil {
		t.Fatal(err)
	}
	data, readErr := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
	if err := errors.Join(readErr, value.Close()); err != nil {
		t.Fatal(err)
	}
	return data
}

func TestSessionExplicitCloneLineageSurvivesReopenAndOnlyChangedStreamsDetach(t *testing.T) {
	ctx := context.Background()
	s, directory := newSession(t)
	defer func() { _ = s.Close() }()
	reopen := func() {
		t.Helper()
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		var err error
		s, err = Open(ctx, directory)
		if err != nil {
			t.Fatal(err)
		}
	}
	data := bytes.Repeat([]byte("session clone data\n"), 1301)
	fork := bytes.Repeat([]byte("session clone fork\n"), 733)
	attribute := bytes.Repeat([]byte("session attribute\n"), 251)
	host := filepath.Join(t.TempDir(), "data")
	if err := os.WriteFile(host, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/source", "/independent"} {
		if _, err := s.Copy(ctx, []string{host}, path, CopyOptions{FromHost: true}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ReplaceResourceFork(ctx, "/source", bytes.NewReader(fork)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetAttribute(ctx, []string{"/source"}, "org.go-apfs.large", bytes.NewReader(attribute), AttributeOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/clone", "/untouched"} {
		report, err := s.Copy(ctx, []string{"/source"}, path, CopyOptions{Clone: true, Preserve: true})
		if err != nil || len(report.Clones) != 1 || !report.Clones[0].Cloned || report.Clones[0].Fallback != "" {
			t.Fatal("explicit clone outcome", report.Clones, err)
		}
		reopen()
	}
	if _, err := s.Link(ctx, "/clone", "/alias", LinkOptions{}); err != nil {
		t.Fatal(err)
	}
	reopen()
	source, clone := cloneSessionNode(t, s, "/source"), cloneSessionNode(t, s, "/clone")
	independent, alias := cloneSessionNode(t, s, "/independent"), cloneSessionNode(t, s, "/alias")
	if source.Identity == clone.Identity || clone.Identity != alias.Identity || independent.CloneStreams != nil || s.objects[source.Identity.Object].Data.SHA256 != s.objects[independent.Identity.Object].Data.SHA256 {
		t.Fatal("blob equality, hard links and clone identity were conflated")
	}
	if source.CloneStreams == nil || clone.CloneStreams == nil || source.CloneStreams.Data == "" || source.CloneStreams.Data != clone.CloneStreams.Data || source.CloneStreams.Attributes[filesystem.ResourceFork] != clone.CloneStreams.Attributes[filesystem.ResourceFork] || source.CloneStreams.Attributes["org.go-apfs.large"] != clone.CloneStreams.Attributes["org.go-apfs.large"] {
		t.Fatal("clone lineage was not persisted")
	}
	forkToken, attributeToken := clone.CloneStreams.Attributes[filesystem.ResourceFork], clone.CloneStreams.Attributes["org.go-apfs.large"]
	clone.CloneStreams.Attributes[filesystem.ResourceFork] = "caller-modified"
	if cloneSessionNode(t, s, "/clone").CloneStreams.Attributes[filesystem.ResourceFork] != forkToken {
		t.Fatal("Stat returned mutable session lineage")
	}
	if _, err := s.Chmod(ctx, []string{"/clone"}, "0700", WalkOptions{}); err != nil {
		t.Fatal(err)
	}
	reopen()
	if cloneSessionNode(t, s, "/source").Metadata.Mode.Value == cloneSessionNode(t, s, "/clone").Metadata.Mode.Value || cloneSessionNode(t, s, "/clone").CloneStreams.Data != source.CloneStreams.Data {
		t.Fatal("metadata changed a sibling or detached shared data")
	}
	if _, err := s.ReplaceData(ctx, "/alias", bytes.NewReader([]byte("private data"))); err != nil {
		t.Fatal(err)
	}
	reopen()
	clone = cloneSessionNode(t, s, "/clone")
	if clone.CloneStreams.Data != "" || clone.CloneStreams.Attributes[filesystem.ResourceFork] != forkToken || clone.CloneStreams.Attributes["org.go-apfs.large"] != attributeToken || string(cloneSessionBytes(t, s, "/clone", "")) != "private data" || !bytes.Equal(cloneSessionBytes(t, s, "/source", ""), data) {
		t.Fatal("data replacement did not detach only data")
	}
	if _, err := s.SetAttribute(ctx, []string{"/clone"}, "org.go-apfs.large", bytes.NewReader([]byte("private attribute")), AttributeOptions{}); err != nil {
		t.Fatal(err)
	}
	reopen()
	clone = cloneSessionNode(t, s, "/clone")
	if clone.CloneStreams.Attributes["org.go-apfs.large"] != "" || clone.CloneStreams.Attributes[filesystem.ResourceFork] != forkToken || !bytes.Equal(cloneSessionBytes(t, s, "/source", "org.go-apfs.large"), attribute) {
		t.Fatal("attribute replacement detached unrelated sharing")
	}
	if _, err := s.ReplaceResourceFork(ctx, "/clone", bytes.NewReader([]byte("private fork"))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Remove(ctx, []string{"/source"}, RemoveOptions{}); err != nil {
		t.Fatal(err)
	}
	reopen()
	if _, err := s.LookupPath(ctx, "/source", false); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("source removal", err)
	}
	if !bytes.Equal(cloneSessionBytes(t, s, "/untouched", ""), data) || !bytes.Equal(cloneSessionBytes(t, s, "/untouched", filesystem.ResourceFork), fork) || !bytes.Equal(cloneSessionBytes(t, s, "/untouched", "org.go-apfs.large"), attribute) || string(cloneSessionBytes(t, s, "/alias", filesystem.ResourceFork)) != "private fork" {
		t.Fatal("removing the original source broke surviving streams")
	}
	if err := s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSessionCloneFailureLeavesPublishedRevisionAndSourceUnchanged(t *testing.T) {
	ctx := context.Background()
	s, directory := newSession(t)
	if _, err := s.Touch(ctx, []string{"/source"}, TouchOptions{}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(directory, "current"))
	if err != nil {
		t.Fatal(err)
	}
	s.beforePublish = func() error { return io.ErrShortWrite }
	if report, err := s.Copy(ctx, []string{"/source"}, "/clone", CopyOptions{Clone: true}); !errors.Is(err, io.ErrShortWrite) || len(report.Clones) != 0 {
		t.Fatal("unpublished clone was reported as materialized", report.Clones, err)
	}
	s.beforePublish = nil
	after, err := os.ReadFile(filepath.Join(directory, "current"))
	if err != nil || !bytes.Equal(before, after) || cloneSessionNode(t, s, "/source").CloneStreams != nil {
		t.Fatal("failed clone changed source or publication", err)
	}
	if _, err := s.LookupPath(ctx, "/clone", false); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("failed clone became visible", err)
	}
}

func TestSessionOpenRejectsConflictingCloneGroupsWithoutChangingScratch(t *testing.T) {
	ctx := context.Background()
	s, directory := newSession(t)
	for _, name := range []string{"/first", "/second"} {
		if _, err := s.Touch(ctx, []string{name}, TouchOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.ReplaceData(ctx, "/second", bytes.NewReader([]byte("different"))); err != nil {
		t.Fatal(err)
	}
	document := s.document
	for i := range document.Objects {
		if document.Objects[i].Node.Metadata.Mode.Value&0170000 == 0100000 {
			document.Objects[i].Node.CloneStreams = &filesystem.CloneStreams{Data: "declared-same-lineage"}
		}
	}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	current := filepath.Join(directory, "current")
	if err := os.WriteFile(current, data, 0600); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(ctx, directory); !errors.Is(err, filesystem.ErrCorrupt) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatal("conflicting group was admitted", err)
	}
	after, err := os.ReadFile(current)
	if err != nil || !bytes.Equal(after, data) {
		t.Fatal("rejected metadata admission changed scratch", err)
	}
}

func TestSessionCapturedPartialMarkersPersistAndDetachOnlyWithReplacedStreams(t *testing.T) {
	ctx := context.Background()
	source, _ := newSession(t)
	if _, err := source.Touch(ctx, []string{"/partial"}, TouchOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := source.ReplaceData(ctx, "/partial", bytes.NewReader([]byte("data"))); err != nil {
		t.Fatal(err)
	}
	if _, err := source.ReplaceResourceFork(ctx, "/partial", bytes.NewReader([]byte("fork"))); err != nil {
		t.Fatal(err)
	}
	if _, err := source.SetAttribute(ctx, []string{"/partial"}, "org.go-apfs.large", bytes.NewReader([]byte("attribute")), AttributeOptions{}); err != nil {
		t.Fatal(err)
	}
	id := cloneSessionNode(t, source, "/partial").Identity.Object
	directory := filepath.Join(t.TempDir(), "captured")
	s, err := Capture(ctx, partialCloneReader{Reader: source, object: id}, directory, Options{Time: source.document.Config.Time})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Chmod(ctx, []string{"/partial"}, "0700", WalkOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := cloneSessionNode(t, s, "/partial").CloneStreams.Partial; !reflect.DeepEqual(got, []string{"", filesystem.ResourceFork, "org.go-apfs.large"}) {
		t.Fatal("metadata edit discarded partial ownership", got)
	}
	if _, err := s.ReplaceData(ctx, "/partial", bytes.NewReader([]byte("private data"))); err != nil {
		t.Fatal(err)
	}
	if got := cloneSessionNode(t, s, "/partial").CloneStreams.Partial; !reflect.DeepEqual(got, []string{filesystem.ResourceFork, "org.go-apfs.large"}) {
		t.Fatal("data replacement changed unrelated partial markers", got)
	}
	if _, err := s.ReplaceResourceFork(ctx, "/partial", bytes.NewReader([]byte("private fork"))); err != nil {
		t.Fatal(err)
	}
	if got := cloneSessionNode(t, s, "/partial").CloneStreams.Partial; !reflect.DeepEqual(got, []string{"org.go-apfs.large"}) {
		t.Fatal("fork replacement changed unrelated partial marker", got)
	}
	if _, err := s.SetAttribute(ctx, []string{"/partial"}, "org.go-apfs.large", bytes.NewReader([]byte("private attribute")), AttributeOptions{}); err != nil {
		t.Fatal(err)
	}
	if cloneSessionNode(t, s, "/partial").CloneStreams != nil {
		t.Fatal("complete replacement retained obsolete partial markers")
	}
}

func TestSessionCloneSchemaRetainsReadableLegacyRevisions(t *testing.T) {
	ctx := context.Background()
	s, directory := newSession(t)
	document := s.document
	document.Schema = 1
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "current"), data, 0600); err != nil {
		t.Fatal(err)
	}
	s, err = Open(ctx, directory)
	if err != nil {
		t.Fatal("legacy session was rejected", err)
	}
	defer s.Close()
	if _, err := s.Touch(ctx, []string{"/new"}, TouchOptions{}); err != nil || s.document.Schema != 2 {
		t.Fatal("legacy session did not advance to clone-capable schema", err)
	}
}
