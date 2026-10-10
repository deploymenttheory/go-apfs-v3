package session

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

func newSession(t *testing.T) (*Session, string) {
	t.Helper()
	when := time.Date(2026, 10, 10, 1, 2, 3, 123456789, time.UTC)
	directory := filepath.Join(t.TempDir(), "session")
	s, err := Create(context.Background(), directory, Options{Names: filesystem.NameRules{Format: "APFS", NormalizationInsensitive: true}, Time: &when})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s, directory
}
func TestPersistentCommandsAndPublication(t *testing.T) {
	ctx := context.Background()
	s, dir := newSession(t)
	if _, err := s.Mkdir(ctx, []string{"/App/Contents/MacOS"}, MkdirOptions{Parents: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Touch(ctx, []string{"/App/Contents/MacOS/Example"}, TouchOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Chmod(ctx, []string{"/App/Contents/MacOS/Example"}, "u+x", WalkOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Link(ctx, "/App/Contents/MacOS/Example", "/alias", LinkOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetAttribute(ctx, []string{"/alias"}, "org.example", bytes.NewReader([]byte("value")), AttributeOptions{}); err != nil {
		t.Fatal(err)
	}
	old := s.Report().Revision
	if _, err := s.Chmod(ctx, []string{"/alias", "/missing"}, "0000", WalkOptions{}); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if s.Report().Revision != old {
		t.Fatal("failed command published")
	}
	if _, err := Open(ctx, dir); !errors.Is(err, filesystem.ErrConflict) {
		t.Fatal("concurrent open", err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	id, err := s.LookupPath(ctx, "/alias", true)
	if err != nil {
		t.Fatal(err)
	}
	n, err := s.Stat(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if n.Metadata.Mode.Value != 0100744 || n.Links.Value != 2 {
		t.Fatalf("%+v", n)
	}
	v, err := s.OpenAttribute(ctx, id, "org.example")
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(io.NewSectionReader(v, 0, v.Size()))
	if err != nil {
		t.Fatal(err)
	}
	v.Close()
	if string(b) != "value" {
		t.Fatal(string(b))
	}
	destination := filepath.Join(t.TempDir(), "export")
	if _, err = s.Export(ctx, destination); err != nil {
		t.Fatal(err)
	}
	w, err := workspace.Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if _, err = w.Stat(ctx, id); err != nil {
		t.Fatal(err)
	}
}
func TestMetadataCommandsReusePayloadAndRollback(t *testing.T) {
	ctx := context.Background()
	s, _ := newSession(t)
	if _, err := s.Touch(ctx, []string{"/data"}, TouchOptions{}); err != nil {
		t.Fatal(err)
	}
	id, err := s.LookupPath(ctx, "/data", false)
	if err != nil {
		t.Fatal(err)
	}
	ref := s.objects[id].Data
	// An unavailable payload proves chmod neither reads nor copies its bytes.
	saved := filepath.Join(s.directory, "blobs", ref.SHA256)
	if err = os.Rename(saved, saved+".hidden"); err != nil {
		t.Fatal(err)
	}
	if _, err = s.Chmod(ctx, []string{"/data"}, "0755", WalkOptions{}); err != nil {
		t.Fatal(err)
	}
	if err = s.Verify(ctx); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("verify must detect missing payload", err)
	}
	if err = os.Rename(saved+".hidden", saved); err != nil {
		t.Fatal(err)
	}
	before := s.Report().Revision
	s.beforePublish = func() error { return io.ErrShortWrite }
	if _, err = s.Chmod(ctx, []string{"/data"}, "0600", WalkOptions{}); !errors.Is(err, io.ErrShortWrite) {
		t.Fatal(err)
	}
	s.beforePublish = nil
	if s.Report().Revision != before {
		t.Fatal("failed flush advanced session")
	}
	n, err := s.Stat(ctx, id)
	if err != nil || n.Metadata.Mode.Value != 0100755 {
		t.Fatal(n, err)
	}
	if err = s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
}
func TestLogicalSymlinkTraversal(t *testing.T) {
	ctx := context.Background()
	s, _ := newSession(t)
	if _, err := s.Mkdir(ctx, []string{"/dir"}, MkdirOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Touch(ctx, []string{"/dir/file"}, TouchOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Link(ctx, "/dir", "/link", LinkOptions{Symbolic: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Chmod(ctx, []string{"/link/file"}, "0700", WalkOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Link(ctx, "cycle", "/cycle", LinkOptions{Symbolic: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupPath(ctx, "/cycle", true); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal(err)
	}
	if _, err := s.Remove(ctx, []string{"/link"}, RemoveOptions{Recursive: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupPath(ctx, "/dir/file", true); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Remove(ctx, []string{"/"}, RemoveOptions{Recursive: true}); !errors.Is(err, fs.ErrInvalid) {
		t.Fatal(err)
	}
}
func TestFixedClockCanonicalState(t *testing.T) {
	ctx := context.Background()
	a, _ := newSession(t)
	b, _ := newSession(t)
	for _, s := range []*Session{a, b} {
		if _, err := s.Touch(ctx, []string{"/x"}, TouchOptions{}); err != nil {
			t.Fatal(err)
		}
		if _, err := s.Chmod(ctx, []string{"/x"}, "u+x,g=u,o=", WalkOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	if a.Report().Revision != b.Report().Revision {
		t.Fatal("host paths entered canonical state")
	}
	payload, err := os.ReadFile(filepath.Join(a.directory, "current"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(payload), a.directory) {
		t.Fatal("scratch path serialized")
	}
}

func TestCopyPoliciesAndHostDefaults(t *testing.T) {
	ctx := context.Background()
	s, _ := newSession(t)
	check := func(_ Report, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	source := filepath.Join(t.TempDir(), "bundle")
	if err := os.MkdirAll(filepath.Join(source, "nested"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "executable"), []byte("payload"), 0751); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(filepath.Join(source, "executable"), filepath.Join(source, "nested", "alias")); err != nil {
		t.Fatal(err)
	}
	check(s.Copy(ctx, []string{source}, "/ordinary", CopyOptions{FromHost: true, Archive: true}))
	a, _ := s.LookupPath(ctx, "/ordinary/executable", false)
	b, _ := s.LookupPath(ctx, "/ordinary/nested/alias", false)
	if a == b {
		t.Fatal("Apple archive copy must split hard links")
	}
	n, err := s.Stat(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS == "windows" {
		if n.Metadata.Mode.Value != 0100644 || n.Metadata.UID.Value != 0 || n.Metadata.GID.Value != 0 || !n.AttributesUnavailable {
			t.Fatal("missing Windows default observations", n)
		}
	} else if n.Metadata.Mode.Value != 0100751 {
		t.Fatalf("preserved mode: %#o", n.Metadata.Mode.Value)
	}
	if runtime.GOOS != "darwin" && !slices.Contains(n.MetadataDefaulted, "bsdFlags") {
		t.Fatal("missing BSD flag default")
	}
	check(s.Chmod(ctx, []string{"/ordinary/executable"}, "0700", WalkOptions{}))
	n, _ = s.Stat(ctx, a)
	if slices.Contains(n.MetadataDefaulted, "mode") {
		t.Fatal("explicit mode still marked defaulted")
	}
	check(s.Copy(ctx, []string{source}, "/linked", CopyOptions{FromHost: true, Archive: true, PreserveLinks: true}))
	a, _ = s.LookupPath(ctx, "/linked/executable", false)
	b, _ = s.LookupPath(ctx, "/linked/nested/alias", false)
	if a != b {
		t.Fatal("--preserve-links split aliases")
	}
	// Later host changes cannot alter captured bytes.
	if err = os.WriteFile(filepath.Join(source, "executable"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	v, err := s.OpenData(ctx, a)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(io.NewSectionReader(v, 0, v.Size()))
	v.Close()
	if err != nil || string(data) != "payload" {
		t.Fatal(string(data), err)
	}
	before := s.Report().Revision
	if _, err = s.Copy(ctx, []string{"/linked"}, "/linked/nested", CopyOptions{Archive: true}); !errors.Is(err, filesystem.ErrConflict) {
		t.Fatal(err)
	}
	if s.Report().Revision != before {
		t.Fatal("rejected copy published")
	}
	check(s.Mkdir(ctx, []string{"/destination"}, MkdirOptions{}))
	check(s.Copy(ctx, []string{"/linked/"}, "/destination", CopyOptions{Archive: true, NoAttributes: true}))
	if _, err = s.LookupPath(ctx, "/destination/nested/alias", false); err != nil {
		t.Fatal(err)
	}
}

func TestSymlinkParentsAndSameInodeMove(t *testing.T) {
	ctx := context.Background()
	s, _ := newSession(t)
	check := func(_ Report, err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	check(s.Mkdir(ctx, []string{"/a", "/b/deep"}, MkdirOptions{Parents: true}))
	check(s.Link(ctx, "/b/deep", "/a/link", LinkOptions{Symbolic: true}))
	check(s.Touch(ctx, []string{"/a/link/../file"}, TouchOptions{}))
	if _, err := s.LookupPath(ctx, "/b/file", false); err != nil {
		t.Fatal("lexical cleaning lost symlink parent", err)
	}
	check(s.Link(ctx, "/b/missing", "/dangling", LinkOptions{Symbolic: true}))
	check(s.Touch(ctx, []string{"/dangling"}, TouchOptions{}))
	if _, err := s.LookupPath(ctx, "/b/missing", false); err != nil {
		t.Fatal(err)
	}
	check(s.Mkdir(ctx, []string{"/a/link/../created"}, MkdirOptions{Parents: true}))
	if _, err := s.LookupPath(ctx, "/b/created", false); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LookupPath(ctx, "/b/file/..", false); err == nil {
		t.Fatal("regular file accepted as parent")
	}
	check(s.Link(ctx, "/b/file", "/alias", LinkOptions{}))
	before := s.Report().Revision
	check(s.Move(ctx, "/b/file", "/alias", false))
	if s.Report().Revision != before {
		t.Fatal("same-inode rename changed timestamps")
	}
	check(s.Mkdir(ctx, []string{"/input/one", "/input/two", "/out"}, MkdirOptions{Parents: true}))
	check(s.Touch(ctx, []string{"/input/one/file", "/input/two/file"}, TouchOptions{}))
	// Both operands intentionally overwrite the same destination in one command.
	check(s.Copy(ctx, []string{"/input/one/file", "/input/two/file"}, "/out", CopyOptions{}))
}

func TestInterruptedCommandRecovery(t *testing.T) {
	if directory := os.Getenv("APFS_SESSION_TEST_CRASH"); directory != "" {
		s, err := Open(context.Background(), directory)
		if err != nil {
			t.Fatal(err)
		}
		s.beforePublish = func() error { os.Exit(47); return nil }
		_, err = s.SetAttribute(context.Background(), []string{"/"}, "org.interrupted", bytes.NewReader([]byte("uncommitted payload")), AttributeOptions{})
		t.Fatalf("did not interrupt: %v", err)
	}
	ctx := context.Background()
	s, dir := newSession(t)
	before := s.Report().Revision
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	child := exec.Command(os.Args[0], "-test.run=^TestInterruptedCommandRecovery$")
	child.Env = append(os.Environ(), "APFS_SESSION_TEST_CRASH="+dir)
	output, err := child.CombinedOutput()
	var failure *exec.ExitError
	if !errors.As(err, &failure) || failure.ExitCode() != 47 {
		t.Fatalf("%v: %s", err, output)
	}
	s, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.Report().Revision != before {
		t.Fatal("interrupted command published")
	}
	if err = s.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"pending", "blobs"} {
		entries, err := os.ReadDir(filepath.Join(dir, name))
		if err != nil || len(entries) != 0 {
			t.Fatal("abandoned command not reclaimed", name, len(entries), err)
		}
	}
	if _, err = s.Touch(ctx, []string{"/after-recovery"}, TouchOptions{}); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptionLimitsAndValueLifetime(t *testing.T) {
	ctx := context.Background()
	s, dir := newSession(t)
	if _, err := s.Touch(ctx, []string{"/x"}, TouchOptions{}); err != nil {
		t.Fatal(err)
	}
	id, _ := s.LookupPath(ctx, "/x", false)
	v, err := s.OpenData(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = v.ReadAt(nil, 0); !errors.Is(err, fs.ErrClosed) {
		t.Fatal(err)
	}
	v.Close()
	s, err = Open(ctx, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	ref := s.objects[id].Data
	if err = os.WriteFile(filepath.Join(dir, "blobs", ref.SHA256), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.Verify(ctx); !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatal(err)
	}
	before := s.Report().Revision
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err = s.Touch(cancelled, []string{"/cancelled"}, TouchOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if s.Report().Revision != before {
		t.Fatal("cancelled command published")
	}
	limited, err := Create(ctx, filepath.Join(t.TempDir(), "small"), Options{Names: s.NameRules(), Limits: workspace.Limits{ValueBytes: 4, TotalBytes: 8}})
	if err != nil {
		t.Fatal(err)
	}
	defer limited.Close()
	if _, err = limited.SetAttribute(ctx, []string{"/"}, "org.large", bytes.NewReader([]byte("too large")), AttributeOptions{}); !errors.Is(err, filesystem.ErrLimit) {
		t.Fatal(err)
	}
}
