package workspace

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func replacementBaseline(t *testing.T) (*Workspace, uint64, string) {
	t.Helper()
	reader, root := sourceTree(t)
	directory := filepath.Join(t.TempDir(), "baseline")
	if _, err := Extract(context.Background(), reader, root, directory, Limits{}); err != nil {
		t.Fatal(err)
	}
	w, err := Open(context.Background(), directory)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := w.Close(); err != nil {
			t.Error(err)
		}
	})
	id, err := filesystem.Lookup(context.Background(), w, "alias")
	if err != nil {
		t.Fatal(err)
	}
	return w, id, directory
}

func TestReplaceDataPreservesInputAndAliases(t *testing.T) {
	w, id, baseline := replacementBaseline(t)
	ctx := context.Background()
	oldNode, err := w.Stat(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	originalValue, err := w.OpenData(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	defer originalValue.Close()
	original, err := io.ReadAll(io.NewSectionReader(originalValue, 0, originalValue.Size()))
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("complete new contents\x00\xff")
	destination := filepath.Join(t.TempDir(), "replacement")
	if _, err = w.ReplaceData(ctx, []DataReplacement{{id, bytes.NewReader(data)}}, destination, Limits{}); err != nil {
		t.Fatal(err)
	}
	changed, err := Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer changed.Close()
	if changed.Report().ModifiedFiles != 1 || changed.ParentManifestSHA256() != w.ManifestSHA256() {
		t.Fatal("replacement provenance lost")
	}
	aliases := 0
	for _, e := range changed.document.Entries {
		if e.Object != id {
			continue
		}
		aliases++
		contents, err := os.ReadFile(filepath.Join(destination, filepath.FromSlash(e.HostPath)))
		if err != nil || !bytes.Equal(contents, data) {
			t.Fatal("hard-link alias has stale contents", e, err)
		}
	}
	if aliases < 2 {
		t.Fatal("fixture did not exercise aliases")
	}
	newNode, err := changed.Stat(ctx, id)
	if err != nil || !reflect.DeepEqual(newNode.Metadata, oldNode.Metadata) || newNode.Identity != oldNode.Identity || newNode.Links != oldNode.Links || newNode.Size != uint64(len(data)) || !newNode.DataModified {
		t.Fatal("replacement changed unrelated fields", oldNode, newNode, err)
	}
	retained, err := io.ReadAll(io.NewSectionReader(originalValue, 0, originalValue.Size()))
	if err != nil || !bytes.Equal(retained, original) {
		t.Fatal("open baseline value changed", err)
	}
	reopened, err := Open(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.ManifestSHA256() != w.ManifestSHA256() {
		t.Fatal("baseline changed")
	}
	// Chained replacement and ordinary re-extraction keep the edited marker.
	second := filepath.Join(t.TempDir(), "second")
	if _, err = changed.ReplaceData(ctx, []DataReplacement{{id, bytes.NewReader(nil)}}, second, Limits{}); err != nil {
		t.Fatal(err)
	}
	empty, err := Open(ctx, second)
	if err != nil {
		t.Fatal(err)
	}
	defer empty.Close()
	if empty.Report().ModifiedFiles != 1 || empty.ParentManifestSHA256() != changed.ManifestSHA256() {
		t.Fatal("chained replacement lost provenance")
	}
	copied := filepath.Join(t.TempDir(), "copied")
	if _, err = Extract(ctx, empty, empty.Root(), copied, Limits{}); err != nil {
		t.Fatal(err)
	}
	copy, err := Open(ctx, copied)
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	if copy.Report().ModifiedFiles != 1 || copy.ParentManifestSHA256() != empty.ManifestSHA256() {
		t.Fatal("re-extraction erased modified origin")
	}
}

type failedReplacement struct {
	size   int64
	read   func([]byte, int64) (int, error)
	closed bool
}

func (f *failedReplacement) Size() int64                             { return f.size }
func (f *failedReplacement) ReadAt(b []byte, off int64) (int, error) { return f.read(b, off) }
func (f *failedReplacement) Close() error                            { f.closed = true; return nil }

func TestReplacementFailuresNeverPublish(t *testing.T) {
	w, id, baseline := replacementBaseline(t)
	good := bytes.NewReader([]byte("new contents"))
	short := &failedReplacement{size: 100, read: func([]byte, int64) (int, error) { return 0, io.EOF }}
	failure := errors.New("source I/O failure")
	bad := &failedReplacement{size: 100, read: func([]byte, int64) (int, error) { return 0, failure }}
	ctx, cancel := context.WithCancel(context.Background())
	cancelling := &failedReplacement{size: 1, read: func(b []byte, _ int64) (int, error) { b[0] = 1; cancel(); return 1, nil }}
	for _, tc := range []struct {
		name    string
		ctx     context.Context
		changes []DataReplacement
		limits  Limits
		want    error
	}{
		{"empty operation", context.Background(), nil, Limits{}, fs.ErrInvalid},
		{"duplicate identity", context.Background(), []DataReplacement{{id, good}, {id, good}}, Limits{}, filesystem.ErrConflict},
		{"directory", context.Background(), []DataReplacement{{w.Root(), good}}, Limits{}, fs.ErrInvalid},
		{"missing identity", context.Background(), []DataReplacement{{^uint64(0), good}}, Limits{}, fs.ErrNotExist},
		{"nil source", context.Background(), []DataReplacement{{id, nil}}, Limits{}, fs.ErrInvalid},
		{"value limit", context.Background(), []DataReplacement{{id, good}}, Limits{ValueBytes: 1}, filesystem.ErrLimit},
		{"short source", context.Background(), []DataReplacement{{id, short}}, Limits{}, io.ErrUnexpectedEOF},
		{"source failure", context.Background(), []DataReplacement{{id, bad}}, Limits{}, failure},
		{"cancel during copy", ctx, []DataReplacement{{id, cancelling}}, Limits{}, context.Canceled},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "output")
			if _, err := w.ReplaceData(tc.ctx, tc.changes, dest, tc.limits); !errors.Is(err, tc.want) {
				t.Fatalf("got %v want %v", err, tc.want)
			}
			if _, err := os.Stat(filepath.Join(dest, "metadata/manifest.json")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("failure published completion", err)
			}
		})
	}
	if short.closed || bad.closed || cancelling.closed {
		t.Fatal("borrowed replacement source closed")
	}
	baselineCopy, err := Open(context.Background(), baseline)
	if err != nil {
		t.Fatal(err)
	}
	defer baselineCopy.Close()
	if baselineCopy.ManifestSHA256() != w.ManifestSHA256() {
		t.Fatal("failed replacement mutated baseline")
	}
}

func TestReplacementRejectsOutputInsideBaseline(t *testing.T) {
	w, id, baseline := replacementBaseline(t)
	link := filepath.Join(t.TempDir(), "linked-baseline")
	if err := os.Symlink(baseline, link); err != nil {
		t.Fatal(err)
	}
	for _, parent := range []string{baseline, filepath.Join(baseline, "files"), link} {
		dest := filepath.Join(parent, "replacement")
		if _, err := w.ReplaceData(context.Background(), []DataReplacement{{id, bytes.NewReader(nil)}}, dest, Limits{}); !errors.Is(err, fs.ErrInvalid) {
			t.Fatal("baseline containment", err)
		}
		if _, err := os.Stat(dest); !errors.Is(err, fs.ErrNotExist) {
			t.Fatal("nested destination created", err)
		}
	}
	if _, err := w.ReplaceData(context.Background(), []DataReplacement{{id, bytes.NewReader(nil)}}, baseline, Limits{}); !errors.Is(err, fs.ErrExist) {
		t.Fatal("existing workspace replaced", err)
	}
}

func TestReplacementRejectsChangingInput(t *testing.T) {
	w, id, _ := replacementBaseline(t)
	calls := 0
	source := &failedReplacement{size: 1, read: func(b []byte, _ int64) (int, error) { calls++; b[0] = byte(calls); return 1, nil }}
	dest := filepath.Join(t.TempDir(), "output")
	if _, err := w.ReplaceData(context.Background(), []DataReplacement{{id, source}}, dest, Limits{}); !errors.Is(err, filesystem.ErrConflict) {
		t.Fatal("logical/raw mismatch admitted", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "metadata/manifest.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("changing source published")
	}
}

func TestReplacementRefusesUnknownCompressionOwnership(t *testing.T) {
	w, id, _ := replacementBaseline(t)
	n, err := w.Stat(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	n.Metadata.BSDFlags.Value |= 32
	n.Compression = filesystem.Observed(filesystem.Compression{Type: 99})
	data := make([]byte, 16)
	data[0] = 'f'
	data[1] = 'p'
	data[2] = 'm'
	data[3] = 'c'
	data[4] = 99
	// Header size must agree before classification; fake unknown native profile.
	binary.LittleEndian.PutUint64(data[8:], n.Size)
	reader := unknownCompression{Reader: w, data: bytes.NewReader(data)}
	if _, _, err := replacementNode(context.Background(), reader, n, 0); !errors.Is(err, filesystem.ErrUnsupported) {
		t.Fatal("guessed ownership of unknown compression storage", err)
	}
}

type unknownCompression struct {
	filesystem.Reader
	data block.Source
}

func (r unknownCompression) OpenAttribute(context.Context, uint64, string) (filesystem.Value, error) {
	return &replacementValue{r.data, context.Background()}, nil
}
