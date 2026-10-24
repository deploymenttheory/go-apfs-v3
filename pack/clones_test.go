package pack_test

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/diskimage"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/pack"
	"github.com/deploymenttheory/go-apfs-v3/session"
)

type cloneFormatReader struct {
	filesystem.Reader
	format  string
	partial bool
}

func (r cloneFormatReader) NameRules() filesystem.NameRules {
	rules := r.Reader.NameRules()
	if r.format != "" {
		rules.Format = r.format
	}
	return rules
}

func (r cloneFormatReader) Stat(ctx context.Context, id uint64) (filesystem.Node, error) {
	node, err := r.Reader.Stat(ctx, id)
	if err == nil && r.partial && node.Metadata.Mode.Value&0170000 == 0100000 {
		node.CloneStreams = &filesystem.CloneStreams{Partial: []string{""}}
	}
	return node, err
}

func TestPackExplicitClonesReportsActualSharedAndEmbeddedStorage(t *testing.T) {
	ctx := context.Background()
	s, options := inputFormat(t, "APFS")
	if _, err := s.ReplaceResourceFork(ctx, "/file", bytes.NewReader(bytes.Repeat([]byte("fork"), 2000))); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetAttribute(ctx, []string{"/file"}, "org.go-apfs.inline", bytes.NewReader([]byte("inline")), session.AttributeOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Copy(ctx, []string{"/file"}, "/clone", session.CopyOptions{Clone: true}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "clones.dmg")
	report, err := pack.Create(ctx, path, s, options)
	if err != nil {
		t.Fatal(err)
	}
	shared, embedded := 0, 0
	for _, result := range report.Clones {
		if result.Action == "shared" && (result.Stream == "" || result.Stream == filesystem.ResourceFork) {
			shared++
		} else if result.Action == "copied" && result.Reason == "embedded-attribute" && result.Stream != "" && result.Stream != filesystem.ResourceFork {
			if result.Stream == "org.go-apfs.inline" {
				embedded++
			}
		} else {
			t.Fatal("unexpected actual packing outcome", result)
		}
	}
	if shared != 4 || embedded != 2 {
		t.Fatal("missing explicit packing outcomes", report.Clones)
	}
	image, err := diskimage.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	raw, err := image.Partition(0)
	if err != nil {
		t.Fatal(err)
	}
	if err := apfs.ValidateMutation(ctx, raw); err != nil {
		t.Fatal(err)
	}
}

func TestPackNonCloningFilesystemReportsExplicitIndependentFallback(t *testing.T) {
	ctx := context.Background()
	s, options := inputFormat(t, "APFS")
	if _, err := s.Copy(ctx, []string{"/file"}, "/clone", session.CopyOptions{Clone: true}); err != nil {
		t.Fatal(err)
	}
	// The Reader explicitly supplies HFS logical names and clone intent; pack
	// does not reinterpret payload equality or silently convert a source format.
	reader := cloneFormatReader{Reader: s, format: "HFS+"}
	path := filepath.Join(t.TempDir(), "fallback.dmg")
	report, err := pack.Create(ctx, path, reader, options)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Clones) < 2 {
		t.Fatal("clone intent disappeared from fallback report", report.Clones)
	}
	dataOutcomes := 0
	for _, outcome := range report.Clones {
		if outcome.Action != "copied" || outcome.Reason != "filesystem-does-not-support-clones" {
			t.Fatal("fallback falsely advertised sharing", outcome)
		}
		if outcome.Stream == "" {
			dataOutcomes++
		}
	}
	if dataOutcomes != 2 {
		t.Fatal("fallback data stream outcomes missing", report.Clones)
	}
	result := openBuilt(t, path, "HFS+")
	left, err := filesystem.LookupExact(ctx, result, "/file")
	if err != nil {
		t.Fatal(err)
	}
	right, err := filesystem.LookupExact(ctx, result, "/clone")
	if err != nil || left == right {
		t.Fatal("fallback made a hard link", err)
	}
	for _, id := range []uint64{left, right} {
		value, err := result.OpenData(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
		if closeErr := value.Close(); err != nil || closeErr != nil || !bytes.Equal(data, bytes.Repeat([]byte("payload"), 2000)) {
			t.Fatal("fallback changed contents", err, closeErr)
		}
	}
	// Ordinary HFS session requests also report the actual copy fallback.
	hfs, _ := inputFormat(t, "HFS+")
	copyReport, err := hfs.Copy(ctx, []string{"/file"}, "/clone", session.CopyOptions{Clone: true})
	if err != nil || len(copyReport.Clones) != 1 || copyReport.Clones[0].Cloned || copyReport.Clones[0].Fallback == "" {
		t.Fatal("HFS session did not report ordinary-copy fallback", copyReport.Clones, err)
	}
}

func TestPackCompressionTransformsOnlyExplicitCloneRepresentation(t *testing.T) {
	ctx := context.Background()
	s, options := inputFormat(t, "APFS")
	payload := bytes.Repeat([]byte("compressible clone contents\n"), 40000)
	if _, err := s.ReplaceData(ctx, "/file", bytes.NewReader(payload)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Copy(ctx, []string{"/file"}, "/clone", session.CopyOptions{Clone: true}); err != nil {
		t.Fatal(err)
	}
	options.FileCompression = "zlib"
	compressed := filepath.Join(t.TempDir(), "compressed.dmg")
	report, err := pack.Create(ctx, compressed, s, options)
	if err != nil {
		t.Fatal(err)
	}
	shared := 0
	for _, result := range report.Clones {
		if result.Action == "shared" && result.Stream == filesystem.ResourceFork {
			shared++
		}
	}
	if shared != 2 {
		t.Fatal("encoding discarded explicit clone lineage", report.Clones)
	}
	reader := openBuilt(t, compressed, "APFS")
	options.FileCompression = "none"
	uncompressed := filepath.Join(t.TempDir(), "uncompressed.dmg")
	report, err = pack.Create(ctx, uncompressed, reader, options)
	if err != nil {
		t.Fatal(err)
	}
	shared = 0
	for _, result := range report.Clones {
		if result.Action == "shared" && result.Stream == "" {
			shared++
		}
	}
	if shared != 2 {
		t.Fatal("decoding discarded explicit native fork lineage", report.Clones)
	}
}

func TestPackPartiallySharedImportRefusesBeforeReadingOrPublishing(t *testing.T) {
	ctx := context.Background()
	s, options := inputFormat(t, "APFS")
	reader := cloneFormatReader{Reader: s, partial: true}
	dir := t.TempDir()
	for _, policy := range []string{"preserve", "zlib", "none"} {
		options.FileCompression = policy
		if _, err := pack.Create(ctx, filepath.Join(dir, "partial.dmg"), reader, options); !errors.Is(err, filesystem.ErrUnsupported) {
			t.Fatal("partial import was silently flattened", err)
		}
		if entries, _ := os.ReadDir(dir); len(entries) != 0 {
			t.Fatal("refused partial import published output")
		}
	}
}
