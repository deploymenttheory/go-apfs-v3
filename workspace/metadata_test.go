package workspace

import (
	"bytes"
	"context"
	"errors"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/block"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

func TestMetadataBatchRetainsAliasesProvenanceAndUntouchedValues(t *testing.T) {
	w, id, baseline := replacementBaseline(t)
	ctx := context.Background()
	original, err := w.Stat(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	instant := time.Date(2023, 11, 14, 22, 13, 20, 123456789, time.UTC)
	patch := filesystem.Metadata{Mode: filesystem.Observed(uint32(0100700)), UID: filesystem.Observed(uint32(0)), ModifyTime: filesystem.Observed(instant)}
	changes := []Change{
		{Op: RemoveAttribute, Path: "alias", Attribute: "org.go-apfs.link"},
		{Op: SetAttribute, Path: "alias", Attribute: "org.supplied", AttributeMode: AttributeCreate, Data: bytes.NewReader([]byte("first"))},
		{Op: ReplaceFileData, Path: "alias", Data: bytes.NewReader([]byte("replacement"))},
		{Op: RenameEntry, Path: "alias", To: "renamed"},
		{Op: SetAttribute, Path: "renamed", Attribute: "org.supplied", AttributeMode: AttributeReplace, Data: bytes.NewReader(nil)},
		{Op: ReplaceResourceFork, Path: "renamed", Data: bytes.NewReader([]byte("short fork"))},
		{Op: SetMetadata, Path: "renamed", Metadata: &patch},
	}
	destination := filepath.Join(t.TempDir(), "edited")
	report, err := w.Edit(ctx, changes, destination, Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if report.MetadataObjects != 1 || report.AttributeObjects != 1 || report.ModifiedFiles != 1 {
		t.Fatal(report)
	}
	result, err := Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	n, err := result.Stat(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	want := original.Metadata
	want.Mode, want.UID, want.ModifyTime = patch.Mode, patch.UID, patch.ModifyTime
	if !reflect.DeepEqual(n.Metadata, want) || n.Identity != original.Identity || n.Links != original.Links ||
		!slices.Equal(n.MetadataModified, []string{"mode", "modifyTime", "uid"}) ||
		!slices.Equal(n.AttributesModified, []string{filesystem.ResourceFork, "org.go-apfs.link", "org.supplied"}) {
		t.Fatal("metadata or provenance", n)
	}
	if _, err := result.OpenAttribute(ctx, id, "org.go-apfs.link"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("replacement resurrected removed attribute", err)
	}
	for name, want := range map[string]string{filesystem.ResourceFork: "short fork", "org.supplied": ""} {
		value, err := result.OpenAttribute(ctx, id, name)
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(io.NewSectionReader(value, 0, value.Size()))
		value.Close()
		if err != nil || string(data) != want {
			t.Fatal(name, string(data), err)
		}
	}
	// Callers own Stat's slices; changing one cannot corrupt the verified workspace.
	n.MetadataModified[0] = "invalid"
	n.AttributesModified[0] = "invalid"
	n, err = result.Stat(ctx, id)
	if err != nil || n.MetadataModified[0] == "invalid" || n.AttributesModified[0] == "invalid" {
		t.Fatal("shared Stat result")
	}
	copied := filepath.Join(t.TempDir(), "copied")
	if _, err := Extract(ctx, result, result.Root(), copied, Limits{}); err != nil {
		t.Fatal(err)
	}
	copy, err := Open(ctx, copied)
	if err != nil {
		t.Fatal(err)
	}
	defer copy.Close()
	saved, err := copy.Stat(ctx, id)
	if err != nil || !reflect.DeepEqual(saved, n) {
		t.Fatal("recapture lost edits", err)
	}
	next := filepath.Join(t.TempDir(), "next")
	newMode := filesystem.Metadata{Mode: filesystem.Observed(uint32(0100755))}
	if _, err := copy.Edit(ctx, []Change{{Op: RemoveAttribute, Path: "renamed", Attribute: "org.supplied"}, {Op: SetMetadata, Path: "renamed", Metadata: &newMode}}, next, Limits{}); err != nil {
		t.Fatal(err)
	}
	second, err := Open(ctx, next)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	changed, err := second.Stat(ctx, id)
	if err != nil || !slices.Equal(changed.AttributesModified, n.AttributesModified) || !slices.Equal(changed.MetadataModified, n.MetadataModified) {
		t.Fatal("cumulative edits lost", err)
	}
	// All original alias projections retain the immutable old contents/metadata.
	unchanged, err := Open(ctx, baseline)
	if err != nil {
		t.Fatal(err)
	}
	defer unchanged.Close()
	if unchanged.ManifestSHA256() != w.ManifestSHA256() {
		t.Fatal("baseline changed")
	}
	again := filepath.Join(t.TempDir(), "again")
	if _, err := w.Edit(ctx, changes, again, Limits{}); err != nil {
		t.Fatal(err)
	}
	same, err := Open(ctx, again)
	if err != nil {
		t.Fatal(err)
	}
	defer same.Close()
	if same.ManifestSHA256() != result.ManifestSHA256() {
		t.Fatal("identical edits produced different manifests")
	}
}

func TestMetadataFailuresNeverPublishOrCloseBorrowedInputs(t *testing.T) {
	w, _, _ := replacementBaseline(t)
	ctx := context.Background()
	failure := errors.New("attribute input failure")
	broken := &failedReplacement{size: 2, read: func([]byte, int64) (int, error) { return 0, failure }}
	short := &failedReplacement{size: 32, read: func([]byte, int64) (int, error) { return 0, io.EOF }}
	oversized := &failedReplacement{size: math.MaxInt32 + 1, read: func([]byte, int64) (int, error) { t.Fatal("read oversized attribute input"); return 0, failure }}
	cases := []struct {
		name    string
		changes []Change
		want    error
	}{
		{"empty patch", []Change{{Op: SetMetadata, Path: "alias", Metadata: &filesystem.Metadata{}}}, fs.ErrInvalid},
		{"absent mode", []Change{{Op: SetMetadata, Path: "alias", Metadata: &filesystem.Metadata{Mode: filesystem.Observation[uint32]{State: filesystem.Absent}}}}, fs.ErrInvalid},
		{"hidden patch value", []Change{{Op: SetMetadata, Path: "alias", Metadata: &filesystem.Metadata{UID: filesystem.Observation[uint32]{Value: 12}}}}, fs.ErrInvalid},
		{"object type", []Change{{Op: SetMetadata, Path: "alias", Metadata: &filesystem.Metadata{Mode: filesystem.Observed(uint32(0040755))}}}, fs.ErrInvalid},
		{"uid sentinel", []Change{{Op: SetMetadata, Path: "alias", Metadata: &filesystem.Metadata{UID: filesystem.Observed(uint32(math.MaxUint32))}}}, fs.ErrInvalid},
		{"ctime", []Change{{Op: SetMetadata, Path: "alias", Metadata: &filesystem.Metadata{ChangeTime: filesystem.Observed(time.Now())}}}, filesystem.ErrUnsupported},
		{"compression flag", []Change{{Op: SetMetadata, Path: "alias", Metadata: &filesystem.Metadata{BSDFlags: filesystem.Observed(uint32(32))}}}, filesystem.ErrUnsupported},
		{"system flag", []Change{{Op: SetMetadata, Path: "alias", Metadata: &filesystem.Metadata{BSDFlags: filesystem.Observed(uint32(0x80000))}}}, filesystem.ErrUnsupported},
		{"compression attribute", []Change{{Op: SetAttribute, Path: "alias", Attribute: filesystem.Decmpfs, Data: bytes.NewReader(nil)}}, filesystem.ErrUnsupported},
		{"security attribute", []Change{{Op: SetAttribute, Path: "alias", Attribute: "com.apple.system.Security", Data: bytes.NewReader(nil)}}, filesystem.ErrUnsupported},
		{"resource xattr", []Change{{Op: SetAttribute, Path: "alias", Attribute: filesystem.ResourceFork, Data: bytes.NewReader(nil)}}, fs.ErrInvalid},
		{"invalid name", []Change{{Op: SetAttribute, Path: "alias", Attribute: strings.Repeat("é", 64), Data: bytes.NewReader(nil)}}, fs.ErrInvalid},
		{"invalid UTF8", []Change{{Op: SetAttribute, Path: "alias", Attribute: "\xff", Data: bytes.NewReader(nil)}}, fs.ErrInvalid},
		{"replace missing", []Change{{Op: SetAttribute, Path: "alias", Attribute: "org.absent", AttributeMode: AttributeReplace, Data: bytes.NewReader(nil)}}, fs.ErrNotExist},
		{"irrelevant field", []Change{{Op: SetMetadata, Path: "alias", Attribute: "ignored", Metadata: &filesystem.Metadata{UID: filesystem.Observed(uint32(0))}}}, fs.ErrInvalid},
		{"late batch", []Change{{Op: SetAttribute, Path: "alias", Attribute: "org.first", Data: bytes.NewReader(nil)}, {Op: RemoveAttribute, Path: "alias", Attribute: "org.absent"}}, fs.ErrNotExist},
		{"short FinderInfo", []Change{{Op: SetAttribute, Path: "alias", Attribute: filesystem.FinderInfo, Data: short}}, io.ErrUnexpectedEOF},
		{"failed streaming", []Change{{Op: SetAttribute, Path: "alias", Attribute: "org.failed", Data: broken}}, failure},
		{"native attribute size", []Change{{Op: SetAttribute, Path: "alias", Attribute: "org.large", Data: oversized}}, filesystem.ErrLimit},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			destination := filepath.Join(t.TempDir(), "output")
			_, err := w.Edit(ctx, test.changes, destination, Limits{})
			if !errors.Is(err, test.want) {
				t.Fatalf("got %v want %v", err, test.want)
			}
			if _, err := os.Stat(filepath.Join(destination, "metadata/manifest.json")); !errors.Is(err, fs.ErrNotExist) {
				t.Fatal("failed operation published", err)
			}
		})
	}
	if broken.closed || short.closed {
		t.Fatal("closed borrowed input")
	}
	data := &failedReplacement{size: 1, read: func(b []byte, _ int64) (int, error) { b[0] = 7; return 1, nil }}
	cancelled, cancel := context.WithCancel(ctx)
	data.read = func(b []byte, _ int64) (int, error) { b[0] = 7; cancel(); return 1, nil }
	destination := filepath.Join(t.TempDir(), "cancelled")
	if _, err := w.Edit(cancelled, []Change{{Op: SetAttribute, Path: "alias", Attribute: "org.cancelled", Data: data}}, destination, Limits{}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if data.closed {
		t.Fatal("closed cancelled source")
	}
	if _, err := os.Stat(filepath.Join(destination, "metadata/manifest.json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("cancelled publication")
	}
}

func TestMetadataRefusesActiveOrUnknownForkOwnership(t *testing.T) {
	w, id, _ := replacementBaseline(t)
	ctx := context.Background()
	for _, state := range []filesystem.State{filesystem.Uncaptured, filesystem.Present} {
		r, err := w.editReader(ctx, DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		r.nodes[id].node.Compression.State = state
		if state == filesystem.Present {
			r.nodes[id].node.Metadata.BSDFlags.Value |= 32
		}
		for _, change := range []Change{{Op: ReplaceResourceFork, Path: "alias", Data: bytes.NewReader(nil)}, {Op: RemoveAttribute, Path: "alias", Attribute: filesystem.ResourceFork}} {
			if err := r.apply(ctx, change); !errors.Is(err, filesystem.ErrUnsupported) {
				t.Fatal("guessed fork ownership", err)
			}
		}
	}
	// New objects use the same overlay path; removals must affect initial attrs.
	n, err := w.Stat(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "created")
	changes := []Change{{Op: CreateFile, Path: "new", Metadata: &n.Metadata, Data: bytes.NewReader(nil), Attributes: map[string]block.Source{"org.initial": bytes.NewReader([]byte("old"))}},
		{Op: RemoveAttribute, Path: "new", Attribute: "org.initial"},
		{Op: SetAttribute, Path: "new", Attribute: "org.initial", AttributeMode: AttributeCreate, Data: bytes.NewReader([]byte("new"))}}
	if _, err := w.Edit(ctx, changes, dest, Limits{}); err != nil {
		t.Fatal(err)
	}
	created, err := Open(ctx, dest)
	if err != nil {
		t.Fatal(err)
	}
	defer created.Close()
	newID, err := filesystem.Lookup(ctx, created, "new")
	if err != nil {
		t.Fatal(err)
	}
	value, err := created.OpenAttribute(ctx, newID, "org.initial")
	if err != nil {
		t.Fatal(err)
	}
	defer value.Close()
	b := make([]byte, 3)
	if _, err := value.ReadAt(b, 0); err != nil || string(b) != "new" {
		t.Fatal("initial attribute resurrected", err)
	}
}
