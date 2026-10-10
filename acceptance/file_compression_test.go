package acceptance_test

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type nativeCompression struct {
	Path            string `json:"path"`
	Type            uint32 `json:"type"`
	Storage         string `json:"storage"`
	CodecSHA256     string `json:"codecSHA256"`
	NativeReadError int    `json:"nativeReadError"`
	Samples         []struct {
		Offset int64  `json:"offset"`
		Hex    string `json:"hex"`
	} `json:"samples"`
}

type nativeCompressionRejection struct {
	Path      string      `json:"path"`
	Size      int64       `json:"size"`
	Flags     uint32      `json:"flags"`
	ReadSize  int64       `json:"readSize"`
	ReadError int         `json:"readError"`
	Attribute nativeValue `json:"attribute"`
}

// TestNativeFileCompression compares logical data and raw stored evidence from
// both filesystems. The separate inventory prevents losing a codec silently.
func TestNativeFileCompression(t *testing.T) {
	t.Parallel()
	testFileCorpus(t, "file-compression", "APFS_NATIVE_COMPRESSION", "testdata/compression", 27, compareCompression)
}

func compareCompression(t *testing.T, r filesystem.Reader, want fileObservation, _ string) {
	t.Helper()
	ctx := context.Background()
	expected := map[string]uint32{
		"zlib-checksum": 3, "zlib-gaps": 4,
		"type-01": 1, "type-03": 3, "type-04": 4, "type-07": 7, "type-08": 8,
		"type-09": 9, "type-10": 10, "type-11": 11, "type-12": 12, "type-13": 13,
		"type-14": 14, "type-15": 15, "type-16": 16,
		"stored-03": 3, "stored-07": 7, "stored-09": 9, "stored-11": 11,
		"stored-13": 13, "stored-15": 15, "native-ditto": 8, "empty": 1, "hardlink": 4,
	}
	if len(want.Compression) != len(expected) {
		t.Fatal("incomplete compression inventory")
	}
	seen := map[string]bool{}
	for _, c := range want.Compression {
		name := strings.TrimPrefix(c.Path, "Fixture/")
		if expected[name] != c.Type || seen[name] {
			t.Fatal("unknown or duplicate compression case", c.Path)
		}
		seen[name] = true
		matched := false
		for _, entry := range want.Entries {
			if entry.Path == c.Path {
				matched = len(c.CodecSHA256) == 64 && c.CodecSHA256 == entry.SHA256
			}
		}
		if !matched {
			t.Fatal("native codec and filesystem observations disagree", c.Path)
		}
		storage := "attribute"
		if c.Type != 1 && c.Type&1 == 0 {
			storage = "resource-fork"
		}
		if c.Storage != storage || (c.NativeReadError != 0 && ((c.Type != 15 && c.Type != 16) || c.NativeReadError != 5)) {
			t.Fatal("invalid native compression outcome", c)
		}
		id, err := filesystem.LookupExact(ctx, r, c.Path)
		if err != nil {
			t.Fatal(err)
		}
		n, err := r.Stat(ctx, id)
		if err != nil || n.Compression.State != filesystem.Present || n.Compression.Value.Type != c.Type {
			t.Fatalf("%s compression metadata: %+v, %v", c.Path, n.Compression, err)
		}
		v, err := r.OpenData(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if len(c.Samples) == 0 {
			t.Fatal("missing native read samples")
		}
		// Reverse order crosses cache boundaries independently of the full hash.
		for i := len(c.Samples) - 1; i >= 0; i-- {
			sample := c.Samples[i]
			data, err := hex.DecodeString(sample.Hex)
			if err != nil || sample.Offset < 0 || sample.Offset > v.Size() {
				t.Fatal("invalid native sample")
			}
			got := make([]byte, len(data))
			count, err := v.ReadAt(got, sample.Offset)
			if err != nil || count != len(data) || !bytes.Equal(got, data) {
				t.Fatalf("%s sample at %d: %x, %v", c.Path, sample.Offset, got, err)
			}
		}
		if _, err := v.ReadAt(make([]byte, 1), v.Size()); err != io.EOF {
			t.Fatal("logical EOF", err)
		}
		_ = v.Close()
		raw, err := r.OpenRawData(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		if raw.Size() != 0 {
			t.Fatalf("%s stored data fork should be empty, got %d", c.Path, raw.Size())
		}
		_ = raw.Close()
	}
	for _, label := range []string{"valid", "malformed"} {
		id, err := filesystem.LookupExact(ctx, r, "Fixture/inactive-"+label)
		if err != nil {
			t.Fatal(err)
		}
		n, err := r.Stat(ctx, id)
		if err != nil || n.Compression.State != filesystem.Absent {
			t.Fatal("inactive attribute selected compression", err)
		}
	}
	if len(want.CompressionRejections) != 1 {
		t.Fatal("missing malformed native compression control")
	}
	control := want.CompressionRejections[0]
	if control.Path != "RejectedCompression/lzfse-marker-zero" || control.Size != 73 || control.Flags&0x20 == 0 || control.ReadSize != 0 || (control.ReadError != 0 && control.ReadError != 5 && control.ReadError != 22) {
		t.Fatal("malformed native control changed", control)
	}
	id, err := filesystem.LookupExact(ctx, r, control.Path)
	if err != nil {
		t.Fatal(err)
	}
	a, err := r.OpenAttribute(ctx, id, filesystem.Decmpfs)
	if err != nil {
		t.Fatal(err)
	}
	compareValue(t, control.Path+":raw", a, control.Attribute)
	v, err := r.OpenData(ctx, id)
	if err == nil {
		defer v.Close()
		_, err = v.ReadAt(make([]byte, 73), 0)
	}
	if !errors.Is(err, filesystem.ErrCorrupt) {
		t.Fatalf("malformed active file returned successful data: %v", err)
	}
}
