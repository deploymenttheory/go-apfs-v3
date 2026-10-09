package acceptance_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io/fs"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/filesystem"
)

type nativeLookup struct {
	Path   string `json:"path"`
	Object uint64 `json:"object"`
}
type nativeFragmentedFork struct {
	Path      string                                      `json:"path"`
	Attribute string                                      `json:"attribute"`
	Ranges    []struct{ Logical, Physical, Length int64 } `json:"ranges"`
	Samples   []struct {
		Offset, Size int64
		SHA256       string `json:"sha256"`
	} `json:"samples"`
}

// Native lookup results include both equivalences and distinctions. Hard-link
// aliases must share identity and all file/fork metadata. Darwin extent maps
// prove that the HFS+ cases actually require records beyond the inline eight.
func TestNativeFileSemantics(t *testing.T) {
	testFileCorpus(t, "file-semantics", "APFS_NATIVE_SEMANTICS", "testdata/semantics", 30, compareSemantics)
}

func compareSemantics(t *testing.T, r filesystem.Reader, want fileObservation, caseID string) {
	t.Helper()
	ctx := context.Background()
	inventory := map[string]int{"ascii": 4, "canonical": 4, "reorder": 3, "hangul": 3, "sharp-s": 4, "sigma": 4, "iota": 4, "angstrom": 4, "ligature": 4, "deseret": 3, "unicode-11": 3, "unicode-14": 3, "unicode-16": 3, "ignorable": 4, "colon": 3}
	if len(want.Lookups) != 53 {
		t.Fatal("incomplete native filename observations")
	}
	positives, negatives := 0, 0
	seen := map[string]bool{}
	for _, query := range want.Lookups {
		if seen[query.Path] || !strings.HasPrefix(query.Path, "Fixture/names/") {
			t.Fatal("invalid or duplicate lookup observation")
		}
		seen[query.Path] = true
		parts := strings.Split(query.Path, "/")
		if len(parts) != 4 || inventory[parts[2]] <= 0 {
			t.Fatal("unexpected filename scenario", query.Path)
		}
		inventory[parts[2]]--
		got, err := filesystem.Lookup(ctx, r, query.Path)
		if query.Object == 0 {
			negatives++
			if !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("%q: native missing, got %d, %v", query.Path, got, err)
			}
		} else {
			positives++
			if err != nil || got != query.Object {
				t.Errorf("%q: native object %d, got %d, %v", query.Path, query.Object, got, err)
			}
		}
	}
	for label, missing := range inventory {
		if missing != 0 {
			t.Fatal("incomplete filename scenario", label)
		}
	}
	if positives < 13 || negatives < 13 {
		t.Fatal("native lookups must contain successful and missing results")
	}
	aliases := map[string]bool{"Fixture/alias": false, "Fixture/links/original": false, "Fixture/links/second": false}
	var inode uint64
	for _, entry := range want.Entries {
		if _, ok := aliases[entry.Path]; ok {
			aliases[entry.Path] = true
			if entry.Object == 0 || entry.Links != 3 || (inode != 0 && inode != entry.Object) || entry.Attributes[filesystem.ResourceFork].Size == 0 || entry.Attributes["org.go-apfs.link"].Size == 0 {
				t.Fatal("native hard-link preconditions missing")
			}
			inode = entry.Object
		}
	}
	for path, found := range aliases {
		if !found {
			t.Fatal("missing native hard-link alias", path)
		}
	}
	hfs := strings.HasSuffix(caseID, "/hfsplus") || strings.HasSuffix(caseID, "/hfsx")
	if (hfs && len(want.FragmentedForks) != 2) || (!hfs && len(want.FragmentedForks) != 0) {
		t.Fatal("invalid fragmented fork inventory")
	}
	forks := map[string]string{"Fixture/fragmented-data": "", "Fixture/fragmented-resource": filesystem.ResourceFork}
	for _, f := range want.FragmentedForks {
		attribute, known := forks[f.Path]
		if !known || f.Attribute != attribute {
			t.Fatal("unknown or duplicate fragmented fork")
		}
		delete(forks, f.Path)
		if len(f.Ranges) <= 8 || len(f.Samples) != len(f.Ranges)-1 {
			t.Fatal("native overflow extent precondition missing")
		}
		id, err := filesystem.LookupExact(ctx, r, f.Path)
		if err != nil {
			t.Fatal(err)
		}
		var value filesystem.Value
		if f.Attribute == "" {
			value, err = r.OpenData(ctx, id)
		} else {
			value, err = r.OpenAttribute(ctx, id, f.Attribute)
		}
		if err != nil {
			t.Fatal(err)
		}
		var end int64
		for _, extent := range f.Ranges {
			if extent.Logical != end || extent.Length <= 0 || extent.Physical < 0 || extent.Length > value.Size()-end {
				t.Fatal("invalid native extent observation")
			}
			end += extent.Length
		}
		if end != value.Size() {
			t.Fatal("incomplete native fork mapping")
		}
		// Reverse order exercises random reads across every observed boundary.
		for i := len(f.Samples) - 1; i >= 0; i-- {
			sample := f.Samples[i]
			if sample.Size <= 0 || sample.Size > 34 || sample.Offset != f.Ranges[i+1].Logical-17 {
				t.Fatal("invalid boundary sample")
			}
			data := make([]byte, sample.Size)
			if _, err := value.ReadAt(data, sample.Offset); err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(data)
			if hex.EncodeToString(digest[:]) != sample.SHA256 {
				t.Fatal("fragment boundary bytes differ", f.Path, sample.Offset)
			}
		}
		if err := value.Close(); err != nil {
			t.Fatal(err)
		}
		t.Logf("%s: %d native extents and boundary reads matched", f.Path, len(f.Ranges))
	}
}
