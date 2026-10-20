package native

import (
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func entry(path string, id uint64) schema.Entry {
	return schema.Entry{Path: path, NameBytes: "61", Kind: "file", ID: id, Links: 1, Mode: 0o644, Size: 3, SHA256: "abc", Times: schema.Times{Birth: 1, Modify: 2, Change: 3, Access: 4}, Xattrs: []schema.Xattr{{Name: "org.x", Bytes: 1, SHA256: "ffffffffffff"}}}
}

func TestCompareViewsReportsEveryKindOfDifference(t *testing.T) {
	want := schema.View{Entries: []schema.Entry{entry("Fixture/a", 10), entry("Fixture/b", 11)}}
	got := schema.View{Entries: []schema.Entry{entry("a", 20), entry("c", 22)}}
	got.Entries[0].Mode = 0o600
	got.Entries[0].Times.Change = 99
	got.Entries[0].Xattrs = nil
	diffs := CompareViews(got, want, CompareOptions{Subtree: "Fixture", IgnoreIdentity: true, IgnoreTimes: map[string]bool{"change": true}})
	var fields []string
	for _, d := range diffs {
		fields = append(fields, d.Path+":"+d.Field)
	}
	joined := strings.Join(fields, " ")
	for _, want := range []string{"a:mode", "a:xattr.org.x", "b:presence", "c:presence"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing difference %s in %s", want, joined)
		}
	}
	for _, unwanted := range []string{"a:id", "a:time.change"} {
		if strings.Contains(joined, unwanted) {
			t.Errorf("ignored field reported: %s", unwanted)
		}
	}
	if len(CompareViews(want, want, CompareOptions{})) != 0 {
		t.Error("identical views differ")
	}
}

func TestKnownDriftMatchesOnlyRecordedPairs(t *testing.T) {
	allow := &schema.KnownDrift{Schema: 1, Entries: []schema.DriftEntry{{Recipe: "compressed-files", Path: "Fixture/type-15", Field: "compression.kernelRead", Producers: map[string]string{"macos-15": "EIO", "macos-27": "ok"}, Reason: "r"}}}
	d := Difference{Path: "Fixture/type-15", Field: "compression.kernelRead", Got: "EIO", Want: "ok"}
	if !KnownDrift(allow, "compressed-files", "apfs", d, [2]int{15, 27}) {
		t.Error("recorded drift not matched")
	}
	if KnownDrift(allow, "compressed-files", "apfs", d, [2]int{26, 27}) {
		t.Error("unrecorded producer pair matched")
	}
	if KnownDrift(allow, "file-corpus", "apfs", d, [2]int{15, 27}) {
		t.Error("other recipe matched")
	}
}

func TestPairRequiresEveryHostAndEqualPlaintext(t *testing.T) {
	plain := schema.Output{Name: "x.build.UDZO.dmg", File: "x", Operation: "build", SHA256: "aa", Bytes: 1}
	enc := schema.Output{Name: "x.enc.dmg", File: "y", Operation: "encrypt", Encrypted: true, SHA256: "bb", Bytes: 1}
	linux := HostOutputs{Dir: "/l", Manifest: schema.Outputs{Host: "linux", Lock: "L", Outputs: []schema.Output{plain, enc}}}
	windows := HostOutputs{Dir: "/w", Manifest: schema.Outputs{Host: "windows", Lock: "L", Outputs: []schema.Output{plain, enc}}}
	if _, err := Pair(map[string]HostOutputs{"linux": linux, "windows": windows}); err == nil || !strings.Contains(err.Error(), "not all distinct") {
		t.Fatalf("identical encrypted outputs accepted: %v", err)
	}
	enc2 := enc
	enc2.SHA256 = "cc"
	windows.Manifest.Outputs = []schema.Output{plain, enc2}
	pairs, err := Pair(map[string]HostOutputs{"linux": linux, "windows": windows})
	if err != nil || len(pairs) != 2 || pairs[0].Primary != "linux" {
		t.Fatalf("pairs %+v err %v", pairs, err)
	}
	plain2 := plain
	plain2.SHA256 = "zz"
	windows.Manifest.Outputs = []schema.Output{plain2, enc2}
	if _, err := Pair(map[string]HostOutputs{"linux": linux, "windows": windows}); err == nil || !strings.Contains(err.Error(), "plaintext bytes differ") {
		t.Fatalf("differing plaintext accepted: %v", err)
	}
	windows.Manifest.Outputs = []schema.Output{enc2}
	if _, err := Pair(map[string]HostOutputs{"linux": linux, "windows": windows}); err == nil || !strings.Contains(err.Error(), "missing from") {
		t.Fatalf("missing output accepted: %v", err)
	}
	windows.Manifest.Lock = "M"
	windows.Manifest.Outputs = []schema.Output{plain, enc2}
	if _, err := Pair(map[string]HostOutputs{"linux": linux, "windows": windows}); err == nil || !strings.Contains(err.Error(), "different locks") {
		t.Fatalf("lock mismatch accepted: %v", err)
	}
}

func TestComparisonUnderAStoragePolicyIgnoresOnlyCompressionOwnedStorage(t *testing.T) {
	source := schema.Entry{Path: "f", Kind: "file", Flags: 0x20, Size: 9, SHA256: "aa", Compression: &schema.Compression{Type: 7, Storage: "attribute", KernelRead: "ok"},
		Xattrs: []schema.Xattr{{Name: "com.apple.decmpfs", Bytes: 30, SHA256: "decmpfs-source"}, {Name: "org.example", Bytes: 1, SHA256: "kept"}}}
	none := schema.Entry{Path: "f", Kind: "file", Size: 9, SHA256: "aa", Xattrs: []schema.Xattr{{Name: "org.example", Bytes: 1, SHA256: "kept"}}}
	if d := compareEntry(none, source, CompareOptions{FileCompression: "none"}); len(d) != 0 {
		t.Fatalf("a decompressed build differs only in compression-owned storage, got %v", d)
	}
	stillCompressed := none
	stillCompressed.Compression = &schema.Compression{Type: 7, KernelRead: "ok"}
	if d := compareEntry(stillCompressed, source, CompareOptions{FileCompression: "none"}); len(d) != 1 || d[0].Field != "compression" {
		t.Fatalf("compression left under the none policy must be reported, got %v", d)
	}
	lost := none
	lost.Xattrs = nil
	if d := compareEntry(lost, source, CompareOptions{FileCompression: "none"}); len(d) != 1 || d[0].Field != "xattr.org.example" {
		t.Fatalf("an ordinary attribute lost by a policy build must be reported, got %v", d)
	}
}

func TestComparisonUsesTheKernelReadOutcomeWhenTheKernelCannotHash(t *testing.T) {
	readable := schema.Entry{Path: "lz4", Kind: "file", Size: 9, SHA256: "aa", Compression: &schema.Compression{Type: 15, KernelRead: "ok"}}
	refused := schema.Entry{Path: "lz4", Kind: "file", Size: 9, Compression: &schema.Compression{Type: 15, KernelRead: "EIO"}}
	d := compareEntry(refused, readable, CompareOptions{})
	if len(d) != 1 || d[0].Field != "compression.kernelRead" || d[0].Got != "EIO" {
		t.Fatalf("a refused read is one kernelRead difference, not a digest difference, got %v", d)
	}
}

func TestComparisonChecksIdentityOnlyForEntriesThatExistedBeforeAnEdit(t *testing.T) {
	want := []schema.Entry{entry("old", 10), entry("new", 11)}
	got := []schema.Entry{entry("old", 10), entry("new", 12)}
	existing := map[string]bool{"old": true}
	if d := CompareViews(schema.View{Entries: got}, schema.View{Entries: want}, CompareOptions{Existing: existing}); len(d) != 0 {
		t.Fatalf("a created entry may take the allocator's identity, got %v", d)
	}
	got[0].ID = 13
	if d := CompareViews(schema.View{Entries: got}, schema.View{Entries: want}, CompareOptions{Existing: existing}); len(d) != 1 || d[0].Path != "old" {
		t.Fatalf("an existing entry must keep its identity, got %v", d)
	}
}

func TestContainerChecksAreSpreadAcrossALineage(t *testing.T) {
	repack := func(name, format string, encrypted bool) Paired {
		return Paired{Name: name, Output: schema.Output{Name: name, Operation: "repack", Format: format, Encrypted: encrypted, Expect: schema.Expectation{DiskSHA256: "d"}},
			ByHost: map[string]schema.Output{"darwin": {}, "linux": {}, "windows": {}}}
	}
	group := []Paired{
		repack("a.UDRO", "UDRO", false), repack("a.UDZO", "UDZO", false), repack("a.enc", "UDZO", true),
		repack("b.UDRO", "UDRO", false), repack("b.UDZO", "UDZO", false), repack("b.enc", "UDZO", true),
		repack("c.enc", "UDZO", true),
		{Name: "edit", Output: schema.Output{Name: "edit", Operation: "edit", Format: "UDZO", Expect: schema.Expectation{DiskSHA256: "d"}}},
	}
	planContainerChecks(group)
	for i, wantSkip := range []bool{false, false, false, true, true, true, true, false} {
		if group[i].SkipChecksums != wantSkip {
			t.Errorf("%s: skip checksums %v, want %v (verify once per format and encryption)", group[i].Name, group[i].SkipChecksums, wantSkip)
		}
	}
	var decrypted []string
	for _, p := range group {
		if p.Output.Encrypted {
			if len(p.DecryptHosts) != 1 {
				t.Fatalf("%s: decrypt hosts %v, want one", p.Name, p.DecryptHosts)
			}
			decrypted = append(decrypted, p.DecryptHosts[0])
		} else if len(p.DecryptHosts) != 0 {
			t.Errorf("%s: plaintext output selected for decryption", p.Name)
		}
	}
	if strings.Join(decrypted, ",") != "darwin,linux,windows" {
		t.Errorf("decryption rotated through %v, want every host in turn", decrypted)
	}
}
