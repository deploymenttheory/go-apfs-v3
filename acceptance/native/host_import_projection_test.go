package native

import (
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"unicode/utf16"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// These are worked host-order kauth_filesec literals, not filesec codec output.
// The owner/group and ACE GUIDs deliberately contain non-palindromic bytes.
// copyfile_security's source-direct/destination-inherited composition and
// XNU kauth.h define the policy; their pinned sources are in docs/sources.json.
const (
	hostProjectionGUIDs     = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	hostProjectionDirect    = "202122232425262728292a2b2c2d2e2f2100000078563412"
	hostProjectionInherited = "303132333435363738393a3b3c3d3e3f11000000efbeadde"
	hostProjectionHeader    = "6dc12c01" + hostProjectionGUIDs
)

func hostProjectionRaw(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func hostProjectionFields(host string) []schema.HostInputField {
	fields := make([]schema.HostInputField, 0, 14)
	for _, name := range []string{"accessTime", "acl", "attributes", "birthTime", "bsdFlags", "changeTime", "gid", "identity", "links", "mode", "modifyTime", "resourceFork", "sourceFlags", "uid"} {
		format := host + "-stat"
		if host == "windows" {
			format = "windows-file-basic-info"
		}
		field := schema.HostInputField{Field: name, State: "present", SourceFormat: format}
		switch name {
		case "acl":
			field.SourceFormat = map[string]string{"darwin": "darwin-filesec", "linux": "linux-posix-acl", "windows": "windows-security-descriptor"}[host]
			field.State = "absent"
		case "attributes", "resourceFork":
			field.SourceFormat = host + "-xattrs"
			if host == "windows" {
				field.SourceFormat = "windows-named-streams"
			}
			if name == "resourceFork" {
				field.State = "absent"
			}
		case "identity", "links":
			if host == "windows" {
				field.SourceFormat = "windows-file-id"
			}
		case "sourceFlags":
			field.SourceFormat = map[string]string{"darwin": "darwin-stat", "linux": "linux-inode-flags", "windows": "windows-file-attributes"}[host]
		}
		if host != "darwin" && (name == "bsdFlags" || name == "resourceFork") || host == "windows" && (name == "mode" || name == "uid" || name == "gid") {
			field.State, field.Reason = "unavailable", "no implicit cross-platform representation"
		}
		fields = append(fields, field)
	}
	return fields
}

func hostProjectionInput(host, profile string) (schema.HostInputInventory, schema.View, schema.HostImportExpectation) {
	const payload = "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
	times := schema.Times{Birth: replayCommandClock - 9000000007, Modify: replayCommandClock + 123456789, Change: replayCommandClock + 987654321, Access: replayCommandClock + 765432198}
	entry := func(name, kind, identity, native string) schema.HostInputEntry {
		v := schema.HostInputEntry{Entry: schema.Entry{Path: name, NameBytes: hex.EncodeToString([]byte(name)), Kind: kind, ID: 901, Mode: 0654, UID: 501, GID: 20, Links: 1, Times: times}, Identity: identity, SourceLinks: 1, SourceMode: 0100654, Fields: hostProjectionFields(host), NativePath: native, Security: schema.HostInputSecurity{State: "absent", Format: map[string]string{"darwin": "darwin-filesec", "linux": "linux-posix-acl", "windows": "windows-security-descriptor"}[host]}}
		if kind == "file" {
			v.Entry.Size, v.Entry.SHA256 = 7, payload
		} else {
			v.Entry.Mode, v.Entry.Links, v.SourceMode = 0755, 0, 0040755
		}
		if name == "." {
			v.Entry.NameBytes = hex.EncodeToString([]byte("HostImport"))
		}
		if host == "windows" {
			v.Entry.Mode, v.Entry.UID, v.Entry.GID, v.SourceMode = 0, 0, 0, 0
			name, _ := hex.DecodeString(v.Entry.NameBytes)
			v.NameUTF16 = hostProjectionUTF16(string(name))
		}
		return v
	}
	root := entry(".", "dir", "host:1", "Fixture/tree")
	file := entry("data", "file", "host:2", "Fixture/tree/data")
	input := schema.HostInputInventory{Schema: schema.HostInputSchema, Host: host, Arch: "amd64", Go: "go1.27.1", Source: schema.CaseRef{Producer: 26, Recipe: "workspace-edits", Profile: profile, Stage: "before"}, Entries: []schema.HostInputEntry{root, file}}
	source := schema.View{Entries: []schema.Entry{
		{Path: "Fixture", NameBytes: "46697874757265", Kind: "dir", ID: 2, Mode: 0755, UID: 502, GID: 80, Times: schema.Times{Birth: 11000000001, Modify: 22000000002, Change: 33000000003, Access: 44000000004}},
		{Path: "Fixture/tree", NameBytes: "74726565", Kind: "dir", ID: 3, Mode: 0750},
		{Path: "Fixture/tree/data", NameBytes: "64617461", Kind: "file", ID: 4, Links: 1, Mode: 0600, Size: 7, SHA256: payload},
	}}
	policy := schema.HostImportExpectation{Route: "session-pack", Destination: "/HostImport", ClockNS: replayCommandClock, UID: 60001, GID: 60002, PreserveLinks: true}
	return input, source, policy
}

func hostProjectionUTF16(value string) string {
	var raw []byte
	for _, unit := range utf16.Encode([]rune(value)) {
		raw = append(raw, byte(unit), byte(unit>>8))
	}
	return hex.EncodeToString(raw)
}

func hostProjectionEntry(t *testing.T, view schema.View, name string) schema.Entry {
	t.Helper()
	for _, entry := range view.Entries {
		if entry.Path == name {
			return entry
		}
	}
	t.Fatal("missing projected entry", name)
	return schema.Entry{}
}

func hostProjectionSecurity(item *schema.HostInputEntry, state, raw string) {
	item.Security.State = state
	item.Security.Values = nil
	if raw != "" {
		data, _ := hex.DecodeString(raw)
		item.Security.Values = []schema.HostInputValue{hostInputTestValue("filesec", data)}
	}
	for i := range item.Fields {
		if item.Fields[i].Field == "acl" {
			item.Fields[i].State = state
			if state == "empty" || state == "null" {
				item.Fields[i].State = "present"
			}
		}
	}
}

func TestHostImportViewUsesCopiedClocksRatherThanSourceCreationOrChangeTimes(t *testing.T) {
	for _, profile := range []string{"apfs", "apfsx", "hfsplus", "hfsx"} {
		for _, olderModify := range []bool{false, true} {
			t.Run(profile+"/"+map[bool]string{false: "future-modify", true: "earlier-modify"}[olderModify], func(t *testing.T) {
				input, source, policy := hostProjectionInput("darwin", profile)
				want := schema.Times{Birth: replayCommandClock, Modify: replayCommandClock + 123456789, Change: replayCommandClock, Access: replayCommandClock + 765432198}
				if olderModify {
					input.Entries[1].Entry.Times.Modify = replayCommandClock - 123456789
					want.Birth, want.Modify = replayCommandClock-123456789, replayCommandClock-123456789
				}
				if strings.HasPrefix(profile, "hfs") {
					want.Birth = 1749283750000000000
					if olderModify {
						want.Birth, want.Modify = 1749283749000000000, 1749283749000000000
					} else {
						want.Modify = 1749283750000000000
					}
					want.Access = 1749283750000000000
				}
				view, err := HostImportView(input, policy, source)
				if err != nil {
					t.Fatal(err)
				}
				if got := hostProjectionEntry(t, view, "HostImport/data").Times; !reflect.DeepEqual(got, want) {
					t.Fatalf("copy clock policy: got %+v, want %+v", got, want)
				}
			})
		}
	}
}

func TestHostImportViewCountsCopiedAliasesWithoutMergingEqualIndependentFiles(t *testing.T) {
	input, source, policy := hostProjectionInput("darwin", "apfs")
	file := input.Entries[1]
	file.Entry.Links, file.SourceLinks = 4, 4 // Two other host names are outside the import.
	alias := file
	alias.Entry.Path, alias.Entry.NameBytes = "alias", "616c696173"
	independent := file
	independent.Entry.Path, independent.Entry.NameBytes, independent.Identity = "independent", "696e646570656e64656e74", "host:3"
	independent.Entry.Links, independent.SourceLinks = 1, 1
	input.Entries = []schema.HostInputEntry{input.Entries[0], alias, file, independent}
	view, err := HostImportView(input, policy, source)
	if err != nil {
		t.Fatal(err)
	}
	a, b, c := hostProjectionEntry(t, view, "HostImport/alias"), hostProjectionEntry(t, view, "HostImport/data"), hostProjectionEntry(t, view, "HostImport/independent")
	if a.ID != b.ID || a.ID == c.ID || a.Links != 2 || b.Links != 2 || c.Links != 1 {
		t.Fatalf("copied identities/counts: alias=%d/%d data=%d/%d independent=%d/%d", a.ID, a.Links, b.ID, b.Links, c.ID, c.Links)
	}
}

func TestHostImportViewPreservesBinaryAndEmptyAttributesWithoutStorageCompressionFlag(t *testing.T) {
	input, source, policy := hostProjectionInput("darwin", "apfs")
	item := &input.Entries[1]
	item.Entry.Flags, item.SourceFlags = 0x21, 0x21 // NODUMP and storage-owned COMPRESSED.
	item.Attributes = []schema.HostInputValue{hostInputTestValue("org.go-apfs.binary", []byte{0, 1, 0xff, 0}), hostInputTestValue("org.go-apfs.empty", nil), hostInputTestValue("com.apple.ResourceFork", []byte{0xff, 0, 2})}
	for i := range item.Fields {
		if item.Fields[i].Field == "resourceFork" {
			item.Fields[i].State = "present"
		}
	}
	view, err := HostImportView(input, policy, source)
	if err != nil {
		t.Fatal(err)
	}
	got := hostProjectionEntry(t, view, "HostImport/data")
	want := []schema.Xattr{{Name: "org.go-apfs.binary", Bytes: 4, SHA256: hostInputTestDigest([]byte{0, 1, 0xff, 0})}, {Name: "org.go-apfs.empty", Bytes: 0, SHA256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}, {Name: "com.apple.ResourceFork", Bytes: 3, SHA256: hostInputTestDigest([]byte{0xff, 0, 2})}}
	if !reflect.DeepEqual(got.Xattrs, want) || got.Flags != 1 || got.Compression != nil {
		t.Fatalf("logical attributes/flags: got %+v, want attributes %+v and NODUMP only", got, want)
	}
}

func TestHostImportDarwinACLProjectionPreservesOpaqueGUIDsAndDirectACEs(t *testing.T) {
	zeroGUIDs := strings.Repeat("00", 32)
	for _, test := range []struct{ name, state, raw, host, disk string }{
		{"absent", "absent", "", "", ""},
		{"no-acl-null-guids", "absent", "6dc12c01" + zeroGUIDs + "ffffffff00000000", "", ""},
		{"owner-guids-without-acl", "absent", hostProjectionHeader + "ffffffff78563412", hostProjectionHeader + "ffffffff00000000", "012cc16d" + hostProjectionGUIDs + "ffffffff00000000"},
		{"explicit-empty", "empty", hostProjectionHeader + "0000000078563412", hostProjectionHeader + "0000000000000000", "012cc16d" + hostProjectionGUIDs + "0000000000000000"},
		{"direct-and-inherited", "present", hostProjectionHeader + "0200000078563412" + hostProjectionDirect + hostProjectionInherited, hostProjectionHeader + "0100000000000000" + hostProjectionDirect, "012cc16d" + hostProjectionGUIDs + "0000000100000000202122232425262728292a2b2c2d2e2f0000002112345678"},
		{"only-inherited-becomes-empty", "present", hostProjectionHeader + "0100000078563412" + hostProjectionInherited, hostProjectionHeader + "0000000000000000", "012cc16d" + hostProjectionGUIDs + "0000000000000000"},
	} {
		t.Run(test.name, func(t *testing.T) {
			input, source, policy := hostProjectionInput("darwin", "apfs")
			hostProjectionSecurity(&input.Entries[1], test.state, test.raw)
			before, _ := json.Marshal(input)
			view, err := HostImportView(input, policy, source)
			if err != nil {
				t.Fatal(err)
			}
			if got := hostProjectionEntry(t, view, "HostImport/data").ACL; got != test.host {
				t.Fatalf("native host ACL: got %s, want %s", got, test.host)
			}
			disk, err := HostImportDiskACL(input.Entries[1].Security)
			if err != nil || hex.EncodeToString(disk) != test.disk {
				t.Fatalf("disk ACL: got %x (%v), want %s", disk, err, test.disk)
			}
			after, _ := json.Marshal(input)
			if string(after) != string(before) {
				t.Fatal("projection changed raw source security evidence")
			}
		})
	}
}

func TestHostImportViewRejectsACLStateThatContradictsOriginalFilesec(t *testing.T) {
	for _, test := range []struct{ state, raw string }{
		{"absent", hostProjectionHeader + "0100000000000000" + hostProjectionDirect},
		{"empty", hostProjectionHeader + "0100000000000000" + hostProjectionDirect},
		{"present", hostProjectionHeader + "ffffffff00000000"},
		{"present", hostProjectionHeader + "0000000000000000"},
	} {
		t.Run(test.state+"/"+test.raw[72:80], func(t *testing.T) {
			input, source, policy := hostProjectionInput("darwin", "apfs")
			hostProjectionSecurity(&input.Entries[1], test.state, test.raw)
			if _, err := HostImportView(input, policy, source); err == nil {
				t.Fatal("contradictory source ACL state was converted into a native expectation")
			}
		})
	}
}

func TestHostImportDiskACLRejectsMalformedHostRecords(t *testing.T) {
	for name, raw := range map[string]string{
		"truncated-header":    "6dc12c01",
		"network-order-input": "012cc16d" + hostProjectionGUIDs + "0000000100000000" + hostProjectionDirect,
		"truncated-ace":       hostProjectionHeader + "0100000000000000",
		"trailing-ace":        hostProjectionHeader + "0000000000000000" + hostProjectionDirect,
		"noacl-with-ace":      hostProjectionHeader + "ffffffff00000000" + hostProjectionDirect,
		"over-limit-count":    hostProjectionHeader + "8100000000000000",
	} {
		t.Run(name, func(t *testing.T) {
			security := schema.HostInputSecurity{State: "present", Format: "darwin-filesec", Values: []schema.HostInputValue{hostInputTestValue("filesec", hostProjectionRaw(t, raw))}}
			if result, err := HostImportDiskACL(security); err == nil || result != nil {
				t.Fatalf("malformed source produced a disk ACL: %x, %v", result, err)
			}
		})
	}
}

func TestHostImportViewKeepsForeignSecurityAndNamedStreamsAsSourceFacts(t *testing.T) {
	for _, host := range []string{"linux", "windows"} {
		for _, route := range []string{"session-pack", "image-copy"} {
			t.Run(host+"/"+route, func(t *testing.T) {
				input, source, policy := hostProjectionInput(host, "apfs")
				if route == "image-copy" {
					policy.Route, policy.Destination = route, "/Fixture/HostImport"
					policy.UID, policy.GID = 502, 80
				}
				item := &input.Entries[1]
				item.SourceFlags = 0x8120
				if host == "linux" {
					// Original POSIX ACL bytes remain visible, but are never
					// reinterpreted as opaque Darwin GUID/ACE records.
					const accessACL = "0200000001000600ffffffff02000400feff000004000400ffffffff10000400ffffffff20000400ffffffff"
					item.Attributes = []schema.HostInputValue{hostInputTestValue("system.posix_acl_access", hostProjectionRaw(t, accessACL)), hostInputTestValue("user.binary", []byte{0, 0xff}), hostInputTestValue("user.empty", nil)}
					hostProjectionSecurity(item, "present", accessACL)
				} else {
					// Self-relative SD header with a NULL DACL. Source bytes
					// and ADS names/values are not macOS xattrs or filesec.
					hostProjectionSecurity(item, "null", "0100048000000000000000000000000000000000")
					item.NamedStreams = []schema.HostInputValue{hostInputTestValue(":binary:$DATA", []byte{0, 0xff}), hostInputTestValue(":empty:$DATA", nil)}
					for i := range item.NamedStreams {
						item.NamedStreams[i].NameUTF16 = hostProjectionUTF16(item.NamedStreams[i].Name)
					}
				}
				before, _ := json.Marshal(input)
				view, err := HostImportView(input, policy, source)
				if err != nil {
					t.Fatal(err)
				}
				got := hostProjectionEntry(t, view, strings.TrimPrefix(policy.Destination, "/")+"/data")
				if got.ACL != "" || got.Flags != 0 {
					t.Fatal("foreign raw security/flags became native Darwin metadata", got)
				}
				if host == "windows" {
					uid, gid := uint32(60001), uint32(60002)
					if route == "image-copy" {
						uid, gid = 502, 80
					}
					if len(got.Xattrs) != 0 || got.UID != uid || got.GID != gid || got.Mode != 0644 {
						t.Fatalf("unmapped Windows source/defaults: got %+v, want uid=%d gid=%d mode=0644 without xattrs", got, uid, gid)
					}
				} else if len(got.Xattrs) != 2 || got.Xattrs[0].Name != "user.binary" || got.Xattrs[1].Name != "user.empty" || got.Mode != 0654 || got.UID != 501 || got.GID != 20 {
					t.Fatal("Linux ordinary attrs/ownership were lost or POSIX ACL became an ordinary attr", got)
				}
				after, _ := json.Marshal(input)
				if string(before) != string(after) {
					t.Fatal("projection rewrote unsupported original host evidence")
				}
			})
		}
	}
}

func TestHostImportViewPreservesEveryUntouchedCapturedNativeEntry(t *testing.T) {
	// This existing immutable observation is read in place. Its captured IDs,
	// aliases, flags, contents, links and clocks are never generated by a product
	// reader or replaced with host input expectations.
	file, err := os.Open("../fixture/testdata/apfs-duplicate-identity-observation.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			t.Error(err)
		}
	}()
	reader, err := gzip.NewReader(file)
	if err != nil {
		t.Fatal(err)
	}
	var observation schema.Observation
	if err := json.NewDecoder(reader).Decode(&observation); err != nil {
		t.Fatal(err)
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if len(observation.Views) != 1 || len(observation.Views[0].Entries) != 13 {
		t.Fatal("original captured peer inventory changed")
	}
	source := observation.Views[0]
	input, _, policy := hostProjectionInput("darwin", "apfs")
	// This unit checks projection of real peers, not the closed output matrix:
	// retain this observation's actual provenance rather than relabelling it as
	// a newly captured workspace-edits control.
	input.Source = schema.CaseRef{Producer: observation.Producer.Major, Recipe: observation.Recipe, Profile: observation.Profile, Stage: observation.Stage}
	policy.Route, policy.Destination = "image-copy", "/Fixture/HostImport"
	for _, entry := range source.Entries {
		if entry.Path == "Fixture" {
			policy.UID, policy.GID = entry.UID, entry.GID
		}
	}
	input.Entries[1].NativePath = "Fixture/tree/nested/leaf"
	for _, entry := range source.Entries {
		if entry.Path == input.Entries[1].NativePath {
			input.Entries[1].Entry.Size, input.Entries[1].Entry.SHA256 = entry.Size, entry.SHA256
		}
	}
	before, _ := json.Marshal(source)
	view, err := HostImportView(input, policy, source)
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range source.Entries {
		want := original
		if want.Path == "Fixture" {
			want.Times.Modify, want.Times.Change = replayCommandClock, replayCommandClock
		}
		if got := hostProjectionEntry(t, view, original.Path); !reflect.DeepEqual(got, want) {
			t.Fatalf("captured peer %s changed: got %+v, want %+v", original.Path, got, want)
		}
	}
	if len(view.Entries) != len(source.Entries)+len(input.Entries) || !slices.IsSortedFunc(view.Entries, func(a, b schema.Entry) int { return strings.Compare(a.Path, b.Path) }) {
		t.Fatal("imported subtree dropped/duplicated native peers or output ordering")
	}
	after, _ := json.Marshal(source)
	if string(before) != string(after) {
		t.Fatal("projection mutated the original Apple observation")
	}
}

func TestHostImportViewRefusesUnqualifiedDestinationOwnershipOrACLInheritance(t *testing.T) {
	for _, change := range []string{"uid", "gid", "parent-acl", "existing-destination"} {
		t.Run(change, func(t *testing.T) {
			input, source, policy := hostProjectionInput("windows", "apfs")
			policy.Route, policy.Destination, policy.UID, policy.GID = "image-copy", "/Fixture/HostImport", 502, 80
			switch change {
			case "uid":
				policy.UID++
			case "gid":
				policy.GID++
			case "parent-acl":
				source.Entries[0].ACL = hostProjectionHeader + "0100000000000000" + hostProjectionInherited
			case "existing-destination":
				source.Entries = append(source.Entries, schema.Entry{Path: "Fixture/HostImport", Kind: "dir", ID: 50})
			}
			if _, err := HostImportView(input, policy, source); err == nil {
				t.Fatal("unqualified destination was converted into an import expectation", change)
			}
		})
	}
}
