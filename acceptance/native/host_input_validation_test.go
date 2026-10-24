package native

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func hostInputTestValue(name string, data []byte) schema.HostInputValue {
	return schema.HostInputValue{Name: name, Bytes: int64(len(data)), Hex: hex.EncodeToString(data), SHA256: hostInputTestDigest(data)}
}

func hostInputTestDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func hostInputTestInventory() schema.HostInputInventory {
	fields := []schema.HostInputField{}
	for _, name := range []string{"accessTime", "acl", "attributes", "birthTime", "bsdFlags", "changeTime", "gid", "identity", "links", "mode", "modifyTime", "resourceFork", "sourceFlags", "uid"} {
		field := schema.HostInputField{Field: name, State: "present", SourceFormat: "darwin-stat"}
		if name == "attributes" || name == "resourceFork" {
			field.SourceFormat = "darwin-xattrs"
		}
		if name == "acl" {
			field.SourceFormat = "darwin-filesec"
		}
		if name == "acl" || name == "resourceFork" {
			field.State = "absent"
		}
		fields = append(fields, field)
	}
	return schema.HostInputInventory{Schema: schema.HostInputSchema, Host: "darwin", Arch: "arm64", Go: "go1.27.1", Source: schema.CaseRef{Producer: 26, Recipe: "workspace-edits", Profile: "apfs", Stage: "before"}, Entries: []schema.HostInputEntry{
		{Entry: schema.Entry{Path: ".", Kind: "dir", NameBytes: hex.EncodeToString([]byte("HostImport")), Mode: 0750}, Identity: "volume:1", SourceMode: 0040750, SourceLinks: 2, Fields: fields, Security: schema.HostInputSecurity{State: "absent", Format: "darwin-filesec"}},
		{Entry: schema.Entry{Path: "data", NameBytes: "64617461", Kind: "file", Mode: 0640, Size: 7, SHA256: hostInputTestDigest([]byte("payload"))}, Identity: "volume:2", SourceMode: 0100640, SourceLinks: 1, Fields: fields, Attributes: []schema.HostInputValue{hostInputTestValue("org.go-apfs.binary", []byte{0, 0xff}), hostInputTestValue("org.go-apfs.empty", nil)}, Security: schema.HostInputSecurity{State: "absent", Format: "darwin-filesec"}},
	}}
}

func cloneHostInputTest(t *testing.T, original schema.HostInputInventory) schema.HostInputInventory {
	t.Helper()
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var result schema.HostInputInventory
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestHostInputInventoryRejectsContradictoryOrUnboundedEvidence(t *testing.T) {
	original := hostInputTestInventory()
	if err := ValidateHostInput(original, "darwin", original.Source); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*schema.HostInputInventory){
		"unknown schema":                 func(i *schema.HostInputInventory) { i.Schema++ },
		"different source":               func(i *schema.HostInputInventory) { i.Source.Producer = 27 },
		"different host":                 func(i *schema.HostInputInventory) { i.Host = "windows" },
		"parent traversal":               func(i *schema.HostInputInventory) { i.Entries[1].Entry.Path = "../data" },
		"missing parent":                 func(i *schema.HostInputInventory) { i.Entries[1].Entry.Path = "absent/data" },
		"missing name bytes":             func(i *schema.HostInputInventory) { i.Entries[1].Entry.NameBytes = "" },
		"repeated path":                  func(i *schema.HostInputInventory) { i.Entries[1].Entry.Path = "." },
		"missing field":                  func(i *schema.HostInputInventory) { i.Entries[1].Fields = i.Entries[1].Fields[:13] },
		"unknown field":                  func(i *schema.HostInputInventory) { i.Entries[1].Fields[0].Field = "invented" },
		"unavailable without reason":     func(i *schema.HostInputInventory) { i.Entries[1].Fields[0].State = "unavailable" },
		"unsupported relabelled present": func(i *schema.HostInputInventory) { i.Entries[1].Security.Format = "linux-posix-acl" },
		"contradictory acl state":        func(i *schema.HostInputInventory) { i.Entries[1].Security.State = "empty" },
		"foreign null acl":               func(i *schema.HostInputInventory) { i.Entries[1].Security.State = "null" },
		"negative attribute size":        func(i *schema.HostInputInventory) { i.Entries[1].Attributes[0].Bytes = -1 },
		"binary digest mismatch":         func(i *schema.HostInputInventory) { i.Entries[1].Attributes[0].Hex = "0000" },
		"missing empty digest":           func(i *schema.HostInputInventory) { i.Entries[1].Attributes[1].SHA256 = "" },
		"duplicate attribute": func(i *schema.HostInputInventory) {
			i.Entries[1].Attributes = append(i.Entries[1].Attributes, i.Entries[1].Attributes[0])
		},
		"too many attributes": func(i *schema.HostInputInventory) {
			i.Entries[1].Attributes = make([]schema.HostInputValue, schema.HostInputMaxAttributes+1)
		},
		"missing original link count": func(i *schema.HostInputInventory) { i.Entries[1].SourceLinks = 0 },
		"contradictory alias":         func(i *schema.HostInputInventory) { i.Entries[1].Identity = i.Entries[0].Identity },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := cloneHostInputTest(t, original)
			mutate(&candidate)
			if err := ValidateHostInput(candidate, "darwin", original.Source); err == nil {
				t.Fatal("contradictory evidence escaped input validation")
			}
		})
	}
}

func hostInputTestOutput(t *testing.T) (Paired, string) {
	t.Helper()
	directory := t.TempDir()
	inventory := hostInputTestInventory()
	data, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	name := "macos-26.workspace-edits.apfs.before.host-import.session-pack.UDZO.dmg"
	image := []byte("artifact binding fixture; native format checking remains separate")
	ref := schema.HostInputReference{File: "macos-26.host-input.json", Bytes: int64(len(data)), SHA256: hostInputTestDigest(data)}
	out := schema.Output{Name: name, File: name, Bytes: int64(len(image)), SHA256: hostInputTestDigest(image), Format: "UDZO", Operation: "build", Source: inventory.Source, HostInput: &ref, Expect: schema.Expectation{HostImport: &schema.HostImportExpectation{Route: "session-pack", Destination: "/HostImport", ClockNS: replayCommandClock, UID: 60001, GID: 60002, PreserveLinks: true}, Continuation: true}}
	for filename, value := range map[string][]byte{name: image, ref.File: data} {
		if err := os.WriteFile(filepath.Join(directory, filename), value, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return Paired{Name: name, Output: out, ByHost: map[string]schema.Output{"darwin": out}, Dirs: map[string]string{"darwin": directory}, Provenance: map[string]HostOutputProvenance{"darwin": {Arch: inventory.Arch, Go: inventory.Go, Commit: inventory.Commit}}}, directory
}

func TestHostInputLoaderChecksBothOriginalArtifactDigests(t *testing.T) {
	pair, directory := hostInputTestOutput(t)
	if _, err := loadHostInput(pair, "darwin"); err != nil {
		t.Fatal(err)
	}
	for _, filename := range []string{pair.Output.File, pair.Output.HostInput.File} {
		original, err := os.ReadFile(filepath.Join(directory, filename))
		if err != nil {
			t.Fatal(err)
		}
		changed := append([]byte(nil), original...)
		changed[len(changed)-1] ^= 1
		if err := os.WriteFile(filepath.Join(directory, filename), changed, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadHostInput(pair, "darwin"); err == nil {
			t.Fatal("changed artifact escaped its original binding", filename)
		}
		if err := os.WriteFile(filepath.Join(directory, filename), original, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestHostImportDescriptorCannotBypassOrdinaryNativeChecks(t *testing.T) {
	pair, _ := hostInputTestOutput(t)
	for name, mutate := range map[string]func(*schema.Output){
		"no input":             func(o *schema.Output) { o.HostInput = nil },
		"wrong operation":      func(o *schema.Output) { o.Operation = "repack" },
		"wrong destination":    func(o *schema.Output) { o.Expect.HostImport.Destination = "/" },
		"wrong profile":        func(o *schema.Output) { o.Source.Profile = "sealed-system" },
		"wrong stage":          func(o *schema.Output) { o.Source.Stage = "after" },
		"snapshot descriptor":  func(o *schema.Output) { o.Expect.Snapshot = "retained" },
		"workspace descriptor": func(o *schema.Output) { o.Expect.Workspace = &schema.WorkspaceExpectation{Policy: "preserve"} },
		"ignored clock":        func(o *schema.Output) { o.Expect.IgnoreTimes = []string{"access"} },
		"no continuation":      func(o *schema.Output) { o.Expect.Continuation = false },
		"expected refusal":     func(o *schema.Output) { o.Expect.ContinuationRefusal = "unsupported" },
		"different clock":      func(o *schema.Output) { o.Expect.HostImport.ClockNS++ },
		"unsafe inventory":     func(o *schema.Output) { o.HostInput.File = "../macos-26.input.json" },
		"unsafe image":         func(o *schema.Output) { o.File = "../macos-26.image.dmg" },
		"overlong inventory":   func(o *schema.Output) { o.HostInput.Bytes = schema.HostInputMaxBytes + 1 },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := pair.Output
			policy, ref := *candidate.Expect.HostImport, *candidate.HostInput
			candidate.Expect.HostImport, candidate.HostInput = &policy, &ref
			mutate(&candidate)
			if err := validateHostImportOutput(candidate); err == nil {
				t.Fatal("unqualified output became a host-input exception")
			}
		})
	}
}
