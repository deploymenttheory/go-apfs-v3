package native

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func hostPairUTF16(value string) string {
	units := utf16.Encode([]rune(value))
	data := make([]byte, 2*len(units))
	for i, unit := range units {
		data[2*i], data[2*i+1] = byte(unit), byte(unit>>8)
	}
	return hex.EncodeToString(data)
}

func hostPairInventory(t *testing.T, host string) schema.HostInputInventory {
	t.Helper()
	inventory := cloneHostInputTest(t, hostInputTestInventory())
	inventory.Host = host
	if host != "darwin" {
		inventory.Arch = "amd64"
	}
	for i := range inventory.Entries {
		item := &inventory.Entries[i]
		item.Entry.UID, item.Entry.GID = 60001, 60002
		item.Entry.Mode = 0644
		item.SourceMode = 0100644
		if item.Entry.Kind == "dir" {
			item.Entry.Mode, item.SourceMode = 0755, 0040755
		}
		item.Attributes = nil
		item.Entry.Times = schema.Times{Birth: 1_704_164_645_000_000_000, Modify: replayCommandClock + 3_600_000_000_000, Change: replayCommandClock + 7_200_000_000_000, Access: 2_059_369_628_000_000_000}
		item.Identity = host + ":" + item.Identity
		if host == "darwin" {
			continue
		}
		item.Security.Format = "linux-posix-acl"
		for j := range item.Fields {
			field := &item.Fields[j]
			field.SourceFormat = "linux-stat"
			switch field.Field {
			case "birthTime":
				field.SourceFormat = "linux-statx"
			case "acl":
				field.SourceFormat = "linux-posix-acl"
			case "attributes", "resourceFork":
				field.SourceFormat = "linux-xattrs"
			case "bsdFlags", "sourceFlags":
				field.SourceFormat = "linux-inode-flags"
			}
			if field.Field == "bsdFlags" || field.Field == "sourceFlags" || field.Field == "resourceFork" {
				field.State, field.Reason = "unavailable", "the host representation does not supply this Darwin field"
			}
		}
		if host != "windows" {
			continue
		}
		name, err := hex.DecodeString(item.Entry.NameBytes)
		if err != nil {
			t.Fatal(err)
		}
		item.NameUTF16 = hostPairUTF16(string(name))
		item.Entry.Mode, item.Entry.UID, item.Entry.GID, item.SourceMode = 0, 0, 0, 0
		item.Security.Format = "windows-security-descriptor"
		for j := range item.Fields {
			field := &item.Fields[j]
			field.SourceFormat = "windows-file-basic-info"
			switch field.Field {
			case "identity", "links":
				field.SourceFormat = "windows-file-id"
			case "mode", "bsdFlags", "sourceFlags":
				field.SourceFormat = "windows-file-attributes"
			case "uid", "gid", "acl":
				field.SourceFormat = "windows-security-descriptor"
			case "attributes", "resourceFork":
				field.SourceFormat = "windows-named-streams"
			}
			if field.Field == "mode" || field.Field == "uid" || field.Field == "gid" || field.Field == "bsdFlags" || field.Field == "resourceFork" {
				field.State, field.Reason = "unavailable", "no configured Darwin conversion for this native representation"
			} else if field.Field != "acl" {
				field.State, field.Reason = "present", ""
			}
		}
	}
	return inventory
}

func hostPairArtifacts(t *testing.T, variedInput, variedImages bool) map[string]HostOutputs {
	t.Helper()
	hosts := map[string]HostOutputs{}
	for index, host := range []string{"darwin", "linux", "windows"} {
		inventory := hostPairInventory(t, host)
		if variedInput {
			data := []byte(fmt.Sprintf("independent original host input %d", index))
			inventory.Entries[1].Entry.Size = int64(len(data))
			inventory.Entries[1].Entry.SHA256 = hostInputTestDigest(data)
		}
		if err := ValidateHostInput(inventory, host, inventory.Source); err != nil {
			t.Fatal(host, err)
		}
		directory := t.TempDir()
		data, err := json.Marshal(inventory)
		if err != nil {
			t.Fatal(err)
		}
		image := []byte("ordinary artifact binding fixture")
		if variedImages {
			image = []byte(fmt.Sprintf("different artifact binding fixture %d", index))
		}
		name := hostImportOutputName(inventory.Source, "session-pack")
		ref := schema.HostInputReference{File: "macos-26.host-input.json", Bytes: int64(len(data)), SHA256: hostInputTestDigest(data)}
		out := schema.Output{Name: name, File: name, Bytes: int64(len(image)), SHA256: hostInputTestDigest(image), Operation: "build", Format: "UDZO", Source: inventory.Source, HostInput: &ref, Expect: schema.Expectation{HostImport: &schema.HostImportExpectation{Route: "session-pack", Destination: "/HostImport", ClockNS: replayCommandClock, UID: 60001, GID: 60002, PreserveLinks: true}, Continuation: true}}
		for filename, contents := range map[string][]byte{out.File: image, ref.File: data} {
			if err := os.WriteFile(filepath.Join(directory, filename), contents, 0600); err != nil {
				t.Fatal(err)
			}
		}
		hosts[host] = HostOutputs{Dir: directory, Manifest: schema.Outputs{Schema: schema.OutputsSchema, Host: host, Arch: inventory.Arch, Go: inventory.Go, Commit: inventory.Commit, Lock: "original-qualified-lock", Outputs: []schema.Output{out}}}
	}
	return hosts
}

func TestHostImportPairRequiresEqualBytesForEqualEffectiveInputs(t *testing.T) {
	if _, err := Pair(hostPairArtifacts(t, false, false)); err != nil {
		t.Fatal(err)
	}
	if _, err := Pair(hostPairArtifacts(t, false, true)); err == nil {
		t.Fatal("equivalent observed host inputs bypassed plaintext determinism")
	}
	if _, err := Pair(hostPairArtifacts(t, true, true)); err != nil {
		t.Fatal("genuinely different independently bound host inputs were conflated", err)
	}
	hosts := hostPairArtifacts(t, false, true)
	for host, value := range hosts {
		value.Manifest.Outputs[0].HostInput = nil
		value.Manifest.Outputs[0].Expect.HostImport = nil
		hosts[host] = value
	}
	if _, err := Pair(hosts); err == nil {
		t.Fatal("ordinary plaintext mismatch escaped its original equality check")
	}
}

func TestHostImportPairRejectsMissingOrMismatchedInventoryBindings(t *testing.T) {
	for _, failure := range []string{"missing-sidecar", "changed-sidecar", "missing-reference", "different-architecture", "different-go", "different-commit", "different-lock", "different-policy"} {
		t.Run(failure, func(t *testing.T) {
			hosts := hostPairArtifacts(t, true, true)
			value := hosts["windows"]
			sidecar := filepath.Join(value.Dir, value.Manifest.Outputs[0].HostInput.File)
			switch failure {
			case "missing-sidecar":
				if err := os.Remove(sidecar); err != nil {
					t.Fatal(err)
				}
			case "changed-sidecar":
				if err := os.WriteFile(sidecar, []byte("changed original inventory"), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-reference":
				value.Manifest.Outputs[0].HostInput = nil
			case "different-architecture":
				value.Manifest.Arch = "arm64"
			case "different-go":
				value.Manifest.Go = "go1.27.2"
			case "different-commit":
				value.Manifest.Commit = "0123456789012345678901234567890123456789"
			case "different-lock":
				value.Manifest.Lock = "another lock"
			case "different-policy":
				value.Manifest.Outputs[0].Expect.HostImport.ClockNS++
			}
			hosts["windows"] = value
			if _, err := Pair(hosts); err == nil {
				t.Fatal("unbound foreign-host output escaped pairing")
			}
		})
	}
}

func TestHostImportRoutesCannotDisappearFromEveryProducer(t *testing.T) {
	cases := map[string]corpus.Case{}
	var pairs []Paired
	for _, profile := range []string{"apfs", "apfsx", "hfsplus", "hfsx"} {
		source := schema.CaseRef{Producer: 26, Recipe: "workspace-edits", Profile: profile, Stage: "before"}
		cases[CaseKey(source)] = corpus.Case{Observation: &schema.Observation{}}
		for _, route := range []string{"session-pack", "image-copy"} {
			out := hostPairArtifacts(t, true, true)["darwin"].Manifest.Outputs[0]
			out.Source = source
			out.Name, out.File = hostImportOutputName(source, route), hostImportOutputName(source, route)
			out.Expect.HostImport.Route = route
			if route == "image-copy" {
				out.Operation, out.Expect.HostImport.Destination = "edit", "/Fixture/HostImport"
			}
			pairs = append(pairs, Paired{Name: out.Name, Output: out, ByHost: map[string]schema.Output{"darwin": out, "linux": out, "windows": out}})
		}
	}
	if err := requireHostImportOutputs(pairs, cases, 26); err != nil {
		t.Fatal(err)
	}
	for index := range pairs {
		remaining := append([]Paired(nil), pairs[:index]...)
		remaining = append(remaining, pairs[index+1:]...)
		if err := requireHostImportOutputs(remaining, cases, 26); err == nil {
			t.Fatal("every host omitted a route without failing completeness", pairs[index].Name)
		}
	}
	if err := requireHostImportOutputs(append(append([]Paired(nil), pairs...), pairs[0]), cases, 26); err == nil {
		t.Fatal("duplicated host-import route escaped completeness")
	}
}

func TestHostImportNativeContinuationRefusesMissingHostCopies(t *testing.T) {
	verifier := &Verifier{}
	for _, hosts := range []map[string]schema.Output{nil, {"darwin": {}}, {"darwin": {}, "linux": {}}, {"darwin": {}, "linux": {}, "unknown": {}}} {
		if err := verifier.hostImportContinuations(context.Background(), Paired{ByHost: hosts}); err == nil {
			t.Fatal("native continuation accepted an incomplete portable-host inventory")
		}
	}
}
