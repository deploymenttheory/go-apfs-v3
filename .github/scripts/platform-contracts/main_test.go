package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func passingEvents(required map[string][]string) []byte {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	for pkg, names := range required {
		_ = encoder.Encode(map[string]string{"Action": "start", "Package": pkg})
		for _, name := range names {
			for _, action := range []string{"run", "pass"} {
				_ = encoder.Encode(map[string]string{"Action": action, "Package": pkg, "Test": name})
			}
		}
		_ = encoder.Encode(map[string]string{"Action": "pass", "Package": pkg})
	}
	return out.Bytes()
}

func TestContractGateRequiresExecutedPassingContractsAndCompletePackages(t *testing.T) {
	if err := validateEvents(passingEvents(helperContracts), 0, helperContracts); err != nil {
		t.Fatal(err)
	}
	required := map[string][]string{"helpers": {"TestIdentity", "TestCleanup"}}
	good := passingEvents(required)
	for _, test := range []struct {
		name string
		raw  []byte
		exit int
	}{
		{"missing test despite successful package", passingEvents(map[string][]string{"helpers": {"TestIdentity"}}), 0},
		{"missing package", nil, 0},
		{"exit failure despite passing events", good, 1},
		{"test failure followed by package pass", bytes.Replace(good, []byte(`"Action":"pass"`), []byte(`"Action":"fail"`), 1), 0},
		{"skipped required contract", bytes.Replace(good, []byte(`"Action":"pass"`), []byte(`"Action":"skip"`), 1), 0},
		{"cached pass without execution", bytes.ReplaceAll(good, []byte(`"Action":"run"`), []byte(`"Action":"output"`)), 0},
		{"truncated JSON", append(bytes.Clone(good), []byte(`{"Action":`)...), 0},
		{"unfinished package", bytes.ReplaceAll(good, []byte(`{"Action":"pass","Package":"helpers"}`), nil), 0},
		{"duplicate execution", append(bytes.Clone(good), good...), 0},
		{"package panic", append(bytes.Clone(good), []byte("{\"Action\":\"fail\",\"Package\":\"helpers\",\"Output\":\"panic\"}\n")...), 0},
		{"compile failure", []byte("{\"Action\":\"build-fail\",\"Package\":\"helpers\"}\n"), 0},
		{"unfinished additional package", append(bytes.Clone(good), []byte("{\"Action\":\"start\",\"Package\":\"additional\"}\n")...), 0},
		{"unfinished additional test", append(bytes.Clone(good), []byte("{\"Action\":\"run\",\"Package\":\"helpers\",\"Test\":\"TestAdditional\"}\n")...), 0},
		{"skipped contract descendant despite parent pass", append(bytes.Clone(good), []byte("{\"Action\":\"skip\",\"Package\":\"helpers\",\"Test\":\"TestIdentity/windows\"}\n")...), 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := validateEvents(test.raw, test.exit, required); err == nil {
				t.Fatal("unqualified contract execution was accepted")
			}
		})
	}
}

func nativeControl(t *testing.T) (nativePacket, string, provenance) {
	t.Helper()
	dir := t.TempDir()
	p := provenance{Commit: strings.Repeat("a", 40), RunID: "1234", RunAttempt: "2", GOOS: "darwin", GOARCH: "arm64", GoVersion: "test"}
	packet := nativePacket{Schema: 2, Commit: p.Commit, RunID: p.RunID, RunAttempt: p.RunAttempt, KernelVersion: "26.0", OSBuild: "25A", Architecture: p.GOARCH, RawBytes: 2 << 20,
		RawSHA256:      map[string]string{"/private/first/ownership.raw": strings.Repeat("b", 64), "/private/second/ownership.raw": strings.Repeat("c", 64)},
		ToolsSHA256:    map[string]string{"/usr/bin/hdiutil": strings.Repeat("d", 64), "/usr/sbin/ioreg": strings.Repeat("e", 64)},
		SymlinkAliases: map[string]string{"/private/alias.raw": "/private/first/ownership.raw"}}
	for kind, values := range map[string][3]string{
		"positive-first": {"owned", "/private/first/ownership.raw", "/dev/disk6"}, "positive-second": {"owned", "/private/second/ownership.raw", "/dev/disk7"},
		"positive-symlink-alias": {"owned", "/private/alias.raw", "/dev/disk6"},
		"crossed-1":              {"foreign", "/private/first/ownership.raw", "/dev/disk7"}, "crossed-2": {"foreign", "/private/second/ownership.raw", "/dev/disk6"},
		"post-detach-first": {"absent", "/private/first/ownership.raw", "/dev/disk6"}, "post-detach-second": {"absent", "/private/second/ownership.raw", "/dev/disk7"},
	} {
		packet.Claims = append(packet.Claims, nativeClaim{Kind: kind, ExpectedState: values[0], State: values[0], Image: values[1], Device: values[2], Owned: values[0] == "owned", ExpectedOwned: values[0] == "owned"})
	}
	command := nativeCommand{Argv: []string{"/usr/sbin/ioreg", "original-query"}}
	for i, raw := range [][]byte{{0, 0xff, '\r', '\n'}, {}} {
		file := fmt.Sprintf("original-%d.stream", i)
		if err := os.WriteFile(filepath.Join(dir, file), raw, 0o600); err != nil {
			t.Fatal(err)
		}
		proof := evidence(file, raw)
		stream := nativeStream{File: file, Bytes: proof.Bytes, StoredBytes: proof.Bytes, SHA256: proof.SHA256, StoredSHA256: proof.SHA256}
		if i == 0 {
			command.Stdout = stream
		} else {
			command.Stderr = stream
		}
	}
	packet.CommandResults = []nativeCommand{command}
	return packet, dir, p
}

func TestNativeContractGateRequiresThisInvocationAndExactQualifiedRelations(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*nativePacket)
	}{
		{"other checkout", func(p *nativePacket) { p.Commit = strings.Repeat("f", 40) }},
		{"other run", func(p *nativePacket) { p.RunID = "1233" }},
		{"other attempt", func(p *nativePacket) { p.RunAttempt = "1" }},
		{"other kernel", func(p *nativePacket) { p.KernelVersion = "27.0" }},
		{"other architecture", func(p *nativePacket) { p.Architecture = "amd64" }},
		{"old boolean-only packet", func(p *nativePacket) { p.Schema = 1 }},
		{"contract error", func(p *nativePacket) { p.ContractError = "actual adapter failed" }},
		{"retention error", func(p *nativePacket) { p.RetentionError = "original stream lost" }},
		{"missing claim", func(p *nativePacket) { p.Claims = p.Claims[1:] }},
		{"duplicate claim", func(p *nativePacket) { p.Claims[0] = p.Claims[1] }},
		{"unknown state", func(p *nativePacket) { p.Claims[0].State = "unknown" }},
		{"claim error", func(p *nativePacket) { p.Claims[0].Error = "proof failed" }},
		{"missing raw digest", func(p *nativePacket) { clear(p.RawSHA256) }},
		{"missing tool digest", func(p *nativePacket) { delete(p.ToolsSHA256, "/usr/sbin/ioreg") }},
		{"changed crossed binding", func(p *nativePacket) {
			for i := range p.Claims {
				if p.Claims[i].Kind == "crossed-1" {
					p.Claims[i].Device = "/dev/disk6"
				}
			}
		}},
		{"changed alias", func(p *nativePacket) { p.SymlinkAliases["/private/alias.raw"] = "/private/second/ownership.raw" }},
		{"no command originals", func(p *nativePacket) { p.CommandResults = nil }},
		{"failed native command", func(p *nativePacket) { p.CommandResults[0].Status = 1 }},
		{"truncated original stream", func(p *nativePacket) { p.CommandResults[0].Stdout.StoredBytes-- }},
		{"missing stream", func(p *nativePacket) { p.CommandResults[0].Stdout.File = "missing" }},
		{"stream traversal", func(p *nativePacket) { p.CommandResults[0].Stdout.File = "../outside" }},
		{"duplicate stream", func(p *nativePacket) { p.CommandResults[0].Stderr = p.CommandResults[0].Stdout }},
	} {
		t.Run(test.name, func(t *testing.T) {
			packet, dir, provenance := nativeControl(t)
			if err := validateNativePacket(packet, dir, 26, provenance); err != nil {
				t.Fatal("valid original control refused", err)
			}
			test.change(&packet)
			if err := validateNativePacket(packet, dir, 26, provenance); err == nil {
				t.Fatal("unqualified native evidence accepted")
			}
		})
	}
}

func TestNativeContractValidationPreservesBinaryOriginalsAndRequiresOnePacket(t *testing.T) {
	packet, dir, provenance := nativeControl(t)
	data, _ := json.Marshal(packet)
	file := filepath.Join(dir, "ownership-evidence.json")
	if err := os.WriteFile(file, data, 0o600); err != nil {
		t.Fatal(err)
	}
	proof, err := validateNative(dir, 26, provenance)
	if err != nil || proof != evidence(file, data) {
		t.Fatal("original native evidence was not bound", proof, err)
	}
	after, _ := os.ReadFile(file)
	if !bytes.Equal(data, after) {
		t.Fatal("original native packet was rewritten")
	}
	streamFile := filepath.Join(dir, packet.CommandResults[0].Stdout.File)
	if err := os.WriteFile(streamFile, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateNative(dir, 26, provenance); err == nil {
		t.Fatal("changed original binary stream accepted")
	}
	duplicate := filepath.Join(dir, "duplicate")
	if err := os.Mkdir(duplicate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(duplicate, "ownership-evidence.json"), data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := validateNative(dir, 26, provenance); err == nil {
		t.Fatal("ambiguous native invocation accepted")
	}
	if _, err := validateNative(filepath.Join(dir, "missing"), 26, provenance); err == nil {
		t.Fatal("missing original native packet accepted")
	}
}

func TestContractFailureRetainsOriginalEventsAndJoinsReceiptWriteFailure(t *testing.T) {
	head, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_SHA", strings.TrimSpace(string(head)))
	t.Setenv("GITHUB_RUN_ID", "1234")
	t.Setenv("GITHUB_RUN_ATTEMPT", "2")
	dir := t.TempDir()
	file := filepath.Join(dir, "events.jsonl")
	raw := []byte("{\"Action\":\"fail\",\"Package\":\"fixture\"}\n")
	if err := os.WriteFile(file, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	opts := options{events: file, output: filepath.Join(dir, "receipt.json"), testExit: 1}
	if err := run(opts); err == nil {
		t.Fatal("failed contract was accepted")
	}
	var report receipt
	stored, err := os.ReadFile(opts.output)
	if err != nil || json.Unmarshal(stored, &report) != nil || report.Error == "" || report.GOOS != runtime.GOOS || report.Events != evidence(file, raw) {
		t.Fatal("failure provenance and original event digest were not retained", err)
	}
	after, _ := os.ReadFile(file)
	if !reflect.DeepEqual(raw, after) {
		t.Fatal("original failure events changed")
	}
	opts.output = filepath.Join(file, "cannot-write")
	var pathErr *os.PathError
	if err := run(opts); err == nil || !strings.Contains(err.Error(), "contract test command exited 1") || !errors.As(err, &pathErr) || pathErr.Path != opts.output {
		t.Fatal("receipt failure hid the original contract failure", err)
	}
}

func TestContractProvenanceRejectsAnotherCheckoutAndMissingRun(t *testing.T) {
	t.Setenv("GITHUB_SHA", strings.Repeat("f", 40))
	if _, err := currentProvenance(); err == nil {
		t.Fatal("different checkout accepted")
	}
	head, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_SHA", strings.TrimSpace(string(head)))
	t.Setenv("GITHUB_RUN_ID", "")
	t.Setenv("GITHUB_RUN_ATTEMPT", "1")
	if _, err := currentProvenance(); err == nil {
		t.Fatal("missing run accepted")
	}
}

func TestEvidenceBoundsDoNotLabelPartialReadsAsOriginalFileDigests(t *testing.T) {
	file := filepath.Join(t.TempDir(), "original.jsonl")
	original := []byte("original bytes")
	if err := os.WriteFile(file, original, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, proof, err := readEvidence(file, 4); err == nil || proof.File != file || proof.Bytes != 0 || proof.SHA256 != "" {
		t.Fatal("partial read was labelled as the complete original", proof, err)
	}
	after, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(after, original) {
		t.Fatal("oversized original was rewritten", err)
	}
}
