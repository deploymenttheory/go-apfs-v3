package receipt

import (
	"bytes"
	"encoding/json"
	"io"
	"slices"
	"strings"
	"testing"
)

func referencePlan() Plan {
	cases := []Case{
		{Family: "geometry", Test: "TestGeometry/macos-15/apfs/UDRO", Corpus: "geometry", Manifest: "macos-15/manifest.json", NativeCase: "cases/apfs", Source: 15, Variant: "UDRO", Outputs: []string{"outputs/UDRO.dmg"}},
		{Family: "geometry", Test: "TestGeometry/macos-15/apfs/UDZO", Corpus: "geometry", Manifest: "macos-15/manifest.json", NativeCase: "cases/apfs", Source: 15, Variant: "UDZO", Outputs: []string{"outputs/UDZO.dmg"}},
	}
	return Plan{Schema: Schema, Stage: "replay", Contract: strings.Repeat("1", 64), Production: strings.Repeat("2", 64), Inputs: []Input{{"geometry", strings.Repeat("3", 64), "retained"}}, Outputs: []File{}, Environment: Environment{OS: "linux", Architecture: "amd64", Version: "test-kernel", Build: "test-build", Toolchain: "go test-toolchain", Flags: []string{"-count=1"}, Tools: []File{}}, Cases: cases, RequiredRuns: RequiredRuns(cases, []string{"TestGeometry", "TestGeometry/macos-15/apfs"})}
}

func referenceReceipt(t *testing.T, p Plan) Receipt {
	t.Helper()
	fingerprint, err := p.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	verdicts := []Verdict{}
	for _, c := range p.Cases {
		verdicts = append(verdicts, Verdict{c, "pass"})
	}
	return Receipt{Schema: Schema, Plan: p, Fingerprint: fingerprint, Origin: Origin{strings.Repeat("a", 40), "1234", "1", "replay"}, Verdicts: verdicts, Outputs: []File{{"outputs/UDRO.dmg", 16, strings.Repeat("4", 64)}, {"outputs/UDZO.dmg", 8, strings.Repeat("5", 64)}}, Events: File{"events.jsonl", 100, strings.Repeat("6", 64)}}
}

func cloneReceipt(t *testing.T, r Receipt) Receipt {
	t.Helper()
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	var result Receipt
	if err = json.Unmarshal(b, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestCompletionRejectsCoverageAndIdentityHoles(t *testing.T) {
	for _, kind := range []string{"valid", "missing-case", "duplicate-case", "skipped-case", "failed-case", "wrong-source", "wrong-host", "wrong-race", "wrong-input", "wrong-production", "wrong-contract", "wrong-origin", "missing-output", "duplicate-output", "bad-output-digest", "missing-events", "unexpected-receipt", "duplicate-receipt", "empty-campaign"} {
		t.Run(kind, func(t *testing.T) {
			plan := referencePlan()
			original := referenceReceipt(t, plan)
			record := cloneReceipt(t, original)
			expected := []Expected{{plan, original.Origin}}
			records := []Receipt{record}
			switch kind {
			case "missing-case":
				record.Verdicts = record.Verdicts[:1]
			case "duplicate-case":
				record.Verdicts[1] = record.Verdicts[0]
			case "skipped-case":
				record.Verdicts[0].Status = "skip"
			case "failed-case":
				record.Verdicts[0].Status = "fail"
			case "wrong-source":
				record.Plan.Cases[0].Source = 26
			case "wrong-host":
				record.Plan.Environment.OS = "windows"
			case "wrong-race":
				record.Plan.Environment.Race = true
			case "wrong-input":
				record.Plan.Inputs[0].TreeSHA256 = strings.Repeat("f", 64)
			case "wrong-production":
				record.Plan.Production = strings.Repeat("e", 64)
			case "wrong-contract":
				record.Plan.Contract = strings.Repeat("e", 64)
			case "wrong-origin":
				record.Origin.Run = "different-run"
			case "missing-output":
				record.Outputs = record.Outputs[:1]
			case "duplicate-output":
				record.Outputs[1] = record.Outputs[0]
			case "bad-output-digest":
				record.Outputs[0].SHA256 = "not-a-digest"
			case "missing-events":
				record.Events.Bytes = 0
			case "unexpected-receipt":
				record.Fingerprint = strings.Repeat("9", 64)
			case "duplicate-receipt":
				records = append(records, record)
			case "empty-campaign":
				expected = nil
				records = nil
			}
			if kind != "duplicate-receipt" && kind != "empty-campaign" {
				records[0] = record
			}
			err := Complete(expected, records)
			if (err == nil) != (kind == "valid") {
				t.Fatalf("%s admission: %v", kind, err)
			}
		})
	}
}

func executionEvents(p Plan) []Event {
	result := []Event{{Action: "start", Package: AcceptancePackage}}
	for _, name := range p.RequiredRuns {
		result = append(result, Event{Action: "run", Package: AcceptancePackage, Test: name})
	}
	for _, name := range slices.Backward(p.RequiredRuns) {
		result = append(result, Event{Action: "pass", Package: AcceptancePackage, Test: name})
	}
	return append(result, Event{Action: "pass", Package: AcceptancePackage})
}

func TestExecutionEventsRequireEveryDeclaredRun(t *testing.T) {
	for _, kind := range []string{"valid", "missing-variant", "pass-without-run", "duplicate-run", "duplicate-pass", "skip", "fail", "unplanned-child", "wrong-package", "truncated", "empty", "duplicate-json", "malformed-json", "build-failure", "diagnostic-output"} {
		t.Run(kind, func(t *testing.T) {
			plan := referencePlan()
			events := executionEvents(plan)
			switch kind {
			case "missing-variant":
				events = slices.DeleteFunc(events, func(e Event) bool { return e.Test == plan.Cases[1].Test })
			case "pass-without-run":
				events = slices.DeleteFunc(events, func(e Event) bool { return e.Test == plan.Cases[0].Test && e.Action == "run" })
			case "duplicate-run":
				events = slices.Insert(events, 2, events[1])
			case "duplicate-pass":
				events = slices.Insert(events, len(events)-1, events[len(events)-2])
			case "skip":
				events[len(events)-2].Action = "skip"
			case "fail":
				events[len(events)-2].Action = "fail"
			case "unplanned-child":
				events = slices.Insert(events, 2, Event{Action: "run", Package: AcceptancePackage, Test: "TestGeometry/undeclared"})
			case "wrong-package":
				for n := range events {
					events[n].Package = "unrelated"
				}
			case "truncated":
				events = events[:len(events)-1]
			case "empty":
				events = nil
			case "build-failure":
				events = []Event{{Action: "build-fail", Package: AcceptancePackage}}
			case "diagnostic-output":
				events = slices.Insert(events, 2, Event{Action: "output", Package: AcceptancePackage, Test: events[1].Test, Output: "diagnostic survives\n"})
			}
			var stream, output bytes.Buffer
			encoder := json.NewEncoder(&stream)
			for _, event := range events {
				if err := encoder.Encode(event); err != nil {
					t.Fatal(err)
				}
			}
			if kind == "duplicate-json" {
				stream.Reset()
				stream.WriteString("{\"Action\":\"fail\",\"Action\":\"pass\"}\n")
			}
			if kind == "malformed-json" {
				stream.Reset()
				stream.WriteString("not json\n")
			}
			verdicts, err := CheckEvents(&stream, plan, nil, &output)
			valid := kind == "valid" || kind == "diagnostic-output"
			if (err == nil) != valid {
				t.Fatalf("%s: %v", kind, err)
			}
			if valid && len(verdicts) != 2 {
				t.Fatal("variant evidence lost")
			}
			if kind == "diagnostic-output" && !strings.Contains(output.String(), "diagnostic survives") {
				t.Fatal("execution output lost")
			}
		})
	}
}

func TestSlashesDoNotInventParentExecutions(t *testing.T) {
	plan := referencePlan()
	if slices.Contains(plan.RequiredRuns, "TestGeometry/macos-15") {
		t.Fatal("invented a t.Run for a slash-containing name")
	}
	if _, err := CheckEvents(strings.NewReader(""), plan, map[string]bool{"TestGeometry": true}, io.Discard); err == nil {
		t.Fatal("optional execution substituted for required evidence")
	}
}

func TestSelectorPreservesGoSubtestSyntax(t *testing.T) {
	for _, test := range []struct {
		pattern, name string
		partial, want bool
	}{
		{"^TestA$/^macos-15$/^(apfs|hfs)$", "TestA/macos-15/apfs/UDRO", false, true},
		{"^TestA$/^macos-15$/^(apfs|hfs)$", "TestA/macos-26/apfs", false, false},
		{"^TestA$/macos-15/UDRO", "TestA", true, true},
		{"^TestA$/macos-15/UDRO", "TestA", false, false},
		{"^TestA$/first|^TestB$/second", "TestB/second", false, true},
		{"^TestA$/first|^TestB$/second", "TestA/second", false, false},
		{"^TestA$/a[/]b", "TestA/a/b", false, false},
		{"^TestA$/^(apfs|hfs)(/|$)", "TestA/apfs", false, true},
	} {
		selector, err := ParseSelector(test.pattern)
		if err != nil {
			t.Fatal(err)
		}
		if got := selector.Match(test.name, test.partial); got != test.want {
			t.Fatalf("%q on %q: %v", test.pattern, test.name, got)
		}
	}
}

func TestStageFingerprintsDoNotInheritResults(t *testing.T) {
	plan := referencePlan()
	replayID, err := plan.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	plan.Stage = "apple-verification"
	plan.Environment.OS = "darwin"
	plan.Environment.Version = "27.0.1"
	plan.Environment.Tools = []File{{"fsck_apfs", 16, strings.Repeat("a", 64)}}
	plan.Outputs = []File{{"UDRO.dmg", 16, strings.Repeat("4", 64)}}
	verifyID, err := plan.Fingerprint()
	if err != nil {
		t.Fatal(err)
	}
	if verifyID == replayID {
		t.Fatal("stage domains conflated")
	}
	plan.Outputs[0].SHA256 = strings.Repeat("7", 64)
	different, err := plan.Fingerprint()
	if err != nil || different == verifyID {
		t.Fatal("changed output inherited native proof", err)
	}
	plan.Stage = "capture"
	plan.Production = ""
	captureID, err := plan.Fingerprint()
	if err != nil || captureID == different {
		t.Fatal("independent capture fingerprint depends on replay", err)
	}
}

func TestRequiredExecutionTakesPrecedenceOverOptionalEntrypoint(t *testing.T) {
	plan := referencePlan()
	var stream bytes.Buffer
	encoder := json.NewEncoder(&stream)
	for _, event := range executionEvents(plan) {
		if err := encoder.Encode(event); err != nil {
			t.Fatal(err)
		}
	}
	optional := map[string]bool{plan.RequiredRuns[0]: true}
	if _, err := CheckEvents(&stream, plan, optional, io.Discard); err != nil {
		t.Fatal("required parent ignored as an optional inputless invocation", err)
	}
}
