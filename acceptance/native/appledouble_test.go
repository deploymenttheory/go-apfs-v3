package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// Hand-built wire evidence is independent of the product writer. Native
// acceptance uses the retained Apple exports, never these synthetic values.
func appleDoubleEvidence() []byte {
	names := []string{"org.test", "org.empty", "com.apple.acl.text"}
	values := [][]byte{[]byte("first"), {}, []byte("opaque")}
	start := 120
	for _, name := range names {
		start += (12 + len(name) + 3) &^ 3
	}
	total := start + 11
	b := make([]byte, total+4)
	be := binary.BigEndian
	be.PutUint32(b, 0x00051607)
	be.PutUint32(b[4:], 0x00020000)
	be.PutUint16(b[24:], 2)
	be.PutUint32(b[26:], 9)
	be.PutUint32(b[30:], 50)
	be.PutUint32(b[34:], uint32(total-50))
	be.PutUint32(b[38:], 2)
	be.PutUint32(b[42:], uint32(total))
	be.PutUint32(b[46:], 4)
	copy(b[50:82], []byte("TEXTttxt"))
	copy(b[84:88], []byte("ATTR"))
	be.PutUint32(b[88:], 23)
	be.PutUint32(b[92:], uint32(total))
	be.PutUint32(b[96:], uint32(start))
	be.PutUint32(b[100:], 11)
	be.PutUint16(b[116:], 7)
	be.PutUint16(b[118:], 3)
	cursor, data := 120, start
	for i, name := range names {
		be.PutUint32(b[cursor:], uint32(data))
		be.PutUint32(b[cursor+4:], uint32(len(values[i])))
		be.PutUint16(b[cursor+8:], uint16(i+1))
		b[cursor+10] = byte(len(name) + 1)
		copy(b[cursor+11:], name)
		copy(b[data:], values[i])
		data += len(values[i])
		cursor += (12 + len(name) + 3) &^ 3
	}
	copy(b[total:], []byte("fork"))
	return b
}

func TestAppleDoubleReferenceReadsEverySerializedValue(t *testing.T) {
	b := appleDoubleEvidence()
	r, err := ReadAppleDouble(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	if r.Flags != 7 || r.DebugTag != 23 || string(r.FinderInfo[:8]) != "TEXTttxt" || len(r.Attributes) != 3 || r.Attributes[1].Name != "org.empty" || r.Attributes[1].Bytes != 0 || r.Attributes[1].Flags != 2 {
		t.Fatal(r)
	}
	sum := sha256.Sum256([]byte("fork"))
	if r.Resource != (AppleDoubleValue{4, fmt.Sprintf("%x", sum)}) {
		t.Fatal(r.Resource)
	}
	for _, tc := range []struct {
		name   string
		mutate func([]byte)
	}{
		{"FinderInfo", func(b []byte) { b[50]++ }},
		{"resource fork", func(b []byte) { b[len(b)-1]++ }},
		{"attribute value", func(b []byte) { b[len(b)-15]++ }},
		{"empty attribute flags", func(b []byte) { b[148]++ }},
		{"container flags", func(b []byte) { b[117]++ }},
		{"debug tag", func(b []byte) { b[91]++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := bytes.Clone(b)
			tc.mutate(changed)
			got, err := ReadAppleDouble(bytes.NewReader(changed), int64(len(changed)))
			if err != nil {
				t.Fatal(err)
			}
			if len(CompareAppleDouble(got, r)) == 0 {
				t.Fatal("altered serialized metadata escaped verdict")
			}
		})
	}
}

func TestAppleDoubleReferenceRejectsDamagedRanges(t *testing.T) {
	be := binary.BigEndian
	for _, tc := range []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"truncated", func(b []byte) []byte { return b[:70] }},
		{"wrong magic", func(b []byte) []byte { b[0]++; return b }},
		{"missing entry", func(b []byte) []byte { be.PutUint32(b[38:], 9); return b }},
		{"fork beyond source", func(b []byte) []byte { be.PutUint32(b[42:], 0xffffffff); return b }},
		{"overlapping entries", func(b []byte) []byte { be.PutUint32(b[42:], 82); return b }},
		{"bad ATTR data", func(b []byte) []byte { be.PutUint32(b[100:], 999); return b }},
		{"oversized header", func(b []byte) []byte { be.PutUint32(b[96:], 0xffffffff); return b }},
		{"too many records", func(b []byte) []byte { be.PutUint16(b[118:], 65535); return b }},
		{"unterminated name", func(b []byte) []byte { b[139] = 1; return b }},
		{"value outside data", func(b []byte) []byte { be.PutUint32(b[120:], 1); return b }},
		{"overlapping values", func(b []byte) []byte { be.PutUint32(b[164:], be.Uint32(b[120:])); return b }},
		{"reserved ATTR fields", func(b []byte) []byte { b[104] = 1; return b }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.mutate(appleDoubleEvidence())
			if _, err := ReadAppleDouble(bytes.NewReader(b), int64(len(b))); err == nil {
				t.Fatal("damaged independent evidence accepted")
			}
		})
	}
}

type appleDoubleCommander func(fixture.Command) fixture.Result

func (f appleDoubleCommander) Run(_ context.Context, c fixture.Command) fixture.Result { return f(c) }

func TestAppleDoubleVerdictRequiresNativeUnpackAndRestoredMetadata(t *testing.T) {
	for _, scenario := range []string{"valid", "native refusal", "no-op control", "changed metadata", "changed data", "corrupt nonprimary bytes"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			b := appleDoubleEvidence()
			for _, name := range []string{"control.bin", "output.bin"} {
				if err := os.WriteFile(filepath.Join(root, name), b, 0644); err != nil {
					t.Fatal(err)
				}
			}
			sum, _ := schema.FileDigest(filepath.Join(root, "control.bin"))
			ref := schema.CaseRef{Producer: 15, Recipe: "file-corpus", Profile: "apfs", Stage: "final"}
			view := schema.View{AppleDouble: []schema.AppleDoubleExport{{Path: "Fixture/metadata", File: "control.bin", SHA256: sum}}}
			k := corpus.Case{Producer: 15, Recipe: ref.Recipe, Profile: ref.Profile, Stage: ref.Stage, Dir: root, Observation: &schema.Observation{Views: []schema.View{view}}}
			o := schema.Output{Name: "metadata", File: "output.bin", Operation: "appledouble", Format: "appledouble", Source: ref, SHA256: sum, Expect: schema.Expectation{AppleDouble: &schema.AppleDoubleExpectation{Path: "Fixture/metadata"}}}
			p := Paired{Name: o.Name, Output: o, ByHost: map[string]schema.Output{"darwin": o}, Dirs: map[string]string{"darwin": root}, Primary: "darwin"}
			if scenario == "corrupt nonprimary bytes" {
				dir := t.TempDir()
				if err := os.WriteFile(filepath.Join(dir, "output.bin"), []byte("wrong"), 0644); err != nil {
					t.Fatal(err)
				}
				p.ByHost["windows"], p.Dirs["windows"] = o, dir
			}
			work := filepath.Join(root, "native", "appledouble", sanitize(p.Name))
			vol := fixture.NewMemoryVolume(work)
			calls := 0
			c := appleDoubleCommander(func(cmd fixture.Command) fixture.Result {
				calls++
				if scenario == "native refusal" {
					return fixture.Result{Status: 1, Stderr: []byte("native unpack refused")}
				}
				if scenario == "no-op control" {
					return fixture.Result{}
				}
				dst := cmd.Argv[2]
				attrs := map[string][]byte{"com.apple.FinderInfo": b[50:82], "com.apple.ResourceFork": []byte("fork"), "org.test": []byte("first"), "memory.acl": []byte("native ACL")}
				if scenario == "changed metadata" && calls == 2 {
					attrs["org.test"] = []byte("wrong")
				}
				if scenario == "changed data" && calls == 2 {
					if err := vol.WriteFile(dst, []byte("wrong data"), false); err != nil {
						t.Fatal(err)
					}
				}
				for name, value := range attrs {
					if err := vol.Setxattr(dst, name, value, ""); err != nil {
						t.Fatal(err)
					}
				}
				return fixture.Result{}
			})
			v := &Verifier{Cases: map[string]corpus.Case{CaseKey(ref): k}, Work: filepath.Join(root, "native"), Vol: vol, C: c, AppleDoubleUnpack: "/fake/appledouble-unpack"}
			diffs, err := v.VerifyOutput(context.Background(), p)
			if scenario == "valid" {
				if err != nil || len(diffs) != 0 || calls != 2 {
					t.Fatal(diffs, err, calls)
				}
			} else if err == nil && len(diffs) == 0 {
				t.Fatal("incorrect native unpack passed", calls)
			}
		})
	}
}

func TestMissingAppleDoubleOutputsCannotDisappearFromNativeVerification(t *testing.T) {
	ref := schema.CaseRef{Producer: 15, Recipe: "file-corpus", Profile: "apfs", Stage: "final"}
	k := corpus.Case{Producer: 15, Recipe: ref.Recipe, Profile: ref.Profile, Stage: ref.Stage, Observation: &schema.Observation{Views: []schema.View{{AppleDouble: []schema.AppleDoubleExport{{Path: "Fixture/metadata"}}}}}}
	cases := map[string]corpus.Case{CaseKey(ref): k}
	if err := requireAppleDoubleOutputs(nil, cases, 15); err == nil {
		t.Fatal("omitted AppleDouble outputs accepted")
	}
	o := schema.Output{Source: ref, Operation: "appledouble", Format: "appledouble", Expect: schema.Expectation{AppleDouble: &schema.AppleDoubleExpectation{Path: "Fixture/metadata"}}}
	if err := requireAppleDoubleOutputs([]Paired{{Output: o}}, cases, 15); err != nil {
		t.Fatal(err)
	}
	o.Operation = "repack"
	if err := requireAppleDoubleOutputs([]Paired{{Output: o}}, cases, 15); err == nil {
		t.Fatal("repack impersonated the codec")
	}
	o.Operation = "appledouble"
	if err := requireAppleDoubleOutputs([]Paired{{Output: o}, {Output: o}}, cases, 15); err == nil {
		t.Fatal("duplicate codec outputs accepted")
	}
	changed := o
	changed.Expect.AppleDouble = &schema.AppleDoubleExpectation{Path: "Fixture/other"}
	hosts := map[string]HostOutputs{"darwin": {Manifest: schema.Outputs{Outputs: []schema.Output{o}}}, "windows": {Manifest: schema.Outputs{Outputs: []schema.Output{changed}}}}
	if _, err := Pair(hosts); err == nil || !strings.Contains(err.Error(), "expectation") {
		t.Fatal("different native controls paired", err)
	}
	changed = o
	changed.SHA256 = "changed"
	hosts["windows"] = HostOutputs{Manifest: schema.Outputs{Outputs: []schema.Output{changed}}}
	if _, err := Pair(hosts); err == nil {
		t.Fatal("different canonical encodings paired")
	}
}
