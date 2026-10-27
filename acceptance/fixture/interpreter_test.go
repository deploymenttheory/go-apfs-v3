package fixture

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func testRecipe() *schema.Recipe {
	return &schema.Recipe{
		Schema: 1, Name: "file-corpus", Purpose: "test", Profiles: []string{"apfs"},
		Image:     schema.ImageSpec{Create: "hdiutil", Size: "64m", Layout: "GPTSPUD", Output: "UDZO"},
		Passwords: map[string]string{"image": "pw"},
		Stages: []schema.Stage{
			{Name: "before", Steps: []schema.Step{
				{FS: &schema.FSStep{Op: "mkdir", Path: "$MOUNT/Fixture"}},
				{FS: &schema.FSStep{Op: "write", Path: "$MOUNT/Fixture/data", Content: "hello\n"}},
				{FS: &schema.FSStep{Op: "setxattr", Path: "$MOUNT/Fixture/data", Name: "org.go-apfs.a", Content: "x"}},
				{FS: &schema.FSStep{Op: "link", Path: "$MOUNT/Fixture/data", Target: "$MOUNT/Fixture/alias"}},
				{FS: &schema.FSStep{Op: "symlink", Path: "$MOUNT/Fixture/link", Target: "data"}},
				{FS: &schema.FSStep{Op: "write", Path: "$MOUNT/Fixture/pattern", Pattern: "sequence", Label: "lbl", Bytes: 600}},
				{Tool: &schema.ToolStep{Program: "ln", Args: []string{"$MOUNT/Fixture/data", "$MOUNT/Fixture/third"}, Expect: "0"}},
				{FS: &schema.FSStep{Op: "write", Path: "$MOUNT/Fixture/data", Content: "x", Option: "create", Expect: "EEXIST"}},
				{FS: &schema.FSStep{Op: "mkdir", Path: "$MOUNT/Fixture/guards"}},
				{FS: &schema.FSStep{Op: "fill", Path: "$MOUNT/Fixture/guards", Bytes: 1024, Count: 1000, Expect: "ENOSPC"}},
				{FS: &schema.FSStep{Op: "thin", Path: "$MOUNT/Fixture/guards"}},
			}, Observe: schema.ObserveSpec{Checks: []string{"verify", "fsck"}, Lookups: []schema.Lookup{{Dir: "Fixture", Query: "data", Expect: "found"}, {Dir: "Fixture", Query: "absent", Expect: "absent"}}, Extents: []string{"Fixture/pattern"}, Samples: 4}},
			{Name: "after", Steps: []schema.Step{
				{FS: &schema.FSStep{Op: "rename", Path: "$MOUNT/Fixture/data", Target: "$MOUNT/Fixture/renamed"}},
				{FS: &schema.FSStep{Op: "unlink", Path: "$MOUNT/Fixture/missing", Expect: "ENOENT"}},
			}},
			{Name: "branch", From: "before", Steps: []schema.Step{
				{FS: &schema.FSStep{Op: "chmod", Path: "$MOUNT/Fixture/data", Mode: 0o600}},
			}},
		},
		Derive: []schema.Derivation{{Name: "aes", From: "after", Steps: []schema.ToolStep{{Program: "hdiutil", Args: []string{"convert", "$IMAGE", "-format", "UDZO", "-encryption", "AES-256", "-stdinpass", "-o", "$OUT"}, Stdin: []string{"image"}, Expect: "0"}}}},
	}
}

func TestCaptureRunsStagesFromBaselinesAndRecordsObservations(t *testing.T) {
	r := testRecipe()
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	work, out := t.TempDir(), t.TempDir()
	vol := NewMemoryVolume("/")
	vol.Capacity = 64 << 10
	disk := newFakeDisk(vol)
	cmd := &fakeCommander{}
	// The fake hdiutil convert in derivations must create $OUT.
	cmd.results = map[string]Result{}
	profile, _ := schema.LookupProfile("apfs")
	c := &Capture{Recipe: r, Profile: profile, Disk: disk, Vol: vol, C: &derivingCommander{fakeCommander: cmd, vol: vol}, Work: work, Out: out, Payloads: t.TempDir(), Producer: schema.Producer{Major: 27}}
	if err := c.Run(context.Background()); err != nil {
		t.Fatalf("run: %v\ncalls:\n%s", err, strings.Join(disk.calls, "\n"))
	}
	baselines, err := os.ReadDir(filepath.Join(work, "baseline"))
	if err != nil || len(baselines) != 1 || baselines[0].Name() != "apfs.before" {
		t.Fatalf("only the referenced before stage needs a writable baseline: got %v, error %v", baselines, err)
	}
	for _, name := range []string{"apfs.before.observation.json", "apfs.after.observation.json", "apfs.branch.observation.json", "apfs.before.dmg", "apfs.after.dmg", "apfs.branch.dmg", "apfs.aes.dmg"} {
		if _, err := os.Stat(filepath.Join(out, name)); err != nil {
			t.Errorf("missing %s", name)
		}
	}
	var before schema.Observation
	data, err := os.ReadFile(filepath.Join(out, "apfs.before.observation.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.DecodeStrict(data, &before); err != nil {
		t.Fatal(err)
	}
	paths := map[string]schema.Entry{}
	for _, e := range before.Views[0].Entries {
		paths[e.Path] = e
	}
	if paths["Fixture/data"].Links != 3 || paths["Fixture/alias"].ID != paths["Fixture/data"].ID {
		t.Errorf("hard links not observed: %+v", paths["Fixture/data"])
	}
	if paths["Fixture/link"].Kind != "symlink" || paths["Fixture/link"].Target != "64617461" {
		t.Errorf("symlink not observed: %+v", paths["Fixture/link"])
	}
	if len(paths["Fixture/data"].Xattrs) != 1 || paths["Fixture/data"].Xattrs[0].Name != "org.go-apfs.a" {
		t.Errorf("xattr not observed: %+v", paths["Fixture/data"].Xattrs)
	}
	if paths["Fixture/pattern"].Extents == nil {
		t.Errorf("extents not recorded for the requested path")
	}
	guards := 0
	for p := range paths {
		if strings.HasPrefix(p, "Fixture/guards/") {
			guards++
		}
	}
	if guards == 0 {
		t.Error("fill wrote nothing")
	}
	if a := before.Volumes[0].APFS; a == nil || a.ReserveBytes != 33554432 || a.QuotaBytes != 67108864 {
		t.Errorf("reserve and quota not taken from diskutil apfs list: %+v", before.Volumes[0].APFS)
	}
	if before.Checks.SelectedXID != 42 || before.Checks.Verify == nil || len(before.Checks.Fsck) != 1 {
		t.Errorf("checks not recorded: %+v", before.Checks)
	}
	if len(before.Views[0].Lookups) != 2 || before.Views[0].Lookups[1].Result != "ENOENT" {
		t.Errorf("lookups not recorded: %+v", before.Views[0].Lookups)
	}
	var found bool
	for _, cmdEntry := range before.Commands {
		if cmdEntry.Label == "fill" && cmdEntry.Errno == "ENOSPC" {
			found = true
		}
		if strings.HasPrefix(cmdEntry.Label, "write") && cmdEntry.Errno == "EEXIST" {
			found = found && true
		}
	}
	if !found {
		t.Error("fill outcome not in transcript")
	}
	var branch schema.Observation
	data, _ = os.ReadFile(filepath.Join(out, "apfs.branch.observation.json"))
	_ = json.Unmarshal(data, &branch)
	for _, e := range branch.Views[0].Entries {
		if e.Path == "Fixture/renamed" {
			t.Error("branch stage started from 'after' instead of its declared 'before' baseline")
		}
		if e.Path == "Fixture/data" && e.Mode != 0o600 {
			t.Errorf("branch chmod not applied: %o", e.Mode)
		}
	}
}

// derivingCommander makes the fake hdiutil convert write its -o target so
// derivations can be checked without hdiutil.
type derivingCommander struct {
	*fakeCommander
	vol *MemoryVolume
}

func (d *derivingCommander) Run(ctx context.Context, cmd Command) Result {
	r := d.fakeCommander.Run(ctx, cmd)
	if cmd.Argv[0] == "ln" && len(cmd.Argv) == 3 && d.vol != nil {
		if err := d.vol.Link(cmd.Argv[1], cmd.Argv[2]); err != nil {
			return Result{Status: 1, Stderr: []byte(err.Error())}
		}
	}
	if cmd.Argv[0] == "hdiutil" && len(cmd.Argv) > 1 && cmd.Argv[1] == "convert" {
		for i, a := range cmd.Argv {
			if a == "-o" && i+1 < len(cmd.Argv) {
				_ = os.WriteFile(cmd.Argv[i+1], []byte("derived"), 0o644)
			}
		}
	}
	return r
}

func TestUnexpectedToolStatusStopsTheCapture(t *testing.T) {
	r := testRecipe()
	r.Stages = r.Stages[:1]
	r.Stages[0].Steps = []schema.Step{{Tool: &schema.ToolStep{Program: "codesign", Args: []string{"--verify", "$MOUNT"}, Expect: "0"}}}
	r.Derive = nil
	vol := NewMemoryVolume("/")
	disk := newFakeDisk(vol)
	profile, _ := schema.LookupProfile("apfs")
	c := &Capture{Recipe: r, Profile: profile, Disk: disk, Vol: vol, C: &fakeCommander{fail: map[string]bool{"codesign": true}}, Work: t.TempDir(), Out: t.TempDir(), Payloads: t.TempDir()}
	err := c.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "exit 1") {
		t.Fatalf("expected the failing tool to stop the capture, got %v", err)
	}
	if len(disk.attached) != 0 {
		t.Error("image left attached after failure")
	}
}

func TestGeneratePatterns(t *testing.T) {
	seq := generate("sequence", "", 300)
	if len(seq) != 300 || seq[0] != 0 || seq[255] != 255 || seq[256] != 0 {
		t.Error("sequence pattern wrong")
	}
	labelled := generate("sequence", "ab", 260)
	if string(labelled[256:259]) != "ab\n" {
		t.Errorf("label not appended: %q", labelled[256:260])
	}
	rev := generate("reverse", "", 3)
	if rev[0] != 255 || rev[2] != 253 {
		t.Error("reverse pattern wrong")
	}
	if n, err := parseSize("1536m"); err != nil || n != 1536<<20 {
		t.Errorf("parseSize: %d %v", n, err)
	}
}
