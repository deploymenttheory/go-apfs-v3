package native

import (
	"reflect"
	"slices"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

const editedTestClock int64 = 10_000_000_000

func editedClockEntry(path, kind string, id uint64) schema.Entry {
	return schema.Entry{Path: path, Kind: kind, ID: id, Times: schema.Times{Birth: 1, Modify: 50, Change: 3, Access: 4}}
}

func editedClockStep(op, path string) schema.Step {
	return schema.Step{FS: &schema.FSStep{Op: op, Path: "$MOUNT/" + path}}
}

func TestEditedViewClockProjectionPreservesSourceClocksAndOrderedArchiveEffects(t *testing.T) {
	source := schema.View{Entries: []schema.Entry{editedClockEntry("Fixture", "dir", 1), editedClockEntry("Fixture/file", "file", 2), editedClockEntry("Fixture/alias", "file", 2), editedClockEntry("Fixture/tree", "dir", 3), editedClockEntry("Fixture/tree/nested", "dir", 4), editedClockEntry("Fixture/tree/nested/leaf", "file", 5), editedClockEntry("Fixture/tree/relative", "symlink", 6), editedClockEntry("Fixture/untouched", "file", 7)}}
	before := slices.Clone(source.Entries)
	target := schema.View{Entries: slices.Clone(source.Entries)}
	target.Entries = append(target.Entries, editedClockEntry("Fixture/copied", "dir", 10), editedClockEntry("Fixture/copied/nested", "dir", 11), editedClockEntry("Fixture/copied/nested/renamed", "file", 12), editedClockEntry("Fixture/copied/nested/leaf", "symlink", 13), editedClockEntry("Fixture/copied/relative", "symlink", 14), editedClockEntry("Fixture/third-alias", "file", 2))
	for i := range target.Entries {
		target.Entries[i].Times = schema.Times{Birth: 777, Modify: 777, Change: 777, Access: 777}
	}
	steps := []schema.Step{editedClockStep("write", "Fixture/file"), {Tool: &schema.ToolStep{Program: "cp", Args: []string{"-a", "$MOUNT/Fixture/tree", "$MOUNT/Fixture/copied"}, Expect: "0"}}, editedClockStep("chmod", "Fixture/copied/nested/leaf"), {FS: &schema.FSStep{Op: "rename", Path: "$MOUNT/Fixture/copied/nested/leaf", Target: "$MOUNT/Fixture/copied/nested/renamed"}}, {FS: &schema.FSStep{Op: "symlink", Path: "$MOUNT/Fixture/copied/nested/leaf", Target: "renamed"}}, editedClockStep("setxattr", "Fixture/file"), {FS: &schema.FSStep{Op: "link", Path: "$MOUNT/Fixture/file", Target: "$MOUNT/Fixture/third-alias"}}}
	got, err := ProjectEditedViewClocks(source, target, steps, "apfs", editedTestClock)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]schema.Times{
		"Fixture":                       {Birth: 1, Modify: editedTestClock, Change: editedTestClock, Access: 4},
		"Fixture/file":                  {Birth: 1, Modify: editedTestClock, Change: editedTestClock, Access: 4},
		"Fixture/alias":                 {Birth: 1, Modify: editedTestClock, Change: editedTestClock, Access: 4},
		"Fixture/third-alias":           {Birth: 1, Modify: editedTestClock, Change: editedTestClock, Access: 4},
		"Fixture/copied":                {Birth: 50, Modify: 50, Change: editedTestClock, Access: 4},
		"Fixture/copied/nested":         {Birth: 50, Modify: editedTestClock, Change: editedTestClock, Access: 4},
		"Fixture/copied/nested/renamed": {Birth: 50, Modify: 50, Change: editedTestClock, Access: 4},
		"Fixture/copied/nested/leaf":    {Birth: editedTestClock, Modify: editedTestClock, Change: editedTestClock, Access: editedTestClock},
		"Fixture/copied/relative":       {Birth: 50, Modify: 50, Change: editedTestClock, Access: 4},
	}
	for _, entry := range got.Entries {
		expected, changed := want[entry.Path]
		if !changed {
			expected = schema.Times{Birth: 1, Modify: 50, Change: 3, Access: 4}
		}
		if entry.Times != expected {
			t.Errorf("%s clocks %+v, want %+v", entry.Path, entry.Times, expected)
		}
	}
	if !reflect.DeepEqual(source.Entries, before) || target.Entries[0].Times.Change != 777 {
		t.Fatal("projection mutated independent native observations")
	}
}

func TestEditedViewClockProjectionDistinguishesClonesFromHardlinkAliases(t *testing.T) {
	source := schema.View{Entries: []schema.Entry{editedClockEntry("Fixture", "dir", 1), editedClockEntry("Fixture/clone", "file", 2), editedClockEntry("Fixture/alias", "file", 2), editedClockEntry("Fixture/independent", "file", 3), editedClockEntry("Fixture/remove", "file", 4)}}
	target := schema.View{Entries: []schema.Entry{source.Entries[0], source.Entries[2], source.Entries[3], editedClockEntry("Fixture/reused", "file", 9)}}
	steps := []schema.Step{editedClockStep("write", "Fixture/clone/..namedfork/rsrc"), editedClockStep("truncate", "Fixture/clone"), editedClockStep("chmod", "Fixture/alias"), editedClockStep("unlink", "Fixture/clone"), editedClockStep("unlink", "Fixture/remove"), editedClockStep("write", "Fixture/reused")}
	got, err := ProjectEditedViewClocks(source, target, steps, "apfsx", editedTestClock)
	if err != nil {
		t.Fatal(err)
	}
	if got.Entries[1].Times != (schema.Times{Birth: 1, Modify: editedTestClock, Change: editedTestClock, Access: 4}) || got.Entries[2].Times != source.Entries[3].Times || got.Entries[3].Times != (schema.Times{Birth: editedTestClock, Modify: editedTestClock, Change: editedTestClock, Access: editedTestClock}) {
		t.Fatal("shared inode or independent clone clocks lost", got.Entries)
	}
}

func TestArchiveClockProjectionDoesNotCopySourceBirthTime(t *testing.T) {
	for _, mtime := range []int64{5, 20_000_000_000} {
		source := schema.View{Entries: []schema.Entry{editedClockEntry("Fixture", "dir", 1), editedClockEntry("Fixture/tree", "dir", 2)}}
		source.Entries[1].Times.Modify = mtime
		target := schema.View{Entries: append(slices.Clone(source.Entries), editedClockEntry("Fixture/copy", "dir", 3))}
		got, err := ProjectEditedViewClocks(source, target, []schema.Step{{Tool: &schema.ToolStep{Program: "cp", Args: []string{"-a", "$MOUNT/Fixture/tree", "$MOUNT/Fixture/copy"}, Expect: "0"}}}, "hfsx", editedTestClock)
		if err != nil {
			t.Fatal(err)
		}
		if got.Entries[2].Times.Birth != min(editedTestClock, mtime) || got.Entries[2].Times.Modify != mtime || got.Entries[2].Times.Access != 4 || got.Entries[2].Times.Change != editedTestClock {
			t.Fatal("archive clock policy", got.Entries[2].Times)
		}
	}
}

func TestEditedViewClockProjectionRefusesUnqualifiedInputs(t *testing.T) {
	base := schema.View{Entries: []schema.Entry{editedClockEntry("Fixture", "dir", 1), editedClockEntry("Fixture/file", "file", 2)}}
	for _, tc := range []struct {
		name   string
		change func(*schema.View, *schema.View, *[]schema.Step)
	}{
		{"missing-path", func(_, _ *schema.View, steps *[]schema.Step) {
			*steps = []schema.Step{editedClockStep("chmod", "Fixture/missing")}
		}},
		{"unknown-op", func(_, _ *schema.View, steps *[]schema.Step) {
			*steps = []schema.Step{editedClockStep("clone", "Fixture/file")}
		}},
		{"wrong-tool", func(_, _ *schema.View, steps *[]schema.Step) {
			*steps = []schema.Step{{Tool: &schema.ToolStep{Program: "cp", Args: []string{"-R", "$MOUNT/Fixture", "$MOUNT/copy"}, Expect: "0"}}}
		}},
		{"unknown-host-step", func(_, _ *schema.View, steps *[]schema.Step) {
			*steps = []schema.Step{{Host: &schema.HostStep{Path: "payload"}}}
		}},
		{"rejected-command", func(_, _ *schema.View, steps *[]schema.Step) {
			*steps = []schema.Step{{FS: &schema.FSStep{Op: "write", Path: "$MOUNT/Fixture/file", Expect: "ENOSPC"}}}
		}},
		{"escaping-path", func(_, _ *schema.View, steps *[]schema.Step) {
			*steps = []schema.Step{editedClockStep("write", "../outside")}
		}},
		{"missing-parent", func(_, _ *schema.View, steps *[]schema.Step) {
			*steps = []schema.Step{editedClockStep("write", "Fixture/missing/file")}
		}},
		{"missing-target-entry", func(_, target *schema.View, _ *[]schema.Step) { target.Entries = target.Entries[:1] }},
		{"extra-target-entry", func(_, target *schema.View, _ *[]schema.Step) {
			target.Entries = append(target.Entries, editedClockEntry("Fixture/undeclared", "file", 3))
		}},
		{"duplicate-target", func(_, target *schema.View, _ *[]schema.Step) {
			target.Entries = append(target.Entries, target.Entries[1])
		}},
		{"changed-existing-id", func(_, target *schema.View, _ *[]schema.Step) { target.Entries[1].ID = 88 }},
		{"alias-clock-conflict", func(source, _ *schema.View, _ *[]schema.Step) {
			alias := source.Entries[1]
			alias.Path = "Fixture/alias"
			alias.Times.Access++
			source.Entries = append(source.Entries, alias)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, target := base, base
			source.Entries = slices.Clone(base.Entries)
			target.Entries = slices.Clone(base.Entries)
			var steps []schema.Step
			tc.change(&source, &target, &steps)
			if _, err := ProjectEditedViewClocks(source, target, steps, "apfs", editedTestClock); err == nil {
				t.Fatal("unqualified clock expectation accepted")
			}
		})
	}
}
