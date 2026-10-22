package native

import (
	"encoding/hex"
	"reflect"
	"slices"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func cloneClockTool(flag, from, to, result string) schema.Step {
	return schema.Step{Tool: &schema.ToolStep{Program: "cp", Args: []string{flag, "$MOUNT/" + from, "$MOUNT/" + to}, Expect: result}}
}

func TestCloneCopyClocksModelSameSecondMutationAndDestinationAliases(t *testing.T) {
	for _, profile := range []string{"apfs", "hfsplus"} {
		t.Run(profile, func(t *testing.T) {
			source := schema.View{Entries: []schema.Entry{
				editedClockEntry("Fixture", "dir", 1), editedClockEntry("Fixture/source", "file", 2),
				editedClockEntry("Fixture/overwrite", "file", 3), editedClockEntry("Fixture/old-alias", "file", 3),
				editedClockEntry("Fixture/source-link", "symlink", 4), editedClockEntry("Fixture/target-link", "symlink", 5),
			}}
			source.Entries[4].Target, source.Entries[5].Target = hex.EncodeToString([]byte("source")), hex.EncodeToString([]byte("old-alias"))
			target := schema.View{Entries: slices.Clone(source.Entries)}
			target.Entries[2].ID = 10
			target.Entries[5].ID, target.Entries[5].Kind, target.Entries[5].Target = 11, "file", ""
			target.Entries = append(target.Entries, editedClockEntry("Fixture/followed", "file", 12), editedClockEntry("Fixture/new-alias", "file", 10), editedClockEntry("Fixture/preserved", "file", 13))
			// Target clocks deliberately equal the source clocks, as HFS may
			// capture multiple operations in one second. The operations still
			// require the explicit command clock, never a changed-time mask.
			steps := []schema.Step{
				cloneClockTool("-c", "Fixture/source", "Fixture/overwrite", "0"),
				cloneClockTool("-c", "Fixture/source", "Fixture/target-link", "0"),
				cloneClockTool("-c", "Fixture/source-link", "Fixture/followed", "0"),
				cloneClockTool("-cp", "Fixture/source", "Fixture/preserved", "0"),
				{FS: &schema.FSStep{Op: "link", Path: "$MOUNT/Fixture/overwrite", Target: "$MOUNT/Fixture/new-alias"}},
				editedClockStep("write", "Fixture/overwrite/..namedfork/rsrc"),
			}
			got, err := CloneCopyReference(source, target, steps, profile, editedTestClock)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range got.Entries {
				switch entry.Path {
				case "Fixture/overwrite", "Fixture/new-alias":
					birth, access := editedTestClock, editedTestClock
					if profile == "apfs" {
						birth, access = 1, 4
					}
					if entry.Times != (schema.Times{Birth: birth, Modify: editedTestClock, Change: editedTestClock, Access: access}) {
						t.Fatal("clone alias mutation clocks", entry)
					}
				case "Fixture/old-alias":
					if entry.Times.Change != editedTestClock || entry.Times.Modify != 50 {
						t.Fatal("unlinked old destination alias clocks", entry)
					}
				case "Fixture/preserved":
					birth := int64(50)
					if profile == "apfs" {
						birth = 1
					}
					if entry.Times != (schema.Times{Birth: birth, Modify: 50, Change: editedTestClock, Access: 4}) {
						t.Fatal("clone or ordinary-preserve clocks", entry)
					}
				case "Fixture/source":
					if entry.Times != source.Entries[1].Times {
						t.Fatal("clone changed source clocks", entry)
					}
				}
			}
			if !reflect.DeepEqual(target.Entries[0].Times, source.Entries[0].Times) {
				t.Fatal("projection changed native observation")
			}
		})
	}
}

func TestRecursiveCloneClocksDistinguishCopiedAliasesAndSymlinks(t *testing.T) {
	source := schema.View{Entries: []schema.Entry{editedClockEntry("Fixture", "dir", 1), editedClockEntry("Fixture/tree", "dir", 2), editedClockEntry("Fixture/tree/leaf", "file", 3), editedClockEntry("Fixture/tree/alias", "file", 3), editedClockEntry("Fixture/tree/link", "symlink", 4)}}
	source.Entries[4].Target = hex.EncodeToString([]byte("leaf"))
	target := schema.View{Entries: slices.Clone(source.Entries)}
	for i, name := range []string{"copy", "copy/leaf", "copy/alias", "copy/link"} {
		kind := []string{"dir", "file", "file", "symlink"}[i]
		target.Entries = append(target.Entries, editedClockEntry("Fixture/"+name, kind, uint64(10+i)))
	}
	for _, profile := range []string{"apfsx", "hfsx"} {
		got, err := CloneCopyReference(source, target, []schema.Step{cloneClockTool("-cR", "Fixture/tree", "Fixture/copy", "0")}, profile, editedTestClock)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range got.Entries[5:] {
			want := schema.Times{Birth: editedTestClock, Modify: editedTestClock, Change: editedTestClock, Access: editedTestClock}
			if profile == "apfsx" && entry.Kind == "file" {
				want.Birth, want.Modify, want.Access = 1, 50, 4
			}
			if entry.Times != want {
				t.Fatal("recursive clone clocks", profile, entry)
			}
		}
	}
	target.Entries[7].ID = target.Entries[6].ID
	if _, err := CloneCopyReference(source, target, []schema.Step{cloneClockTool("-cR", "Fixture/tree", "Fixture/copy", "0")}, "apfsx", editedTestClock); err == nil {
		t.Fatal("recursive clone copies incorrectly accepted as hard links")
	}
}

func TestRejectedCloneCommandsPreserveEveryClockAndRequireProvenRefusals(t *testing.T) {
	before := schema.View{Entries: []schema.Entry{editedClockEntry("Fixture", "dir", 1), editedClockEntry("Fixture/file", "file", 2), editedClockEntry("Fixture/occupied", "file", 3)}}
	steps := []schema.Step{cloneClockTool("-cX", "Fixture/file", "Fixture/new", "1"), cloneClockTool("-c", "Fixture/file", "Fixture/file", "1"), cloneClockTool("-cn", "Fixture/file", "Fixture/occupied", "1"), {FS: &schema.FSStep{Op: "clone", Path: "$MOUNT/Fixture/file", Target: "$MOUNT/Fixture/occupied", Expect: "EEXIST"}}}
	got, err := CloneCopyReference(before, before, steps, "apfs", editedTestClock)
	if err != nil || !reflect.DeepEqual(got, before) {
		t.Fatal("rejected clone commands changed clocks", err, got)
	}
	for _, invalid := range []schema.Step{cloneClockTool("-cn", "Fixture/file", "Fixture/missing", "1"), cloneClockTool("-c", "Fixture/file", "Fixture/occupied", "1"), cloneClockTool("-cR", "Fixture/file", "Fixture/new", "0"), cloneClockTool("-cX", "Fixture/file", "Fixture/new", "0")} {
		if _, err := CloneCopyReference(before, before, []schema.Step{invalid}, "apfs", editedTestClock); err == nil {
			t.Fatal("unproved clone command accepted", invalid.Tool)
		}
	}
}
