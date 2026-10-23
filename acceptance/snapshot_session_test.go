package acceptance_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/native"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
	"github.com/deploymenttheory/go-apfs-v3/filesystem"
	"github.com/deploymenttheory/go-apfs-v3/session"
	"github.com/deploymenttheory/go-apfs-v3/workspace"
)

// TestSnapshotSessionsRetainTheSelectedHistoricalView opens each historical
// state through both public CLI selectors. Independent exports must agree with
// Apple's historical mount, remain distinct from the live state, and preserve
// the selected volume, transaction and object identities through process reopen.
func TestSnapshotSessionsRetainTheSelectedHistoricalView(t *testing.T) {
	cases, _ := loadCorpus(t)
	binary := portableCommandBinary(t)
	seen := map[string]bool{}
	for _, k := range cases {
		if k.Recipe != "snapshot-history" || k.Stage != "live" || (k.Profile != "apfs" && k.Profile != "apfsx") {
			continue
		}
		key := fmt.Sprintf("macos-%d/%s", k.Producer, k.Profile)
		if seen[key] {
			t.Fatalf("duplicate snapshot-session source %s", key)
		}
		seen[key] = true
		t.Run(key, func(t *testing.T) {
			t.Parallel()
			if len(k.Observation.Volumes) != 1 || k.Observation.Volumes[0].APFS == nil {
				t.Fatal("snapshot-session source must have one native APFS volume")
			}
			volume := k.Observation.Volumes[0]
			if len(volume.APFS.Snapshots) != 2 {
				t.Fatal("snapshot-session source must retain both historical states")
			}
			sourceDigest := packingFileDigest(t, fixtureImage(t, k))
			live := snapshotSessionView(t, k, "")
			for _, snapshot := range volume.APFS.Snapshots {
				t.Run(fmt.Sprintf("xid-%d", snapshot.XID), func(t *testing.T) {
					view := snapshotSessionView(t, k, snapshot.Name)
					if len(native.CompareViews(view, live, native.CompareOptions{Subtree: "Fixture"})) == 0 {
						t.Fatal("historical control does not distinguish selection from a live fallback")
					}
					var root uint64
					for _, entry := range view.Entries {
						if entry.Path == "Fixture" {
							root = entry.ID
						}
					}
					if root == 0 {
						t.Fatal("historical observation lacks the selected subtree root")
					}
					identity := filesystem.Identity{Volume: strings.ToUpper(volume.APFS.VolumeUUID), Object: root, View: snapshot.XID}
					expect := schema.Expectation{Subtree: "Fixture", Snapshot: snapshot.Name, Workspace: &schema.WorkspaceExpectation{Policy: "preserve"}}
					nameDirectory := exportSnapshotSession(t, binary, k, view, identity, "--snapshot-name", snapshot.Name)
					xidDirectory := exportSnapshotSession(t, binary, k, view, identity, "--snapshot-xid", strconv.FormatUint(snapshot.XID, 10))
					name := outputName(k, fmt.Sprintf("workspace.snapshot-xid-%d.tar.gz", snapshot.XID))
					archive := filepath.Join(outputDir(t), name)
					if err := archiveWorkspace(nameDirectory, archive); err != nil {
						t.Fatal(err)
					}
					alternate := filepath.Join(t.TempDir(), "selected-by-xid.tar.gz")
					if err := archiveWorkspace(xidDirectory, alternate); err != nil {
						t.Fatal(err)
					}
					if packingFileDigest(t, archive) != packingFileDigest(t, alternate) {
						t.Fatal("name and XID selectors exported different preservation archives")
					}
					for _, filename := range []string{archive, alternate} {
						diffs, err := native.VerifyWorkspaceArchive(filename, k.Profile, view, view, expect)
						if err != nil {
							t.Fatal(err)
						}
						for _, difference := range diffs {
							t.Error(difference)
						}
					}
					recordOutput(t, schema.Output{Name: name, File: filepath.Base(archive), Operation: "workspace-snapshot", Format: "workspace", Source: caseRef(k), Expect: expect})
				})
			}
			for _, control := range []struct {
				name string
				args []string
			}{
				{name: "unknown-name", args: []string{"--snapshot-name", "missing-native-history"}},
				{name: "unknown-xid", args: []string{"--snapshot-xid", "18446744073709551615"}},
				{name: "empty-name", args: []string{"--snapshot-name", ""}},
				{name: "zero-xid", args: []string{"--snapshot-xid", "0"}},
				{name: "ambiguous-selectors", args: []string{"--snapshot-name", volume.APFS.Snapshots[0].Name, "--snapshot-xid", strconv.FormatUint(volume.APFS.Snapshots[0].XID, 10)}},
			} {
				t.Run(control.name, func(t *testing.T) {
					scratch := t.TempDir()
					args := []string{"session", "open", "--scratch-dir", scratch, "--image", fixtureImage(t, k), "--path", "Fixture"}
					args = append(args, control.args...)
					args = append(args, "refused")
					data, err := exec.Command(binary, args...).CombinedOutput()
					var exit *exec.ExitError
					if !errors.As(err, &exit) || exit.ExitCode() != 1 {
						t.Fatalf("invalid snapshot selection was not refused: %v: %s", err, data)
					}
					if _, err := os.Lstat(filepath.Join(scratch, "refused")); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("invalid selection published a live or partial session: %v", err)
					}
				})
			}
			if got := packingFileDigest(t, fixtureImage(t, k)); got != sourceDigest {
				t.Fatal("historical session selection changed the original image")
			}
		})
	}
	for _, producer := range []int{15, 26, 27} {
		for _, profile := range []string{"apfs", "apfsx"} {
			if !seen[fmt.Sprintf("macos-%d/%s", producer, profile)] {
				t.Fatalf("corpus lacks historical session controls for macOS %d/%s", producer, profile)
			}
		}
	}
}

func snapshotSessionView(t *testing.T, k corpus.Case, name string) schema.View {
	t.Helper()
	var found *schema.View
	for _, view := range k.Observation.Views {
		if view.Volume == 0 && view.Snapshot == name {
			if found != nil {
				t.Fatal("duplicate native historical view", name)
			}
			found = &view
		}
	}
	if found == nil {
		t.Fatal("missing native historical view", name)
	}
	return *found
}

func exportSnapshotSession(t *testing.T, binary string, k corpus.Case, view schema.View, identity filesystem.Identity, selector, value string) string {
	t.Helper()
	ctx := context.Background()
	scratch := t.TempDir()
	run := func(args ...string) []byte {
		t.Helper()
		argv := append([]string{"session", args[0], "--scratch-dir", scratch}, args[1:]...)
		data, err := exec.Command(binary, argv...).CombinedOutput()
		if err != nil {
			t.Fatalf("historical session %v: %v: %s", args, err, data)
		}
		return data
	}
	run("open", "--image", fixtureImage(t, k), "--path", "Fixture", selector, value, "--time", fixedClock.Format(time.RFC3339), "history")
	run("verify", "history")
	var report session.Report
	if err := json.Unmarshal(run("status", "--json", "history"), &report); err != nil {
		t.Fatal(err)
	}
	if report.Source != identity {
		t.Fatalf("CLI reopened another view: got %+v, want %+v", report.Source, identity)
	}
	sessionDir := filepath.Join(scratch, "history")
	s, err := session.Open(ctx, sessionDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { closeFixture(t, s) }()
	rules := filesystem.NameRules{Format: "APFS", CaseSensitive: k.Profile == "apfsx", NormalizationInsensitive: true}
	packingSourceIdentity(t, ctx, s, rules, identity)
	compareViewWith(t, ctx, "reopened historical session", s, view, compareOptions{subtree: "Fixture"})
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	before := packingSourceInventory(t, sessionDir)
	destination := filepath.Join(t.TempDir(), "export")
	run("export", "history", destination)
	if after := packingSourceInventory(t, sessionDir); !reflect.DeepEqual(before, after) {
		t.Fatal("export changed the selected historical session")
	}
	w, err := workspace.Open(ctx, destination)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { closeFixture(t, w) }()
	packingSourceIdentity(t, ctx, w, rules, identity)
	compareViewWith(t, ctx, "historical preservation export", w, view, compareOptions{subtree: "Fixture"})
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return destination
}
