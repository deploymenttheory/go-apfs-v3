package native

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// This volume and commander never access a native filesystem or launch a tool.
// Only the bounded host payload tree is materialized under t.TempDir.
type nativeWriteCommandVolume struct{ fixture.Volume }

func (nativeWriteCommandVolume) Mkdir(string, uint32) error                    { return os.ErrPermission }
func (nativeWriteCommandVolume) WriteFile(string, []byte, bool) error          { return nil }
func (nativeWriteCommandVolume) AppendFile(string, []byte) error               { return nil }
func (nativeWriteCommandVolume) Fullfsync(string) error                        { return nil }
func (nativeWriteCommandVolume) Remove(string) error                           { return nil }
func (nativeWriteCommandVolume) Setxattr(string, string, []byte, string) error { return nil }
func (nativeWriteCommandVolume) Removexattr(string, string) error              { return nil }

type nativeWriteCommander struct {
	calls []fixture.Command
	fail  error
}

func (c *nativeWriteCommander) Run(_ context.Context, cmd fixture.Command) fixture.Result {
	c.calls = append(c.calls, cmd)
	result := fixture.Result{Stdout: []byte("native tool receipt\n")}
	if len(cmd.Argv) > 1 && cmd.Argv[1] == "--hfsCompression" {
		result.Err = c.fail
	}
	return result
}

func TestNativeWriteFailuresRetainToolsBeforeDiskCleanup(t *testing.T) {
	for _, failedPhase := range []string{"tool", "detach"} {
		t.Run(failedPhase, func(t *testing.T) {
			work := t.TempDir()
			cause := errors.New("native " + failedPhase + " failed")
			commander := &nativeWriteCommander{}
			disk := &continuationCommandDisk{}
			if failedPhase == "tool" {
				commander.fail = cause
			} else {
				disk.detaches, disk.detachErr = 1, cause
			}
			v := &Verifier{Disk: disk, Vol: nativeWriteCommandVolume{}, C: commander}
			finish := v.recordContinuationCommands(work)
			initial := &fixture.Transcript{}
			v.setTranscript(initial)
			disk.record("prior-disk-check", "0")

			err := v.nativeWrites(context.Background(), "fake-volume", filepath.Join(work, "payload"))
			if failedPhase == "tool" {
				if !errors.Is(err, cause) {
					t.Fatalf("native tool failure changed: %v", err)
				}
				_ = disk.Detach(context.Background(), &fixture.Attachment{})
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if err = disk.Unmount(context.Background(), &fixture.AttachedVolume{}); err != nil {
					t.Fatal(err)
				}
				err = disk.Detach(context.Background(), &fixture.Attachment{})
			}
			finish(&err)
			if !errors.Is(err, cause) || v.Disk != disk || v.continuationLog != nil {
				t.Fatalf("evidence changed failure or disk ownership: %v", err)
			}
			data, readErr := os.ReadFile(filepath.Join(work, "continuation-commands.json"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			var recorded []schema.Command
			if err := json.Unmarshal(data, &recorded); err != nil {
				t.Fatal(err)
			}
			if len(commander.calls) != 9 {
				t.Fatalf("native write procedure did not reach all tool operations: %d", len(commander.calls))
			}
			want := []schema.Command{{Label: "prior-disk-check", Status: "0"}}
			for i, cmd := range commander.calls {
				status := "0"
				if failedPhase == "tool" && i == len(commander.calls)-1 {
					status = "launch-failed"
				}
				want = append(want, schema.Command{Argv: cmd.Argv, Sudo: cmd.Sudo, Expected: cmd.Expected, Status: status, StdoutText: "native tool receipt\n"})
			}
			if failedPhase == "tool" {
				want = append(want, schema.Command{Label: "detach", Status: "0"})
			} else {
				want = append(want, schema.Command{Label: "unmount", Status: "0"}, schema.Command{Label: "hdiutil-info", Status: "0"}, schema.Command{Label: "detach", Status: "16"})
			}
			for i := range recorded {
				// Digests are exercised by fixture.Transcript's own tests. Keep
				// this comparison focused on actual command order and outcomes.
				recorded[i].StdoutSHA256, recorded[i].StderrSHA256 = "", ""
			}
			if !reflect.DeepEqual(recorded, want) {
				t.Fatalf("successful native tools were omitted or reordered before cleanup:\ngot %#v\nwant %#v", recorded, want)
			}
		})
	}
}
