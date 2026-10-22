package fixture

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

type snapshotInventoryCommander struct {
	calls  []Command
	result Result
}

func (c *snapshotInventoryCommander) Run(_ context.Context, command Command) Result {
	c.calls = append(c.calls, command)
	if command.Argv[0] == "plutil" {
		return Result{Stdout: []byte(`{"Snapshots":[{"Name":"native-history","XID":12}]}`)}
	}
	return c.result
}

func TestSnapshotInventoryUsesOnePrivilegedReadIndependentOfVolumeOwner(t *testing.T) {
	c := &snapshotInventoryCommander{result: Result{Stdout: []byte("original native snapshot plist")}}
	d := &HostDisk{C: c, T: &Transcript{}}
	snapshots, err := d.Snapshots(t.Context(), "/dev/disk12s2")
	if err != nil || len(snapshots) != 1 || snapshots[0]["Name"] != "native-history" {
		t.Fatalf("native snapshot inventory lost: %+v, %v", snapshots, err)
	}
	want := []string{"diskutil", "apfs", "listSnapshots", "-plist", "/dev/disk12s2"}
	if len(c.calls) != 2 || !c.calls[0].Sudo || !reflect.DeepEqual(c.calls[0].Argv, want) || c.calls[0].Expected != "0" {
		t.Fatalf("snapshot read was retried, unprivileged or changed: %+v", c.calls)
	}
	if len(d.T.Commands) != 1 || !d.T.Commands[0].Sudo || d.T.Commands[0].StdoutText != "original native snapshot plist" || d.T.Commands[0].StdoutSHA256 == "" {
		t.Fatalf("original privileged read evidence lost: %+v", d.T.Commands)
	}
}

func TestSnapshotInventoryNativeFailureRemainsFatalWithoutFallbackOrRetry(t *testing.T) {
	cause := "Error getting list of snapshots for APFS Volume: Insufficient privileges (-69863)"
	c := &snapshotInventoryCommander{result: Result{Status: 1, Stderr: []byte(cause)}}
	d := &HostDisk{C: c, T: &Transcript{}}
	if snapshots, err := d.Snapshots(t.Context(), "/dev/disk12s2"); err == nil || !strings.Contains(err.Error(), cause) || len(snapshots) != 0 || len(c.calls) != 1 || !c.calls[0].Sudo {
		t.Fatalf("native read failure was suppressed or retried: snapshots=%v error=%v calls=%+v", snapshots, err, c.calls)
	}
	if len(d.T.Commands) != 1 || d.T.Commands[0].Status != "1" || d.T.Commands[0].StderrText != cause {
		t.Fatal("original native failure was not retained")
	}
}
