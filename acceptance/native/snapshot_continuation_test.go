package native

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestSnapshotDeletionContinuationChecksSurvivorsAndPeerHistory(t *testing.T) {
	original := snapshotEditingControl()
	original.Volumes[0].Diskutil["VolumeName"] = "EncryptedHistory"
	original.Volumes[0].APFS.VolumeUUID = "10000000-0000-4000-8000-000000000001"
	original.Volumes[0].APFS.Encrypted = true
	original.Volumes = append(original.Volumes, schema.Volume{Index: 1, Diskutil: map[string]any{"VolumeName": "Peer"}, APFS: &schema.APFSVolume{VolumeUUID: "10000000-0000-4000-8000-000000000002", Encrypted: true, Snapshots: []schema.Snapshot{{Name: "before", XID: 10}, {Name: "after", XID: 20}}}})
	original.Views = append(original.Views, schema.View{Volume: 1}, schema.View{Volume: 1, Snapshot: "before"}, schema.View{Volume: 1, Snapshot: "after"})
	ref := schema.CaseRef{Producer: 26, Recipe: "encrypted-snapshot-history", Profile: "apfs", Stage: "password-changed"}
	out := schema.Output{Name: "encrypted-history.snapshot-delete.oldest", Source: ref, Operation: "delete-snapshot", Format: "UDZO", Expect: schema.Expectation{Continuation: true, Volume: "EncryptedHistory", DeletedSnapshots: []schema.SnapshotIdentity{{Name: "before", XID: 10}}}}
	stop := errors.New("stop after all strict APFS checks")
	disk := &snapshotContinuationDisk{stop: stop}
	commander := &snapshotContinuationCommander{}
	v := &Verifier{Work: t.TempDir(), Disk: disk, Vol: snapshotContinuationVolume{}, C: commander, Cases: map[string]corpus.Case{CaseKey(ref): {Observation: original}}}
	p := Paired{Name: out.Name, Output: out, Primary: "linux", Dirs: map[string]string{"linux": t.TempDir()}, ByHost: map[string]schema.Output{"linux": {File: "output.dmg"}}}
	_, err := v.Continuation(context.Background(), p, schemaCase{})
	if !errors.Is(err, stop) || strings.Contains(err.Error(), "omitted snapshot") || commander.checked != 2 {
		t.Fatalf("continuation required deleted history or omitted a peer check: checks=%d error=%v", commander.checked, err)
	}
	if len(original.Volumes[0].APFS.Snapshots) != 2 || len(original.Views) != 6 {
		t.Fatal("continuation rewrote original evidence")
	}
}

type snapshotContinuationDisk struct {
	continuationCommandDisk
	stop error
}

func (d *snapshotContinuationDisk) Imageinfo(context.Context, string, []byte) (map[string]any, error) {
	return map[string]any{}, nil
}
func (d *snapshotContinuationDisk) Attach(_ context.Context, image string, _ fixture.AttachOptions) (*fixture.Attachment, error) {
	d.record("attach", "0")
	return &fixture.Attachment{Image: image, Volumes: []*fixture.AttachedVolume{
		{Name: "EncryptedHistory", Dev: "/dev/disk8s1", RDev: "/dev/rdisk8s1", UUID: "10000000-0000-4000-8000-000000000001", FS: "apfs"},
		{Name: "Peer", Dev: "/dev/disk8s2", RDev: "/dev/rdisk8s2", UUID: "10000000-0000-4000-8000-000000000002", FS: "apfs"},
	}}, nil
}
func (d *snapshotContinuationDisk) Detach(context.Context, *fixture.Attachment) error {
	d.detaches++
	d.record("detach", "0")
	if d.detaches == 3 {
		return d.stop
	}
	return nil
}

type snapshotContinuationVolume struct{ continuationCommandVolume }

func (snapshotContinuationVolume) Mkdir(string, uint32) error                    { return nil }
func (snapshotContinuationVolume) AppendFile(string, []byte) error               { return nil }
func (snapshotContinuationVolume) Remove(string) error                           { return nil }
func (snapshotContinuationVolume) Setxattr(string, string, []byte, string) error { return nil }
func (snapshotContinuationVolume) Removexattr(string, string) error              { return nil }

type snapshotContinuationCommander struct{ checked int }

func (c *snapshotContinuationCommander) Run(_ context.Context, command fixture.Command) fixture.Result {
	argv := command.Argv
	if len(argv) != 3 || argv[0] != "diskutil" || argv[1] != "verifyVolume" {
		return fixture.Result{}
	}
	c.checked++
	device, id, snapshots := "/dev/rdisk8s1", "10000000-0000-4000-8000-000000000001", "(after, transaction ID 20)"
	if argv[2] == "/dev/disk8s2" {
		device, id, snapshots = "/dev/rdisk8s2", "10000000-0000-4000-8000-000000000002", "(before, transaction ID 10)\n(after, transaction ID 20)"
	}
	text := strings.Join([]string{
		"Checking the container superblock", "Checking the checkpoint with transaction ID 42", "Checking the space manager", "Checking the space manager free queue trees", "Checking the encryption key structures", "Checking the APFS volume superblock", "Checking the object map", "Checking the snapshot metadata tree", "Checking the snapshot metadata", "Checking the fsroot tree", "Checking the extent ref tree", "Verifying volume object map space", "Verifying allocated space", "File system check exit code is 0", fmt.Sprintf("The volume %s with UUID %s appears to be OK", device, id), snapshots,
	}, "\n")
	return fixture.Result{Stdout: []byte(text)}
}
