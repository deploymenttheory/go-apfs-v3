package fixture

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestMixedAPFSVerificationUsesEveryVolumesCryptoContext(t *testing.T) {
	transcript := &Transcript{}
	volumes := []*AttachedVolume{{Dev: "/dev/disk8s1", RDev: "/dev/rdisk8s1", UUID: "PRIMARY", FS: "apfs"}, {Dev: "/dev/disk8s2", RDev: "/dev/rdisk8s2", UUID: "PEER", FS: "apfs"}}
	obs := &schema.Observation{Volumes: []schema.Volume{{Device: volumes[0].Dev, APFS: &schema.APFSVolume{VolumeUUID: "PRIMARY"}}, {Device: volumes[1].Dev, APFS: &schema.APFSVolume{VolumeUUID: "PEER", Encrypted: true}}}}
	commander := &fakeCommander{results: map[string]Result{"/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs": {Status: 66, Stderr: []byte("failed to enable crypto I/O mode")}}, sequence: map[string][]Result{"diskutil": {{Stdout: []byte(apfsVerificationText(volumes[0].RDev, "PRIMARY"))}, {Stdout: []byte(apfsVerificationText(volumes[1].RDev, "PEER"))}}}}
	in := ObserveInput{Spec: schema.ObserveSpec{Checks: []string{"fsck"}}, Att: &Attachment{RDev: "/dev/rdisk7", Volumes: volumes}, Disk: &HostDisk{C: commander, T: transcript}, T: transcript}
	if err := observeChecks(context.Background(), in, obs); err != nil {
		t.Fatal("mixed container verification", err)
	}
	if len(obs.Checks.Fsck) != 2 || obs.Checks.SelectedXID != 42 {
		t.Fatal("verification omitted a volume or checkpoint", obs.Checks)
	}
	for _, argv := range commander.calls {
		if len(argv) != 3 || argv[0] != "diskutil" || argv[1] != "verifyVolume" {
			t.Fatal("verification used a raw checker without crypto context", argv)
		}
	}
}

func apfsVerificationText(device, id string) string {
	return strings.Join([]string{"Checking the container superblock", "Checking the checkpoint with transaction ID 42", "Checking the space manager", "Checking the space manager free queue trees", "Checking the encryption key structures", "Checking the APFS volume superblock", "Checking the object map", "Checking the snapshot metadata tree", "Checking the snapshot metadata", "Checking the fsroot tree", "Checking the extent ref tree", "Verifying volume object map space", "Verifying allocated space", "File system check exit code is 0", fmt.Sprintf("The volume %s with UUID %s appears to be OK", device, id)}, "\n")
}
