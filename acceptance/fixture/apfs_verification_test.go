package fixture

import (
	"bytes"
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
	commander := &fakeCommander{results: map[string]Result{"plutil": {Stdout: []byte(`{"Locked":false}`)}, "/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs": {Status: 66, Stderr: []byte("failed to enable crypto I/O mode")}}, sequence: map[string][]Result{"diskutil": {{}, {Stdout: []byte(apfsVerificationText(volumes[0].RDev, "PRIMARY"))}, {Stdout: []byte(apfsVerificationText(volumes[1].RDev, "PEER"))}}}}
	in := ObserveInput{Spec: schema.ObserveSpec{Checks: []string{"fsck"}}, Att: &Attachment{RDev: "/dev/rdisk7", Volumes: volumes}, Disk: &HostDisk{C: commander, T: transcript}, T: transcript}
	if err := observeChecks(context.Background(), in, obs); err != nil {
		t.Fatal("mixed container verification", err)
	}
	if len(obs.Checks.Fsck) != 2 || obs.Checks.SelectedXID != 42 {
		t.Fatal("verification omitted a volume or checkpoint", obs.Checks)
	}
	checks := 0
	for _, argv := range commander.calls {
		if argv[0] == "/System/Library/Filesystems/apfs.fs/Contents/Resources/fsck_apfs" {
			t.Fatal("verification used a raw checker without crypto context", argv)
		}
		if len(argv) == 3 && argv[0] == "diskutil" && argv[1] == "verifyVolume" {
			checks++
		}
	}
	if checks != 2 {
		t.Fatal("omitted APFS volume verification", commander.calls)
	}
}

func apfsVerificationText(device, id string) string {
	return strings.Join([]string{"Checking the container superblock", "Checking the checkpoint with transaction ID 42", "Checking the space manager", "Checking the space manager free queue trees", "Checking the encryption key structures", "Checking the APFS volume superblock", "Checking the object map", "Checking the snapshot metadata tree", "Checking the snapshot metadata", "Checking the fsroot tree", "Checking the extent ref tree", "Verifying volume object map space", "Verifying allocated space", "File system check exit code is 0", fmt.Sprintf("The volume %s with UUID %s appears to be OK", device, id)}, "\n")
}

// Native observation unmounts each encrypted volume, which relocks its keys.
// A checker command alone cannot restore that crypto context.
func TestAPFSVerificationRefreshesCredentialsAfterObservationUnmount(t *testing.T) {
	transcript := &Transcript{}
	volume := &AttachedVolume{Dev: "/dev/disk8s1", RDev: "/dev/rdisk8s1", UUID: "PRIMARY", Name: "History", FS: "apfs"}
	obs := &schema.Observation{Volumes: []schema.Volume{{Device: volume.Dev, APFS: &schema.APFSVolume{VolumeUUID: volume.UUID, Encrypted: true}}}}
	commander := &unmountedAPFSCommander{locked: true, volume: volume}
	in := ObserveInput{Spec: schema.ObserveSpec{Checks: []string{"fsck"}, Unlock: map[string]string{"History": "primary"}}, Vars: &Vars{Passwords: map[string]string{"primary": "public-context-password"}}, Att: &Attachment{Volumes: []*AttachedVolume{volume}}, Disk: &HostDisk{C: commander, T: transcript}, T: transcript}
	if err := observeChecks(context.Background(), in, obs); err != nil {
		t.Fatal(err)
	}
	if commander.locked || commander.unlocks != 1 || commander.checks != 1 || len(obs.Checks.Fsck) != 1 {
		t.Fatal("checker lacked refreshed crypto context", commander)
	}
}

type unmountedAPFSCommander struct {
	locked          bool
	volume          *AttachedVolume
	unlocks, checks int
}

func (c *unmountedAPFSCommander) Run(_ context.Context, command Command) Result {
	argv := command.Argv
	switch {
	case argv[0] == "plutil":
		return Result{Stdout: bytes.Clone(command.Stdin)}
	case len(argv) == 4 && argv[0] == "diskutil" && argv[1] == "info":
		return Result{Stdout: []byte(fmt.Sprintf(`{"Locked":%t,"FileVault":true}`, c.locked))}
	case len(argv) == 6 && argv[0] == "diskutil" && argv[1] == "apfs" && argv[2] == "unlockVolume" && argv[3] == c.volume.Dev && argv[4] == "-stdinpassphrase" && argv[5] == "-nomount":
		if string(command.Stdin) != "public-context-password\n" {
			return Result{Status: 1, Stderr: []byte("incorrect fixture credential")}
		}
		c.locked = false
		c.unlocks++
		return Result{}
	case len(argv) == 3 && argv[0] == "diskutil" && argv[1] == "verifyVolume" && argv[2] == c.volume.Dev:
		c.checks++
		if c.locked {
			return Result{Status: 1, Stdout: []byte("error: failed to enable crypto I/O mode for container"), Stderr: []byte("Underlying error: 66")}
		}
		return Result{Stdout: []byte(apfsVerificationText(c.volume.RDev, c.volume.UUID))}
	default:
		return Result{Status: 1, Stderr: []byte("unexpected native command")}
	}
}
