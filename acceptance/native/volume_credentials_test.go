package native

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestEncryptedVerificationReleasesKeysBeforeDetach(t *testing.T) {
	for _, failure := range []string{"", "verification", "unlock"} {
		t.Run("failure="+failure, func(t *testing.T) {
			disk := &verificationKeyDisk{locked: true}
			volume := &fixture.AttachedVolume{Name: "History", Dev: "/dev/disk8s1", RDev: "/dev/rdisk8s1", UUID: "HISTORY", FS: "apfs", Locked: true}
			disk.attachment = &fixture.Attachment{Volumes: []*fixture.AttachedVolume{volume}}
			observation := &schema.Observation{Volumes: []schema.Volume{{Diskutil: map[string]any{"VolumeName": "History"}, APFS: &schema.APFSVolume{VolumeUUID: volume.UUID, Encrypted: true, Password: "history"}}}}
			v := &Verifier{Disk: disk, C: verificationKeyCommander{disk: disk, failure: failure}}
			err := v.checkEncryptedVolumes(context.Background(), "original.dmg", nil, observation, schema.Recipe{Passwords: map[string]string{"history": "public-test-password"}})
			if (err != nil) != (failure != "") {
				t.Fatal("checker result changed", err)
			}
			if !disk.detached || !disk.lockedAtDetach {
				t.Fatal("verification left cached keys active at detach", disk.detached, disk.lockedAtDetach)
			}
		})
	}
}

type verificationKeyDisk struct {
	fixture.Disk
	attachment                       *fixture.Attachment
	locked, detached, lockedAtDetach bool
}

func (d *verificationKeyDisk) Attach(context.Context, string, fixture.AttachOptions) (*fixture.Attachment, error) {
	return d.attachment, nil
}
func (d *verificationKeyDisk) Info(context.Context, string) (map[string]any, error) {
	return map[string]any{"Locked": d.locked}, nil
}
func (d *verificationKeyDisk) Detach(context.Context, *fixture.Attachment) error {
	d.detached, d.lockedAtDetach = true, d.locked
	return nil
}

type verificationKeyCommander struct {
	disk    *verificationKeyDisk
	failure string
}

func (c verificationKeyCommander) Run(_ context.Context, command fixture.Command) fixture.Result {
	argv := command.Argv
	switch {
	case len(argv) > 2 && argv[2] == "unlockVolume":
		if c.failure == "unlock" {
			return fixture.Result{Status: 1, Stderr: []byte("unlock refused")}
		}
		if !bytes.Equal(command.Stdin, []byte("public-test-password\n")) {
			return fixture.Result{Status: 1, Stderr: []byte("wrong test password")}
		}
		c.disk.locked = false
		return fixture.Result{}
	case len(argv) > 2 && argv[2] == "lockVolume":
		c.disk.locked = true
		return fixture.Result{}
	case len(argv) > 1 && argv[1] == "verifyVolume":
		if c.disk.locked || c.failure == "verification" {
			return fixture.Result{Status: 1, Stderr: []byte("verification failed")}
		}
		return fixture.Result{Stdout: []byte(strings.Join([]string{
			"Checking the container superblock", "Checking the checkpoint with transaction ID 42",
			"Checking the space manager", "Checking the space manager free queue trees",
			"Checking the encryption key structures", "Checking the APFS volume superblock",
			"Checking the object map", "Checking the snapshot metadata tree", "Checking the snapshot metadata",
			"Checking the fsroot tree", "Checking the extent ref tree", "Verifying volume object map space",
			"Verifying allocated space", "File system check exit code is 0",
			"The volume /dev/rdisk8s1 with UUID HISTORY appears to be OK",
		}, "\n"))}
	default:
		return fixture.Result{Status: 1, Stderr: []byte(fmt.Sprint("unexpected command ", argv))}
	}
}
