package fixture

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestCachedUnlockedVolumeIsMountedBeforeCredentialReset(t *testing.T) {
	stop := errors.New("stop at the required native mount")
	c := &cachedUnlockCommander{stop: stop}
	transcript := &Transcript{}
	volume := &AttachedVolume{Name: "History", Dev: "/dev/disk8s1"}
	in := ObserveInput{Disk: &HostDisk{C: c, T: transcript}, T: transcript, Work: t.TempDir()}
	err := observeVolume(context.Background(), in, &schema.Observation{}, 0, volume)
	if !errors.Is(err, stop) || !c.mountAttempted {
		t.Fatalf("cached unlocked/unmounted volume was locked before mounting: %v", err)
	}
}

type cachedUnlockCommander struct {
	stop           error
	mountAttempted bool
}

func (c *cachedUnlockCommander) Run(_ context.Context, command Command) Result {
	argv := command.Argv
	switch {
	case argv[0] == "plutil":
		return Result{Stdout: bytes.Clone(command.Stdin)}
	case len(argv) == 4 && argv[0] == "diskutil" && argv[1] == "info":
		return Result{Stdout: []byte(`{"FileVault":true,"Locked":false,"MountPoint":""}`)}
	case len(argv) >= 3 && argv[0] == "diskutil" && argv[1] == "mount":
		c.mountAttempted = true
		return Result{Err: c.stop}
	case len(argv) == 4 && argv[0] == "diskutil" && argv[1] == "apfs" && argv[2] == "lockVolume":
		return Result{Status: 1, Stderr: []byte("Error locking APFS Volume; locking an unmounted APFS Volume is not currently supported")}
	default:
		return Result{Status: 1, Stderr: []byte("unexpected native command")}
	}
}
