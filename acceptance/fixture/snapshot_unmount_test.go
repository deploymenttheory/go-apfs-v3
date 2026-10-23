package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func snapshotUnmountDisk(t *testing.T, commander Commander) (*HostDisk, string, mountIdentity) {
	t.Helper()
	pin := filepath.Join(t.TempDir(), "snapshot")
	if err := os.Mkdir(pin, 0o755); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(pin)
	if err != nil {
		t.Fatal(err)
	}
	identity := mountIdentity{MountPoint: canonical, Source: "opaque snapshot source /dev/disk9s1", FSID: [2]int32{21, 3}}
	return &HostDisk{C: commander, T: &Transcript{}, mountProbe: func(string) (mountIdentity, error) { return identity, nil }}, pin, identity
}

func busySnapshotCommander() *fakeCommander {
	return &fakeCommander{sequence: map[string][]Result{"/sbin/umount": {
		{Status: 1, Stderr: []byte("umount: Resource busy")}, {Status: 0},
	}}}
}

func TestSnapshotUnmountRefusesChangedMountIdentityBeforeRetry(t *testing.T) {
	for _, field := range []string{"source", "fsid"} {
		t.Run(field, func(t *testing.T) {
			instantWaits(t)
			cmd := busySnapshotCommander()
			d, pin, original := snapshotUnmountDisk(t, cmd)
			probes := 0
			d.mountProbe = func(string) (mountIdentity, error) {
				probes++
				identity := original
				if probes > 1 {
					if field == "source" {
						identity.Source = "different snapshot on the same device"
					} else {
						identity.FSID[0]++
					}
				}
				return identity, nil
			}
			err := d.UnmountPath(context.Background(), pin)
			if err == nil || !strings.Contains(err.Error(), "identity") || !strings.Contains(err.Error(), "Resource busy") || len(cmd.calls) != 1 || probes != 2 {
				t.Fatalf("changed mount was unmounted or original busy cause lost: %v, calls=%v, probes=%d", err, cmd.calls, probes)
			}
		})
	}
}

func TestSnapshotUnmountRecordsGoneMountWithoutAnotherUnmount(t *testing.T) {
	instantWaits(t)
	cmd := busySnapshotCommander()
	d, pin, original := snapshotUnmountDisk(t, cmd)
	probes := 0
	d.mountProbe = func(string) (mountIdentity, error) {
		probes++
		if probes == 1 {
			return original, nil
		}
		return mountIdentity{MountPoint: filepath.Dir(original.MountPoint), Source: "enclosing filesystem", FSID: [2]int32{1, 2}}, nil
	}
	if err := d.UnmountPath(context.Background(), pin); err != nil || len(cmd.calls) != 1 || probes != 2 {
		t.Fatalf("already absent snapshot was unmounted again: %v, calls=%v, probes=%d", err, cmd.calls, probes)
	}
	last := d.T.Commands[len(d.T.Commands)-1]
	var receipt struct{ Outcome string }
	if err := json.Unmarshal([]byte(last.StdoutText), &receipt); err != nil || receipt.Outcome != "gone" || last.StdoutSHA256 == "" || last.Status != "0" {
		t.Fatalf("native absence has no explicit receipt: %+v, %v", last, err)
	}
}

func TestSnapshotUnmountRefusesUnknownInitialMountWithoutACommand(t *testing.T) {
	for _, state := range []string{"probe failure", "enclosing mount", "empty source", "relative mountpoint", "nul source", "unrelated mountpoint"} {
		t.Run(state, func(t *testing.T) {
			cmd := &fakeCommander{}
			d, pin, identity := snapshotUnmountDisk(t, cmd)
			cause := errors.New("mount probe unavailable")
			d.mountProbe = func(string) (mountIdentity, error) {
				switch state {
				case "probe failure":
					return mountIdentity{}, cause
				case "enclosing mount":
					identity.MountPoint = filepath.Dir(identity.MountPoint)
				case "empty source":
					identity.Source = ""
				case "relative mountpoint":
					identity.MountPoint = "snapshot"
				case "nul source":
					identity.Source = "snapshot\x00device"
				case "unrelated mountpoint":
					identity.MountPoint = t.TempDir()
				}
				return identity, nil
			}
			err := d.UnmountPath(context.Background(), pin)
			if err == nil || len(cmd.calls) != 0 || state == "probe failure" && !errors.Is(err, cause) {
				t.Fatalf("unidentified initial path was unmounted: %v, calls=%v", err, cmd.calls)
			}
		})
	}
}

func TestSnapshotUnmountJoinsBusyCauseWhenRetryOwnershipIsUnknown(t *testing.T) {
	for _, state := range []string{"probe failure", "empty source", "unrelated mountpoint"} {
		t.Run(state, func(t *testing.T) {
			instantWaits(t)
			cmd := busySnapshotCommander()
			d, pin, identity := snapshotUnmountDisk(t, cmd)
			cause := errors.New("mount identity unavailable")
			probes := 0
			d.mountProbe = func(string) (mountIdentity, error) {
				probes++
				if probes == 1 {
					return identity, nil
				}
				switch state {
				case "probe failure":
					return mountIdentity{}, cause
				case "empty source":
					identity.Source = ""
				case "unrelated mountpoint":
					identity.MountPoint = t.TempDir()
				}
				return identity, nil
			}
			err := d.UnmountPath(context.Background(), pin)
			if err == nil || !strings.Contains(err.Error(), "Resource busy") || len(cmd.calls) != 1 || state == "probe failure" && !errors.Is(err, cause) {
				t.Fatalf("unknown retry ownership lost cause or allowed another command: %v, calls=%v", err, cmd.calls)
			}
		})
	}
}

func TestSnapshotUnmountCanonicalTargetSurvivesAliasRetargeting(t *testing.T) {
	instantWaits(t)
	cmd := busySnapshotCommander()
	d, _, identity := snapshotUnmountDisk(t, cmd)
	alias := filepath.Join(t.TempDir(), "alias")
	if err := os.Symlink(identity.MountPoint, alias); err != nil {
		t.Fatal(err)
	}
	different := t.TempDir()
	probes := 0
	d.mountProbe = func(path string) (mountIdentity, error) {
		probes++
		if path != identity.MountPoint {
			t.Fatalf("probe followed alias instead of canonical pin: %q", path)
		}
		if probes == 2 {
			if err := os.Remove(alias); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(different, alias); err != nil {
				t.Fatal(err)
			}
		}
		return identity, nil
	}
	if err := d.UnmountPath(context.Background(), alias); err != nil || probes != 2 || len(cmd.calls) != 2 {
		t.Fatalf("canonical alias cleanup failed: %v, probes=%d, calls=%v", err, probes, cmd.calls)
	}
	for _, argv := range cmd.calls {
		if argv[1] != identity.MountPoint {
			t.Fatalf("unmount followed a retargetable alias: %v", argv)
		}
	}
}

func TestSnapshotUnmountAcceptsCanonicalKernelMountAliases(t *testing.T) {
	cmd := &fakeCommander{}
	d, pin, identity := snapshotUnmountDisk(t, cmd)
	canonical := identity.MountPoint
	alias := filepath.Join(t.TempDir(), "mount-alias")
	if err := os.Symlink(identity.MountPoint, alias); err != nil {
		t.Fatal(err)
	}
	d.mountProbe = func(string) (mountIdentity, error) {
		identity.MountPoint = alias
		return identity, nil
	}
	if err := d.UnmountPath(context.Background(), pin); err != nil || len(cmd.calls) != 1 || cmd.calls[0][1] != canonical {
		t.Fatalf("canonical mount alias rejected: %v, calls=%v", err, cmd.calls)
	}
}

func TestSnapshotUnmountCancellationDuringProbeNeverRunsAnotherCommand(t *testing.T) {
	for _, phase := range []struct {
		name     string
		cancelAt int
	}{{"initial", 1}, {"retry", 2}} {
		t.Run(phase.name, func(t *testing.T) {
			instantWaits(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			cmd := busySnapshotCommander()
			d, pin, identity := snapshotUnmountDisk(t, cmd)
			probes := 0
			d.mountProbe = func(string) (mountIdentity, error) {
				probes++
				if probes == phase.cancelAt {
					cancel()
				}
				return identity, nil
			}
			err := d.UnmountPath(ctx, pin)
			if !errors.Is(err, context.Canceled) || len(cmd.calls) != phase.cancelAt-1 || phase.cancelAt == 2 && !strings.Contains(err.Error(), "Resource busy") {
				t.Fatalf("cancelled probe allowed command or lost cause: %v, probes=%d, calls=%v", err, probes, cmd.calls)
			}
		})
	}
}
