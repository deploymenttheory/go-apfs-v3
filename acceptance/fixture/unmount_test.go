package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The two complete stderr lines retained from native macOS 26 CI 39847603729, job 120064979272.
const capturedBackupDissent = "Volume Reserved on disk12s1 failed to unmount: dissented by PID 311 (/System/Library/CoreServices/TimeMachine/backupd-helper)\nDissenter parent PPID 1 (/sbin/launchd)\n"

func unmountTarget() *AttachedVolume {
	return &AttachedVolume{Name: "Reserved", UUID: "E7A841BD-6244-485B-BDEF-587971DA5FE6", Dev: "/dev/disk12s1", Mount: "/native/Reserved"}
}

func unmountInventory(volume *AttachedVolume) map[string]any {
	return map[string]any{"VolumeName": volume.Name, "VolumeUUID": volume.UUID, "DeviceNode": volume.Dev}
}

func unmountCommander(t *testing.T, volume *AttachedVolume, results ...Result) *fakeCommander {
	t.Helper()
	if volume.Mount != "" {
		volume.Mount = t.TempDir()
	}
	data, err := json.Marshal(unmountInventory(volume))
	if err != nil {
		t.Fatal(err)
	}
	var sequence []Result
	for i, result := range results {
		if i != 0 {
			sequence = append(sequence, Result{}) // Native identity before another unmount.
		}
		sequence = append(sequence, result)
	}
	return &fakeCommander{sequence: map[string][]Result{"diskutil": sequence}, results: map[string]Result{"plutil": {Stdout: data}}}
}

func unmountDisk(commander Commander, volume *AttachedVolume) *HostDisk {
	identity := mountIdentity{MountPoint: volume.Mount, Source: volume.Dev, FSID: [2]int32{41, 7}}
	return &HostDisk{C: commander, T: &Transcript{}, mountProbe: func(string) (mountIdentity, error) { return identity, nil }}
}

func unmountCalls(commander *fakeCommander) int {
	n := 0
	for _, argv := range commander.calls {
		if len(argv) > 1 && argv[0] == "diskutil" && argv[1] == "unmount" {
			n++
		}
	}
	return n
}

func TestUnmountWaitsForCapturedTimeMachineDissentAndConfirmsIdentity(t *testing.T) {
	for _, stderr := range []string{capturedBackupDissent, strings.Split(capturedBackupDissent, "\n")[0] + "\n"} {
		t.Run(stderr, func(t *testing.T) {
			instantWaits(t)
			volume := unmountTarget()
			dissent := Result{Status: 1, Stderr: []byte(stderr)}
			commander := unmountCommander(t, volume, dissent, dissent, Result{})
			disk := unmountDisk(commander, volume)
			if err := disk.Unmount(context.Background(), volume); err != nil {
				t.Fatal(err)
			}
			if volume.Mount != "" {
				t.Fatal("successful normal unmount did not clear mounted state")
			}
			want := [][]string{
				{"diskutil", "unmount", volume.Dev},
				{"diskutil", "info", "-plist", volume.Dev}, {"plutil", "-convert", "json", "-o", "-", "-"},
				{"diskutil", "unmount", volume.Dev},
				{"diskutil", "info", "-plist", volume.Dev}, {"plutil", "-convert", "json", "-o", "-", "-"},
				{"diskutil", "unmount", volume.Dev},
			}
			if !reflect.DeepEqual(commander.calls, want) {
				t.Fatalf("unmount must confirm the original identity before every additional attempt, without force: %v", commander.calls)
			}
			var attempts, waits int
			for _, command := range disk.T.Commands {
				switch command.Label {
				case "unmount":
					attempts++
					if command.Expected != "record" || attempts < 3 && (command.Status != "1" || command.StderrText != stderr) || attempts == 3 && command.Status != "0" {
						t.Fatalf("unmount attempt lost its native outcome: %+v", command)
					}
				case "wait:unmount-backup-dissent":
					waits++
					if command.Status != "retry" || !strings.Contains(command.StderrText, strings.TrimSpace(stderr)) {
						t.Fatalf("wait lost its exact native dissent reason: %+v", command)
					}
				}
			}
			if attempts != 3 || waits != 2 {
				t.Fatalf("every attempt and wait must be recorded: attempts=%d waits=%d", attempts, waits)
			}
		})
	}
}

func TestUnmountDoesNotWaitForUnidentifiedDissentOrStorageFailures(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result Result
	}{
		{"generic failure", Result{Status: 1, Stderr: []byte("Volume Reserved on disk12s1 failed to unmount\n")}},
		{"pressure boundary failure", Result{Status: 1, Stderr: []byte("Volume Reserved on disk10s1 failed to unmount\n")}},
		{"no space", Result{Status: 1, Stderr: []byte("No space left on device")}},
		{"input output", Result{Status: 1, Stderr: []byte("Input/output error")}},
		{"other process", Result{Status: 1, Stderr: []byte(strings.ReplaceAll(capturedBackupDissent, "/System/Library/CoreServices/TimeMachine/backupd-helper", "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"))}},
		{"process basename", Result{Status: 1, Stderr: []byte(strings.ReplaceAll(capturedBackupDissent, "/System/Library/CoreServices/TimeMachine/backupd-helper", "backupd-helper"))}},
		{"other process path", Result{Status: 1, Stderr: []byte(strings.ReplaceAll(capturedBackupDissent, "/System/Library/CoreServices/TimeMachine/backupd-helper", "/tmp/backupd-helper"))}},
		{"other device", Result{Status: 1, Stderr: []byte(strings.ReplaceAll(capturedBackupDissent, "disk12s1", "disk15s1"))}},
		{"other volume", Result{Status: 1, Stderr: []byte(strings.ReplaceAll(capturedBackupDissent, "Reserved", "Secondary"))}},
		{"missing PID", Result{Status: 1, Stderr: []byte(strings.ReplaceAll(capturedBackupDissent, "PID 311", "PID"))}},
		{"different status", Result{Status: 5, Stderr: []byte(capturedBackupDissent)}},
		{"storage error after dissent", Result{Status: 1, Stderr: []byte(capturedBackupDissent + "No space left on device\n")}},
		{"storage error on stdout", Result{Status: 1, Stderr: []byte(capturedBackupDissent), Stdout: []byte("No space left on device\n")}},
		{"deadline", Result{Status: 1, Stderr: []byte(capturedBackupDissent), Err: context.DeadlineExceeded}},
		{"cancelled", Result{Status: 1, Stderr: []byte(capturedBackupDissent), Err: context.Canceled}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ceilings := instantWaits(t)
			volume := unmountTarget()
			commander := unmountCommander(t, volume, tc.result, Result{})
			disk := unmountDisk(commander, volume)
			err := disk.Unmount(context.Background(), volume)
			if err == nil || unmountCalls(commander) != 1 || len(commander.calls) != 1 || len(*ceilings) != 0 || volume.Mount == "" {
				t.Fatalf("terminal failure was retried or cleared mounted state: err=%v calls=%v waits=%v mount=%q", err, commander.calls, *ceilings, volume.Mount)
			}
			if tc.result.Err != nil && !errors.Is(err, tc.result.Err) {
				t.Fatalf("command failure lost its original cause: %v", err)
			}
		})
	}
}

func TestUnmountStopsWhenStorageFailsAfterIdentifiedDissent(t *testing.T) {
	instantWaits(t)
	volume := unmountTarget()
	commander := unmountCommander(t, volume, Result{Status: 1, Stderr: []byte(capturedBackupDissent)}, Result{Status: 1, Stderr: []byte("No space left on device")}, Result{})
	disk := unmountDisk(commander, volume)
	if err := disk.Unmount(context.Background(), volume); err == nil || !strings.Contains(err.Error(), "No space left on device") || unmountCalls(commander) != 2 || volume.Mount == "" {
		t.Fatalf("storage failure after dissent was retried or suppressed: %v, calls=%v", err, commander.calls)
	}
}

func TestUnmountRefusesReusedOrUnidentifiedDeviceBeforeAnotherAttempt(t *testing.T) {
	for _, field := range []string{"VolumeUUID", "VolumeName", "DeviceNode", "missing UUID", "missing initial UUID"} {
		t.Run(field, func(t *testing.T) {
			instantWaits(t)
			volume := unmountTarget()
			inventory := unmountInventory(volume)
			switch field {
			case "missing UUID":
				delete(inventory, "VolumeUUID")
			case "missing initial UUID":
				volume.UUID = ""
			default:
				inventory[field] = "another volume"
			}
			data, err := json.Marshal(inventory)
			if err != nil {
				t.Fatal(err)
			}
			commander := unmountCommander(t, volume, Result{Status: 1, Stderr: []byte(capturedBackupDissent)}, Result{})
			commander.results["plutil"] = Result{Stdout: data}
			disk := unmountDisk(commander, volume)
			if err := disk.Unmount(context.Background(), volume); err == nil || unmountCalls(commander) != 1 || volume.Mount == "" {
				t.Fatalf("changed or missing identity permitted another unmount: %v, calls=%v", err, commander.calls)
			}
		})
	}
}

func TestUnmountRequiresIdentityProbeSuccessBeforeAnotherAttempt(t *testing.T) {
	instantWaits(t)
	volume := unmountTarget()
	commander := unmountCommander(t, volume, Result{Status: 1, Stderr: []byte(capturedBackupDissent)}, Result{})
	commander.sequence["diskutil"][1] = Result{Status: 1, Stderr: []byte("cannot inspect device")}
	disk := unmountDisk(commander, volume)
	if err := disk.Unmount(context.Background(), volume); err == nil || !strings.Contains(err.Error(), "cannot inspect device") || unmountCalls(commander) != 1 || volume.Mount == "" {
		t.Fatalf("failed identity observation permitted another unmount: %v, calls=%v", err, commander.calls)
	}
}

func TestUnmountFailsAfterTheKnownDissentBudgetIsSpent(t *testing.T) {
	ceilings := instantWaits(t)
	volume := unmountTarget()
	var results []Result
	for range BusyWait.Attempts {
		results = append(results, Result{Status: 1, Stderr: []byte(capturedBackupDissent)})
	}
	commander := unmountCommander(t, volume, results...)
	disk := unmountDisk(commander, volume)
	err := disk.Unmount(context.Background(), volume)
	var spent *NotSettledError
	if !errors.As(err, &spent) || spent.Checks != BusyWait.Attempts || unmountCalls(commander) != BusyWait.Attempts || len(*ceilings) != BusyWait.Attempts-1 || volume.Mount == "" {
		t.Fatalf("known dissent exceeded its bounded wait or cleared mounted state: %v, calls=%v waits=%v", err, commander.calls, *ceilings)
	}
}

func TestUnmountStopsForCancellationAndExpiredDeadline(t *testing.T) {
	for _, deadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancelled", true: "deadline"}[deadline], func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			want := context.Canceled
			if deadline {
				cancel()
				ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				want = context.DeadlineExceeded
			} else {
				cancel()
			}
			defer cancel()
			volume := unmountTarget()
			commander := unmountCommander(t, volume, Result{})
			disk := unmountDisk(commander, volume)
			if err := disk.Unmount(ctx, volume); !errors.Is(err, want) || len(commander.calls) != 0 || volume.Mount == "" {
				t.Fatalf("ended context reached unmount or lost its cause: %v, calls=%v", err, commander.calls)
			}
		})
	}
}

func TestUnmountCancellationDuringDissentWaitPreventsAnotherAttempt(t *testing.T) {
	instantWaits(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sleep = func(context.Context, time.Duration) error { cancel(); return ctx.Err() }
	volume := unmountTarget()
	commander := unmountCommander(t, volume, Result{Status: 1, Stderr: []byte(capturedBackupDissent)}, Result{})
	disk := unmountDisk(commander, volume)
	if err := disk.Unmount(ctx, volume); !errors.Is(err, context.Canceled) || len(commander.calls) != 1 || volume.Mount == "" {
		t.Fatalf("cancelled wait reached another command or lost its cause: %v, calls=%v", err, commander.calls)
	}
}

func TestUnmountSuccessDoesNotRequestAnotherNativeCommandOrWait(t *testing.T) {
	ceilings := instantWaits(t)
	volume := unmountTarget()
	commander := unmountCommander(t, volume, Result{})
	disk := unmountDisk(commander, volume)
	if err := disk.Unmount(context.Background(), volume); err != nil || len(commander.calls) != 1 || len(*ceilings) != 0 || volume.Mount != "" {
		t.Fatalf("ordinary success changed command policy or retained mounted state: %v, calls=%v", err, commander.calls)
	}
}

func TestUnmountDissentRequiresTheSameCanonicalMountIdentity(t *testing.T) {
	for _, state := range []string{"source changed", "fsid changed", "pin changed", "probe failure", "cancelled probe failure", "gone"} {
		t.Run(state, func(t *testing.T) {
			instantWaits(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			volume := unmountTarget()
			commander := unmountCommander(t, volume, Result{Status: 1, Stderr: []byte(capturedBackupDissent)}, Result{})
			disk := unmountDisk(commander, volume)
			original, _ := disk.mountProbe(volume.Mount)
			cause := errors.New("mount identity unavailable")
			probes := 0
			disk.mountProbe = func(string) (mountIdentity, error) {
				probes++
				if probes == 1 {
					return original, nil
				}
				identity := original
				switch state {
				case "source changed":
					identity.Source = "/dev/disk99s1"
				case "fsid changed":
					identity.FSID[0]++
				case "pin changed":
					identity.MountPoint = t.TempDir()
				case "probe failure":
					return mountIdentity{}, cause
				case "cancelled probe failure":
					cancel()
					return mountIdentity{}, cause
				case "gone":
					identity.MountPoint = filepath.Dir(original.MountPoint)
					identity.Source = "enclosing host filesystem"
					identity.FSID[0]++
				}
				return identity, nil
			}
			err := disk.Unmount(ctx, volume)
			if unmountCalls(commander) != 1 || probes != 2 {
				t.Fatalf("mount identity change permitted another unmount: %v, calls=%v probes=%d", err, commander.calls, probes)
			}
			if state == "gone" {
				if err != nil || volume.Mount != "" {
					t.Fatalf("missing original pin was not recorded as closed: %v mount=%q", err, volume.Mount)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), strings.TrimSpace(capturedBackupDissent)) || volume.Mount == "" {
				t.Fatalf("identity failure lost the original dissent or cleared the mount: %v", err)
			}
			if strings.Contains(state, "probe failure") && !errors.Is(err, cause) {
				t.Fatal("mount probe cause lost", err)
			}
			if state == "cancelled probe failure" && !errors.Is(err, context.Canceled) {
				t.Fatal("mount probe cancellation lost", err)
			}
		})
	}
}

func TestUnmountDissentWithoutAnInitialMountPinRemainsFatal(t *testing.T) {
	volume := unmountTarget()
	volume.Mount = ""
	commander := unmountCommander(t, volume, Result{Status: 1, Stderr: []byte(capturedBackupDissent)}, Result{})
	disk := unmountDisk(commander, volume)
	if err := disk.Unmount(context.Background(), volume); err == nil || unmountCalls(commander) != 1 {
		t.Fatalf("unbound native dissent was retried: %v, calls=%v", err, commander.calls)
	}
}

func TestUnmountRefusesAnInitialPinMountedFromAnotherDevice(t *testing.T) {
	volume := unmountTarget()
	commander := unmountCommander(t, volume, Result{})
	disk := unmountDisk(commander, volume)
	identity, _ := disk.mountProbe(volume.Mount)
	identity.Source = "/dev/disk99s1"
	disk.mountProbe = func(string) (mountIdentity, error) { return identity, nil }
	if err := disk.Unmount(context.Background(), volume); err == nil || len(commander.calls) != 0 {
		t.Fatalf("foreign initial mount was unmounted: %v, calls=%v", err, commander.calls)
	}
}

type unmountInfoFailureCommander struct {
	*fakeCommander
	cancel context.CancelFunc
	cause  error
}

func (c *unmountInfoFailureCommander) Run(ctx context.Context, command Command) Result {
	if command.Label == "info" {
		c.calls = append(c.calls, command.Argv)
		c.cancel()
		return Result{Status: -1, Err: c.cause}
	}
	return c.fakeCommander.Run(ctx, command)
}

func TestUnmountPreservesDissentAndCancellationWhenVolumeIdentityFails(t *testing.T) {
	instantWaits(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	volume := unmountTarget()
	base := unmountCommander(t, volume, Result{Status: 1, Stderr: []byte(capturedBackupDissent)}, Result{})
	cause := errors.New("volume identity unavailable")
	commander := &unmountInfoFailureCommander{fakeCommander: base, cancel: cancel, cause: cause}
	disk := unmountDisk(commander, volume)
	err := disk.Unmount(ctx, volume)
	if !errors.Is(err, cause) || !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), strings.TrimSpace(capturedBackupDissent)) || unmountCalls(base) != 1 || volume.Mount == "" {
		t.Fatalf("failed native identity lost a cause or permitted another unmount: %v, calls=%v", err, base.calls)
	}
}
