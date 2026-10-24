package fixture

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var (
	backupDissenterPID    = regexp.MustCompile(`^[1-9][0-9]* \(/System/Library/CoreServices/TimeMachine/backupd-helper\)$`)
	backupDissenterParent = regexp.MustCompile(`^Dissenter parent PPID [1-9][0-9]* \(/sbin/launchd\)$`)
)

// Unmount waits only for an explicit Time Machine helper approval dissent.
// An approval refusal precedes unmounting; it is not an allocation or filesystem
// verdict. Every other failure is terminal, including unidentified dissent.
func (d *HostDisk) Unmount(ctx context.Context, volume *AttachedVolume) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	target := *volume
	var pin string
	var original *mountIdentity
	if target.Mount != "" {
		var err error
		pin, err = canonicalMountPath(target.Mount)
		if err != nil {
			return err
		}
		identity, _, err := d.privateMountIdentity(ctx, "volume", pin, nil)
		if err != nil {
			return err
		}
		if identity.Source != target.Dev {
			return fmt.Errorf("refuse unmount of %s: private mount %q belongs to %q", target.Dev, pin, identity.Source)
		}
		original = &identity
	}
	attempts := 0
	var dissent error
	err := Settle(ctx, d.T, "unmount-backup-dissent", BusyWait, func() (bool, string, error) {
		if err := ctx.Err(); err != nil {
			return false, "", err
		}
		if attempts != 0 {
			_, gone, err := d.privateMountIdentity(ctx, "volume", pin, original)
			if err != nil {
				return false, "", errors.Join(dissent, err, ctx.Err())
			}
			if gone {
				volume.Mount = ""
				return true, "", nil
			}
			if err := d.confirmUnmountIdentity(ctx, target); err != nil {
				return false, "", errors.Join(dissent, err, ctx.Err())
			}
		}
		if err := ctx.Err(); err != nil {
			return false, "", err
		}
		attempts++
		cmd := Command{Label: "unmount", Argv: []string{"diskutil", "unmount", target.Dev}, Expected: "record"}
		result := d.C.Run(ctx, cmd)
		commandTranscript := d.T
		commandOrdinal := len(commandTranscript.Commands)
		err := commandTranscript.Record(cmd, result)
		if ctx.Err() != nil {
			return false, "", errors.Join(err, ctx.Err())
		}
		if err != nil {
			return false, "", err
		}
		if result.Status == 0 {
			volume.priorUnmount = nil
			if original != nil {
				volume.priorUnmount = &priorUnmountIdentity{Identity: *original, Command: commandOrdinal, transcript: commandTranscript}
			}
			volume.Mount = ""
			return true, "", nil
		}
		err = fmt.Errorf("diskutil unmount %s: exit %d: %s", target.Dev, result.Status, strings.TrimSpace(string(result.Stderr)+"\n"+string(result.Stdout)))
		if original != nil && target.UUID != "" && timeMachineUnmountDissent(target, result) {
			if dissent == nil {
				dissent = err
			}
			return false, err.Error(), nil
		}
		return false, "", err
	})
	if err != nil {
		return errors.Join(dissent, err)
	}
	return nil
}

// A device number can be reused while Disk Arbitration settles. Never send a
// second unmount request until native inventory still identifies this volume.
func (d *HostDisk) confirmUnmountIdentity(ctx context.Context, target AttachedVolume) error {
	info, err := d.Info(ctx, target.Dev)
	if err != nil {
		return fmt.Errorf("confirm volume identity before unmounting %s again: %w", target.Dev, err)
	}
	uuid, _ := info["VolumeUUID"].(string)
	name, _ := info["VolumeName"].(string)
	dev, _ := info["DeviceNode"].(string)
	if !strings.EqualFold(uuid, target.UUID) || name != target.Name || dev != target.Dev {
		return fmt.Errorf("refuse another unmount of %s: native volume identity changed from %q (%s) to %q (%s) on %q", target.Dev, target.Name, target.UUID, name, uuid, dev)
	}
	return nil
}

func timeMachineUnmountDissent(volume AttachedVolume, result Result) bool {
	if result.Err != nil || result.Status != 1 || volume.Name == "" || volume.Dev == "" {
		return false
	}
	// Match complete captured lines, not a process-name substring inside a
	// different failure. Extra diagnostics, including storage errors, are fatal.
	text := strings.TrimSpace(string(result.Stderr) + "\n" + string(result.Stdout))
	lines := strings.Split(text, "\n")
	if len(lines) < 1 || len(lines) > 2 {
		return false
	}
	prefix := "Volume " + volume.Name + " on " + strings.TrimPrefix(volume.Dev, "/dev/") + " failed to unmount: dissented by PID "
	if !strings.HasPrefix(lines[0], prefix) || !backupDissenterPID.MatchString(strings.TrimPrefix(lines[0], prefix)) {
		return false
	}
	return len(lines) == 1 || backupDissenterParent.MatchString(lines[1])
}
