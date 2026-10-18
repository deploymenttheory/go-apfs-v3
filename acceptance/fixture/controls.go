package fixture

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// runControl performs the capture-tool procedures a recipe cannot express
// as one program. Interruption procedures arrive with #108.
func (c *Capture) runControl(ctx context.Context, ctl *schema.ControlStep) error {
	switch ctl.Action {
	case "asr-snapshot":
		return c.asrSnapshot(ctx, ctl.Name)
	case "settle-encryption":
		return c.settleEncryption(ctx, ctl.Name, ctl.Params["fileVault"] == "true")
	case "free-space-sentinel":
		return c.freeSpaceSentinel(ctl.Name)
	case "snapshot-api":
		return c.snapshotAPI(ctx, ctl.Params)
	case "journal-window", "replay-journal", "checkpoint-window", "damage", "pause-helper", "resume-helper", "retain-device":
		return fmt.Errorf("control %s is not implemented until the interruption fixtures issue lands", ctl.Action)
	}
	return fmt.Errorf("unknown control %q", ctl.Action)
}

// asrSnapshot replicates the first mounted volume with asr to a disposable
// target. asr creates a com.apple.asr.<pid> snapshot on the source for the
// duration of the copy; mounting that snapshot pins it so it survives. The
// mount is attempted repeatedly until the snapshot exists, asr must then
// finish successfully, and the snapshot must still be listed afterwards.
func (c *Capture) asrSnapshot(ctx context.Context, name string) error {
	source := c.att.Volumes[0]
	if source.Mount == "" {
		return errors.New("asr-snapshot: source volume is not mounted")
	}
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		target := filepath.Join(c.Work, fmt.Sprintf("asr-target-%s-%d.dmg", sanitize(name), attempt))
		if err := c.Disk.CreateImage(ctx, target, "128m", "GPTSPUD", "APFS", "", "asr-target"); err != nil {
			lastErr = err
			if strings.Contains(err.Error(), "Resource busy") {
				time.Sleep(time.Second)
				continue
			}
			return err
		}
		snapshot, err := c.asrAttempt(ctx, name, source, target, attempt)
		if err == nil {
			c.snapshots[name] = snapshot
			c.vars.SetKeyed("SNAPSHOT", name, snapshot)
			return nil
		}
		lastErr = err
	}
	return fmt.Errorf("asr-snapshot %s: %w", name, lastErr)
}

func (c *Capture) asrAttempt(ctx context.Context, name string, source *AttachedVolume, target string, attempt int) (string, error) {
	att, err := c.Disk.Attach(ctx, target, AttachOptions{})
	if err != nil {
		return "", err
	}
	defer func() { _ = c.Disk.Detach(ctx, att) }()
	tmount := filepath.Join(c.Work, "asr-target-mount")
	if err := c.Disk.Mount(ctx, att.Volumes[0], "owners", tmount, false); err != nil {
		return "", err
	}
	defer func() { _ = c.Disk.Unmount(ctx, att.Volumes[0]) }()
	asr := exec.CommandContext(ctx, "/usr/sbin/asr", "restore", "--source", source.Mount, "--target", tmount, "--erase", "--noprompt")
	var stderr strings.Builder
	asr.Stderr = &stderr
	start := time.Now()
	if err := asr.Start(); err != nil {
		return "", err
	}
	snapshot := fmt.Sprintf("com.apple.asr.%d", asr.Process.Pid)
	pin := filepath.Join(c.Work, "asr-pin", sanitize(name))
	pinned := false
	retries := 0
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if err := c.Disk.MountSnapshot(ctx, snapshot, source.Mount, pin); err == nil {
			pinned = true
			break
		}
		retries++
		time.Sleep(5 * time.Millisecond)
	}
	waitErr := asr.Wait()
	entry := schema.Command{Label: "asr-snapshot:" + name, Argv: asr.Args, Expected: "0", Status: "0", WallNS: time.Since(start).Nanoseconds(), StderrText: fmt.Sprintf("attempt %d, mount retries %d", attempt, retries)}
	if waitErr != nil {
		entry.Status = "1"
		entry.StderrText += "; " + strings.TrimSpace(stderr.String())
	}
	c.t.Commands = append(c.t.Commands, entry)
	if pinned {
		if err := c.Disk.UnmountPath(ctx, pin); err != nil {
			return "", err
		}
	}
	if waitErr != nil {
		return "", fmt.Errorf("asr restore failed: %w", waitErr)
	}
	if !pinned {
		return "", fmt.Errorf("snapshot %s was never mounted before asr finished", snapshot)
	}
	snaps, err := c.Disk.Snapshots(ctx, source.Dev)
	if err != nil {
		return "", err
	}
	for _, s := range snaps {
		if n, _ := s["SnapshotName"].(string); n == snapshot {
			return snapshot, nil
		}
	}
	return "", fmt.Errorf("snapshot %s not listed after asr completed", snapshot)
}

// settleEncryption waits until diskutil reports the volume's crypto
// migration finished with the expected FileVault state.
func (c *Capture) settleEncryption(ctx context.Context, volume string, fileVault bool) error {
	vol := c.att.Volume(volume)
	if vol == nil {
		return fmt.Errorf("settle-encryption: unknown volume %q", volume)
	}
	deadline := time.Now().Add(90 * time.Second)
	for {
		info, err := c.Disk.Info(ctx, vol.Dev)
		if err != nil {
			return err
		}
		migrating, _ := info["CryptoMigrationOn"].(bool)
		fv, _ := info["FileVault"].(bool)
		if !migrating && fv == fileVault {
			return c.refreshVars(ctx)
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("settle-encryption %s: still migrating after 90s (FileVault=%v)", volume, fv)
		}
		time.Sleep(time.Second)
	}
}

// freeSpaceSentinel writes recognisable bytes into the first Apple_Free
// partition of the detached raw scratch image. The scratch must be a flat
// UDRW image with an Apple Partition Map, which hdiutil create -layout SPUD
// produces.
func (c *Capture) freeSpaceSentinel(name string) error {
	if c.att != nil {
		return errors.New("free-space-sentinel needs the image detached; place it after the stage's last step")
	}
	f, err := os.OpenFile(c.scratch, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	entry := make([]byte, 512)
	if _, err := f.ReadAt(entry, 512); err != nil {
		return err
	}
	if string(entry[:2]) != "PM" {
		return errors.New("free-space-sentinel: no Apple Partition Map at sector 1")
	}
	count := binary.BigEndian.Uint32(entry[4:8])
	for i := uint32(1); i <= count; i++ {
		if _, err := f.ReadAt(entry, int64(i)*512); err != nil {
			return err
		}
		ptype := strings.TrimRight(string(entry[48:80]), "\x00")
		start := int64(binary.BigEndian.Uint32(entry[8:12]))
		length := int64(binary.BigEndian.Uint32(entry[12:16]))
		if ptype != "Apple_Free" || length <= 8 {
			continue
		}
		offset := (start + 1) * 512
		payload := []byte(strings.Repeat("Allocated outside every filesystem: preserve these forensic bytes.\n", 8))[:512]
		if _, err := f.WriteAt(payload, offset); err != nil {
			return err
		}
		sum := sha256.Sum256(payload)
		c.sentinels = append(c.sentinels, schema.Sentinel{Offset: offset, Bytes: 512, SHA256: hex.EncodeToString(sum[:])})
		c.t.Commands = append(c.t.Commands, schema.Command{Label: "free-space-sentinel:" + name, Argv: []string{"sentinel", c.scratch, fmt.Sprint(offset)}, Expected: "0", Status: "0"})
		return f.Sync()
	}
	return errors.New("free-space-sentinel: no Apple_Free partition with room")
}

// snapshotAPI runs the entitled helper and records the API outcome. EPERM
// is a legitimate recorded outcome (issue #74), as is the helper being
// killed by launch policy.
func (c *Capture) snapshotAPI(ctx context.Context, params map[string]string) error {
	helper, ok := c.Helpers["apfs-snapshot"]
	if !ok {
		return errors.New("snapshot-api: helper apfs-snapshot was not built")
	}
	mount := c.att.Volumes[0].Mount
	var argv []string
	switch params["op"] {
	case "create":
		argv = []string{helper, "create", mount, params["name"]}
	case "rename":
		argv = []string{helper, "rename", mount, params["from"], params["to"]}
	case "revert":
		snap, err := c.vars.Expand(params["snapshot"])
		if err != nil {
			return err
		}
		argv = []string{helper, "revert", mount, snap}
	default:
		return fmt.Errorf("snapshot-api: unknown op %q", params["op"])
	}
	cmd := Command{Label: "snapshot-api:" + params["op"], Argv: argv, Sudo: true, Expected: "record"}
	result := c.C.Run(ctx, cmd)
	if err := c.t.Record(cmd, result); err != nil {
		return err
	}
	var outcome struct {
		API    string `json:"api"`
		Status int    `json:"status"`
		Errno  int    `json:"errno"`
	}
	if result.Status == 0 && json.Unmarshal(result.Stdout, &outcome) == nil {
		if outcome.Status == 0 || syscall.Errno(outcome.Errno) == syscall.EPERM {
			return nil
		}
		return fmt.Errorf("snapshot-api %s: status %d errno %d", params["op"], outcome.Status, outcome.Errno)
	}
	if result.Status == -1 || result.Status == 137 || result.Status == 9 {
		return nil // killed by launch policy: recorded
	}
	return fmt.Errorf("snapshot-api %s: helper exit %d", params["op"], result.Status)
}

// BuildHelpers compiles the Apple-source helpers a recipe set requires and
// returns name -> binary path.
func BuildHelpers(ctx context.Context, c Commander, helpersDir, out string, names []string) (map[string]string, error) {
	built := map[string]string{}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return nil, err
	}
	for _, name := range names {
		if _, ok := built[name]; ok {
			continue
		}
		var argv []string
		bin := filepath.Join(out, name)
		switch name {
		case "newfs_hfs_debug":
			src := filepath.Join(helpersDir, "newfs_hfs")
			include := filepath.Join(out, "include", "hfs")
			if err := os.MkdirAll(include, 0o755); err != nil {
				return nil, err
			}
			for _, h := range []string{"hfs_format.h", "hfs_mount.h", "hfs_unistr.h"} {
				if err := copyFile(filepath.Join(src, "core", h), filepath.Join(include, h), true); err != nil {
					return nil, err
				}
			}
			argv = []string{"xcrun", "clang", "-std=gnu17", "-DDEBUG_BUILD=1", "-Wno-deprecated-declarations", "-I", filepath.Join(out, "include"), "-I", src,
				filepath.Join(src, "newfs_hfs.c"), filepath.Join(src, "makehfs.c"), filepath.Join(src, "hfs_endian.c"),
				"-framework", "CoreFoundation", "-framework", "CoreServices", "-framework", "IOKit", "-lutil", "-o", bin}
		case "apfs-snapshot":
			src := filepath.Join(helpersDir, "apfs-snapshot")
			argv = []string{"xcrun", "clang", "-Wall", "-Wextra", "-Werror", "-O2", filepath.Join(src, "apfs_snapshot.c"), "-o", bin}
		default:
			return nil, fmt.Errorf("unknown helper %q", name)
		}
		result := c.Run(ctx, Command{Argv: argv, Expected: "0", Timeout: 5 * time.Minute})
		if result.Err != nil || result.Status != 0 {
			return nil, fmt.Errorf("build %s: %s", name, strings.TrimSpace(string(result.Stderr)))
		}
		if name == "apfs-snapshot" {
			sign := c.Run(ctx, Command{Argv: []string{"codesign", "--force", "--sign", "-", "--entitlements", filepath.Join(helpersDir, "apfs-snapshot", "apfs_snapshot.entitlements"), bin}, Expected: "0"})
			if sign.Err != nil || sign.Status != 0 {
				return nil, fmt.Errorf("sign %s: %s", name, strings.TrimSpace(string(sign.Stderr)))
			}
		}
		built[name] = bin
	}
	return built, nil
}
