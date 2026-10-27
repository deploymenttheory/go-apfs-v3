//go:build native && darwin

package native

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestConstructedVolumeVerificationLockState(t *testing.T) {
	if err := fixture.RequireDisposableHost(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 18*time.Minute)
	defer cancel()
	producer, err := fixture.IdentifyProducer(ctx, fixture.Exec{}, 27, "")
	if err != nil {
		t.Fatal(err)
	}
	work := os.Getenv("APFS_NATIVE_WORK")
	help := fixture.Command{Label: "native-lock-usage", Argv: []string{"diskutil", "apfs", "lockVolume"}, Expected: "record"}
	helpTranscript := &fixture.Transcript{}
	_ = helpTranscript.Record(help, (fixture.Exec{}).Run(ctx, help))
	probeJSON(t, work, "native-lock-usage.json", helpTranscript.Commands)
	raw := filepath.Join(work, "native-construction-writable.raw")
	before, err := schema.FileDigest(raw)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		after, err := schema.FileDigest(raw)
		if err != nil || before != after {
			t.Error("original payload changed", err)
		}
	}()
	data, err := os.ReadFile(filepath.Join(work, "native-construction-observation.json"))
	if err != nil {
		t.Fatal(err)
	}
	var expected schema.Observation
	if err := json.Unmarshal(data, &expected); err != nil {
		t.Fatal(err)
	}
	recipes, err := schema.LoadRecipes("../recipes")
	if err != nil {
		t.Fatal(err)
	}
	var recipe schema.Recipe
	for _, r := range recipes {
		if r.Name == "encrypted-volumes" {
			recipe = r
		}
	}
	private := filepath.Join(work, "native-construction-private.raw")
	source, err := os.Open(raw)
	if err != nil {
		t.Fatal(err)
	}
	copy, err := os.Create(private)
	if err != nil {
		source.Close()
		t.Fatal(err)
	}
	_, copyErr := io.Copy(copy, source)
	closeErr := copy.Close()
	source.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatal(copyErr, closeErr)
	}
	stop, done := make(chan struct{}), make(chan error, 1)
	go func() {
		background := &fixture.HostDisk{C: fixture.Exec{}, T: &fixture.Transcript{}}
		for {
			select {
			case <-stop:
				done <- nil
				return
			default:
			}
			att, err := background.Attach(ctx, filepath.Join(work, "background-ownership.raw"), fixture.AttachOptions{Raw: true, ReadOnly: true, NoInventory: true})
			if err != nil {
				done <- err
				return
			}
			cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), fixture.DefaultTimeout)
			err = background.Detach(cleanup, att)
			cancel()
			if err != nil {
				done <- err
				return
			}
		}
	}()
	defer func() {
		close(stop)
		if err := <-done; err != nil {
			t.Error("background image activity", err)
		}
	}()
	for i := 0; i < 30; i++ {
		t.Run(fmt.Sprintf("attachment-%d", i), func(t *testing.T) {
			c := &verificationLockProbe{work: work, attempt: i, passwords: map[string]string{}}
			for _, v := range expected.Volumes {
				if v.APFS != nil && v.APFS.Encrypted {
					c.passwords[volumeName(v)] = recipe.Passwords[v.APFS.Password]
				}
			}
			disk := &fixture.HostDisk{C: c, T: &fixture.Transcript{}}
			c.disk = disk
			v := &Verifier{Major: 27, Producer: producer, C: c, Disk: disk}
			warmErr := func() (resultErr error) {
				att, err := disk.Attach(ctx, private, fixture.AttachOptions{Raw: true})
				if err != nil {
					return err
				}
				defer func() {
					cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), fixture.DefaultTimeout)
					defer cancel()
					resultErr = errors.Join(resultErr, disk.Detach(cleanup, att))
				}()
				if err := v.unlockContinuationVolumes(ctx, att, &expected, recipe); err != nil {
					return err
				}
				for _, volume := range att.Volumes {
					if err := disk.Mount(ctx, volume, "owners,noatime", filepath.Join(work, "writable-mount", volume.Name), false); err != nil {
						return err
					}
				}
				filename := filepath.Join(att.Volume("Primary").Mount, fmt.Sprintf("verification-key-probe-%d", i))
				if err := os.WriteFile(filename, []byte("native write before read-only verification\n"), 0600); err != nil {
					return err
				}
				if err := (fixture.HostVolume{}).Fullfsync(filename); err != nil {
					return err
				}
				for _, volume := range att.Volumes {
					if err := disk.Unmount(ctx, volume); err != nil {
						return err
					}
				}
				return nil
			}()
			if warmErr != nil {
				t.Fatal(warmErr)
			}
			err := v.checkEncryptedVolumes(ctx, private, nil, &expected, recipe)
			probeJSON(t, work, fmt.Sprintf("verification-attempt-%d.json", i), map[string]any{"error": fmt.Sprint(err), "probeCommands": c.probes.Commands})
			if err != nil {
				t.Fatal("original verifier", err)
			}
		})
		if t.Failed() {
			return
		}
	}
}

type verificationLockProbe struct {
	work      string
	attempt   int
	disk      *fixture.HostDisk
	passwords map[string]string
	probes    fixture.Transcript
	captured  bool
}

func (c *verificationLockProbe) Run(ctx context.Context, cmd fixture.Command) fixture.Result {
	result := (fixture.Exec{}).Run(ctx, cmd)
	if c.captured || len(cmd.Argv) != 4 || cmd.Argv[0] != "diskutil" || cmd.Argv[2] != "lockVolume" || result.Status == 0 {
		return result
	}
	c.captured = true
	dev := cmd.Argv[3]
	native := func(label string, argv []string, stdin []byte) fixture.Result {
		command := fixture.Command{Label: label, Argv: argv, Stdin: stdin, Expected: "record"}
		r := (fixture.Exec{}).Run(ctx, command)
		_ = c.probes.Record(command, r)
		return r
	}
	for _, delay := range []time.Duration{0, time.Second, 3 * time.Second} {
		time.Sleep(delay)
		native(fmt.Sprintf("after-failed-lock-%d", delay/time.Second), []string{"diskutil", "info", "-plist", dev}, nil)
	}
	mount := native("mount-after-failed-lock", []string{"diskutil", "mount", "-mountOptions", "owners", dev}, nil)
	info, _ := c.disk.Info(ctx, dev)
	if mount.Status != 0 {
		name, _ := info["VolumeName"].(string)
		native("unlock-after-failed-lock", []string{"diskutil", "apfs", "unlockVolume", dev, "-stdinpassphrase", "-nomount"}, []byte(c.passwords[name]+"\n"))
		native("mount-after-authentication", []string{"diskutil", "mount", "-mountOptions", "owners", dev}, nil)
	}
	native("lock-after-mounted-authentication", []string{"diskutil", "apfs", "lockVolume", dev}, nil)
	native("final-lock-state", []string{"diskutil", "info", "-plist", dev}, nil)
	return result
}
