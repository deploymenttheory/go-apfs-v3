//go:build native && darwin

package native

import (
	"context"
	"encoding/json"
	"fmt"
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
			err := v.checkEncryptedVolumes(ctx, raw, nil, &expected, recipe)
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
