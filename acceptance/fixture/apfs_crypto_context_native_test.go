//go:build native && darwin

package fixture

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func TestAPFSCryptoContextAcrossObservationUnmount(t *testing.T) {
	if err := RequireDisposableHost(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	major, err := strconv.Atoi(os.Getenv("APFS_EXPECT_MAJOR"))
	if err != nil {
		t.Fatal(err)
	}
	producer, err := IdentifyProducer(ctx, Exec{}, major, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("native producer: %+v", producer)
	image, root := os.Getenv("APFS_CRYPTO_CONTEXT_IMAGE"), os.Getenv("APFS_NATIVE_WORK")
	if image == "" || root == "" {
		t.Fatal("explicit image and evidence paths required")
	}
	before, err := schema.FileDigest(image)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("original input SHA256=%s", before)
	for _, mode := range []string{"fresh-unlock", "observation-unmounted", "observation-unmounted-reunlocked"} {
		t.Run(mode, func(t *testing.T) {
			transcript := &Transcript{}
			disk := &HostDisk{C: Exec{}, T: transcript}
			dir := filepath.Join(root, mode)
			if err := os.MkdirAll(dir, 0700); err != nil {
				t.Fatal(err)
			}
			defer func() {
				data, err := json.MarshalIndent(transcript.Commands, "", "  ")
				if err == nil {
					err = os.WriteFile(filepath.Join(dir, "commands.json"), data, 0600)
				}
				if err != nil {
					t.Error(err)
				}
			}()
			att, err := disk.Attach(ctx, image, AttachOptions{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := disk.Detach(ctx, att); err != nil {
					t.Error(err)
				}
			}()
			unlock := func() {
				for _, volume := range att.Volumes {
					info, err := disk.Info(ctx, volume.Dev)
					if err != nil {
						t.Fatal(err)
					}
					if locked, _ := info["Locked"].(bool); !locked {
						continue
					}
					password := map[string]string{"EncryptedHistory": "public-encrypted-history-password", "EncryptedPeer": "public-independent-encrypted-history-peer"}[volume.Name]
					if password == "" {
						t.Fatal("unknown fixture credential", volume.Name)
					}
					if _, err := disk.run(ctx, "unlock", false, []byte(password+"\n"), "diskutil", "apfs", "unlockVolume", volume.Dev, "-stdinpassphrase", "-nomount"); err != nil {
						t.Fatal(err)
					}
				}
			}
			unlock()
			if mode != "fresh-unlock" {
				for _, volume := range att.Volumes {
					if err := disk.Mount(ctx, volume, "owners,noatime", "", false); err != nil {
						t.Fatal(err)
					}
					if err := disk.Unmount(ctx, volume); err != nil {
						t.Fatal(err)
					}
					info, err := disk.Info(ctx, volume.Dev)
					if err != nil {
						t.Fatal(err)
					}
					t.Logf("after unmount %s: Locked=%v FileVault=%v", volume.Name, info["Locked"], info["FileVault"])
				}
			}
			if mode == "observation-unmounted-reunlocked" {
				if err := disk.Verify(ctx, image, nil); err != nil {
					t.Fatal(err)
				}
				unlock()
			}
			for _, volume := range att.Volumes {
				output, err := disk.run(ctx, "fsck", false, nil, "diskutil", "verifyVolume", volume.Dev)
				if mode == "observation-unmounted" && volume.Name == "EncryptedHistory" {
					if err == nil || !strings.Contains(string(output), "failed to enable crypto I/O mode") {
						t.Fatalf("missing exact crypto-context failure: %v\n%s", err, output)
					}
					t.Log("reproduced original crypto-context failure after observation unmount")
					return
				}
				if err != nil {
					t.Fatalf("%v\n%s", err, output)
				}
				expected := &schema.APFSVolume{VolumeUUID: volume.UUID}
				if volume.Name == "EncryptedHistory" {
					data, err := os.ReadFile(image + ".failure.json")
					if err != nil {
						t.Fatal(err)
					}
					var original struct {
						Commands []schema.Command `json:"commands"`
					}
					if err := json.Unmarshal(data, &original); err != nil {
						t.Fatal(err)
					}
					for _, command := range original.Commands {
						if command.Label != "list-snapshots" || !strings.HasSuffix(command.Argv[len(command.Argv)-1], "s1") {
							continue
						}
						inventory, err := disk.plist(ctx, []byte(command.StdoutText))
						if err != nil {
							t.Fatal(err)
						}
						snapshots, _ := inventory["Snapshots"].([]any)
						for _, item := range snapshots {
							snap := item.(map[string]any)
							expected.Snapshots = append(expected.Snapshots, schema.Snapshot{Name: fmt.Sprint(snap["SnapshotName"]), XID: uint64(number(snap["SnapshotXID"]))})
						}
						break
					}
					if len(expected.Snapshots) == 0 {
						t.Fatal("original native snapshot inventory missing")
					}
				}
				if err := ValidateAPFSVerification(string(output), volume.RDev, expected); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	if after, err := schema.FileDigest(image); err != nil || after != before {
		t.Fatal("original capture changed", after, err)
	}
}
