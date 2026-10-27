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
	"github.com/deploymenttheory/go-apfs-v3/apfs"
	"github.com/deploymenttheory/go-apfs-v3/imageedit"
)

// Diagnostic only: the actual plaintext continuation followed by a fresh
// encryption retaining the UUID. Original native images are unchanged.
func TestEncryptedVolumeCredentialLockState(t *testing.T) {
	v := newVerifier(t)
	ctx := context.Background()
	ref := schema.CaseRef{Producer: v.Major, Recipe: "encrypted-snapshot-history", Profile: "apfs", Stage: "aes256-nested"}
	warm := probeVolumeConversion(t, v, ref, "warm-plaintext")
	encryptedRef := ref
	encryptedRef.Stage = "decrypted"
	reencrypted := probeVolumeConversion(t, v, encryptedRef, "reencrypted")
	diffs, err := v.VerifyOutput(ctx, warm)
	if err != nil || len(diffs) != 0 {
		t.Fatal("plaintext native verification", diffs, err)
	}
	if _, err := v.Continuation(ctx, warm, schemaCase{recipe: v.Recipes[ref.Recipe]}); err != nil {
		t.Fatal("plaintext native/Go/native continuation", err)
	}
	ref = encryptedRef
	image := filepath.Join(reencrypted.Dirs["darwin"], reencrypted.Output.File)
	transcript := &fixture.Transcript{}
	v.setTranscript(transcript)
	att, err := v.Disk.Attach(ctx, image, fixture.AttachOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := v.Disk.Detach(ctx, att); err != nil {
			t.Error(err)
		}
		probeJSON(t, v.Work, "commands.json", transcript.Commands)
	}()
	volume := att.Volume("EncryptedHistory")
	if volume == nil {
		t.Fatal("missing selected retained volume")
	}
	recipe := v.Recipes[ref.Recipe]
	after := ref
	after.Stage = "converted"
	unlock, rejected := volumeCredentials(v.Cases[CaseKey(after)].Observation)
	spec := schema.ObserveSpec{Unlock: unlock, Rejected: rejected, Snapshots: true, Checks: []string{"verify", "fsck"}}
	input := fixture.ObserveInput{Recipe: &recipe, Profile: schema.Profile{ID: "apfs"}, Stage: "re-encryption-lock-probe", Spec: spec, Image: image, Format: "UDZO", Att: att, Disk: v.Disk, Vol: v.Vol, Vars: &fixture.Vars{Passwords: recipe.Passwords}, T: transcript, Work: filepath.Join(v.Work, "probe"), Out: filepath.Join(v.Work, "exports"), Prefix: "re-encryption-lock-probe", Producer: v.Producer, OmitDeviceDigest: true}
	_, observeErr := fixture.Observe(ctx, input)
	probeJSON(t, v.Work, "initial-observation.json", map[string]any{"error": fmt.Sprint(observeErr), "commands": transcript.Commands})
	if observeErr == nil {
		t.Log("actual observer completed strict credentials, retained-history and per-volume checks after plaintext continuation")
		return
	}
	t.Error("actual observer", observeErr)
	for _, delay := range []time.Duration{0, time.Second, 3 * time.Second} {
		if delay != 0 {
			time.Sleep(delay)
		}
		info, err := v.Disk.Info(ctx, volume.Dev)
		probeJSON(t, v.Work, fmt.Sprintf("lock-state-after-%d.json", int(delay/time.Second)), map[string]any{"info": info, "error": fmt.Sprint(err)})
	}
	mountErr := v.Disk.Mount(ctx, volume, "owners", "", false)
	probeJSON(t, v.Work, "mount-before-authentication.json", map[string]any{"error": fmt.Sprint(mountErr)})
	if mountErr != nil {
		cmd := fixture.Command{Label: "probe-authenticate", Argv: []string{"diskutil", "apfs", "unlockVolume", volume.Dev, "-stdinpassphrase", "-nomount"}, Stdin: []byte(recipe.Passwords[unlock[volume.Name]] + "\n"), Expected: "record"}
		if err := transcript.Record(cmd, v.C.Run(ctx, cmd)); err != nil {
			t.Error(err)
		}
		mountErr = v.Disk.Mount(ctx, volume, "owners", "", false)
		probeJSON(t, v.Work, "mount-after-authentication.json", map[string]any{"error": fmt.Sprint(mountErr)})
	}
	if mountErr == nil {
		cmd := fixture.Command{Label: "probe-lock-mounted", Argv: []string{"diskutil", "apfs", "lockVolume", volume.Dev}, Expected: "record"}
		if err := transcript.Record(cmd, v.C.Run(ctx, cmd)); err != nil {
			t.Error(err)
		}
		info, err := v.Disk.Info(ctx, volume.Dev)
		probeJSON(t, v.Work, "state-after-mounted-lock.json", map[string]any{"info": info, "error": fmt.Sprint(err)})
	}
}

func probeVolumeConversion(t *testing.T, v *Verifier, ref schema.CaseRef, label string) Paired {
	t.Helper()
	before := v.Cases[CaseKey(ref)]
	if before.Observation == nil || before.Observation.Image.PartitionMap != "GPT" {
		t.Fatal("missing original GPT history source", ref)
	}
	selected, target, encrypt, err := VolumeConversionTarget(ref)
	if err != nil {
		t.Fatal(err)
	}
	options := imageedit.Options{Format: "UDZO", Partition: 1, Time: time.Unix(1700000000, 0).UTC()}
	recipe := v.Recipes[ref.Recipe]
	if before.Observation.Image.Encryption != nil {
		options.ImagePassword = []byte(recipe.Passwords[before.Observation.Image.Encryption.Password])
	}
	for _, vol := range before.Observation.Volumes {
		if volumeName(vol) == selected {
			options.Volume = vol.APFS.VolumeUUID
		}
		if !vol.APFS.Encrypted {
			continue
		}
		password := []byte(recipe.Passwords[vol.APFS.Password])
		if volumeName(vol) == selected {
			options.VolumePassword = password
		} else {
			options.VolumeCredentials = append(options.VolumeCredentials, apfs.VolumeCredential{VolumeUUID: vol.APFS.VolumeUUID, Password: password})
		}
	}
	conversion := apfs.EncryptionConversion{Encrypt: encrypt}
	if encrypt {
		after := ref
		after.Stage = target
		for _, vol := range v.Cases[CaseKey(after)].Observation.Volumes {
			if volumeName(vol) == selected {
				conversion.Password = []byte(recipe.Passwords[vol.APFS.Password])
			}
		}
	}
	lease, err := v.Corpus.AcquireImage(context.Background(), before)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(v.Work, "generated")
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, label+".dmg")
	_, convertErr := imageedit.ConvertVolumeEncryption(context.Background(), lease.Path(), path, options, conversion)
	releaseErr := lease.Release(nil)
	if convertErr != nil || releaseErr != nil {
		t.Fatal(convertErr, releaseErr)
	}
	digest, err := schema.FileDigest(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	out := schema.Output{Name: label, File: filepath.Base(path), SHA256: digest, Bytes: stat.Size(), Operation: "convert-volume", Format: "UDZO", Source: ref, Expect: schema.Expectation{View: target, Volume: selected, Continuation: true}}
	passwords := map[string]string{}
	if options.ImagePassword != nil {
		out.Encrypted, out.Password = true, "encrypted-snapshot-history.image"
		passwords[out.Password] = string(options.ImagePassword)
	}
	probeJSON(t, v.Work, label+"-scope.json", map[string]any{"scope": "Diagnostic one producer/APFS history sequence only; no complete corpus or gate verdict", "source": ref, "originalImageSHA256": before.Observation.Image.SHA256, "output": out})
	return Paired{Name: label, Output: out, Primary: "darwin", ByHost: map[string]schema.Output{"darwin": out}, Dirs: map[string]string{"darwin": dir}, Passwords: passwords}
}

// Establish the exact recorded API state using only an untouched Apple image:
// correct unlock with -nomount, then call the original credential observer.
func TestNativeUnlockedUnmountedCredentialProbe(t *testing.T) {
	v := newVerifier(t).ForSubtest()
	ctx := context.Background()
	ref := schema.CaseRef{Producer: v.Major, Recipe: "encrypted-snapshot-history", Profile: "apfsx", Stage: "retained-again"}
	before := v.Cases[CaseKey(ref)]
	recipe := v.Recipes[ref.Recipe]
	lease, err := v.Corpus.AcquireImage(ctx, before)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := lease.Release(nil); err != nil {
			t.Error(err)
		}
	}()
	tr := &fixture.Transcript{}
	v.setTranscript(tr)
	att, err := v.Disk.Attach(ctx, lease.Path(), fixture.AttachOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := v.Disk.Detach(ctx, att); err != nil {
			t.Error(err)
		}
		probeJSON(t, v.Work, "known-unmounted-commands.json", tr.Commands)
	}()
	vol := att.Volume("EncryptedHistory")
	if vol == nil {
		t.Fatal("native encrypted control missing")
	}
	unlock, rejected := volumeCredentials(before.Observation)
	cmd := fixture.Command{Label: "known-native-unlock-nomount", Argv: []string{"diskutil", "apfs", "unlockVolume", vol.Dev, "-stdinpassphrase", "-nomount"}, Stdin: []byte(recipe.Passwords[unlock[vol.Name]] + "\n"), Expected: "0"}
	if err := tr.Record(cmd, v.C.Run(ctx, cmd)); err != nil {
		t.Fatal(err)
	}
	info, err := v.Disk.Info(ctx, vol.Dev)
	probeJSON(t, v.Work, "known-native-unmounted-state.json", map[string]any{"info": info, "error": fmt.Sprint(err), "source": ref, "originalImageSHA256": before.Observation.Image.SHA256})
	input := fixture.ObserveInput{Recipe: &recipe, Profile: schema.Profile{ID: "apfsx"}, Stage: "known-native-unmounted", Spec: schema.ObserveSpec{Unlock: unlock, Rejected: rejected, Snapshots: true, Checks: []string{"verify", "fsck"}}, Image: lease.Path(), Format: "UDZO", Att: att, Disk: v.Disk, Vol: v.Vol, Vars: &fixture.Vars{Passwords: recipe.Passwords}, T: tr, Work: filepath.Join(v.Work, "known-probe"), Out: filepath.Join(v.Work, "exports"), Prefix: "known-native-unmounted", Producer: v.Producer, OmitDeviceDigest: true}
	_, observeErr := fixture.Observe(ctx, input)
	probeJSON(t, v.Work, "known-native-observation.json", map[string]any{"error": fmt.Sprint(observeErr), "commands": tr.Commands})
	if observeErr == nil {
		t.Log("observer handled known native unlock-nomount state")
		return
	}
	t.Error("known native unmounted observer", observeErr)
	for _, delay := range []time.Duration{time.Second, 3 * time.Second} {
		time.Sleep(delay)
		info, err := v.Disk.Info(ctx, vol.Dev)
		probeJSON(t, v.Work, fmt.Sprintf("known-state-after-%d.json", int(delay/time.Second)), map[string]any{"info": info, "error": fmt.Sprint(err)})
	}
	mountErr := v.Disk.Mount(ctx, vol, "owners", "", false)
	probeJSON(t, v.Work, "known-native-mount.json", map[string]any{"error": fmt.Sprint(mountErr)})
	if mountErr != nil {
		return
	}
	cmd = fixture.Command{Label: "known-native-mounted-lock", Argv: []string{"diskutil", "apfs", "lockVolume", vol.Dev}, Expected: "0"}
	if err := tr.Record(cmd, v.C.Run(ctx, cmd)); err != nil {
		t.Fatal(err)
	}
	info, err = v.Disk.Info(ctx, vol.Dev)
	probeJSON(t, v.Work, "known-native-mounted-lock-state.json", map[string]any{"info": info, "error": fmt.Sprint(err)})
	_, afterErr := fixture.Observe(ctx, input)
	probeJSON(t, v.Work, "known-native-after-mount-and-lock.json", map[string]any{"error": fmt.Sprint(afterErr)})
	if afterErr != nil {
		t.Error("native original strict checks after mounted lock", afterErr)
	}
}

func probeJSON(t *testing.T, root, name string, value any) {
	t.Helper()
	data, err := json.MarshalIndent(value, "", "  ")
	if err == nil {
		err = os.WriteFile(filepath.Join(root, name), append(data, '\n'), 0600)
	}
	if err != nil {
		t.Error(err)
	}
}
