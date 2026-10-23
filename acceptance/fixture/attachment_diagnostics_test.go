package fixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Synthetic native shapes model the retained failure: the framework identifies
// a whole disk, its physical slice and a synthesized APFS container/volume.
// They are fake-command controls, not additional captured platform evidence.
type attachmentEvidenceCommander struct {
	image      string
	calls      []Command
	mountPoint string
	reply      func(Command) (Result, bool)
}

func (c *attachmentEvidenceCommander) Run(_ context.Context, cmd Command) Result {
	c.calls = append(c.calls, cmd)
	if c.reply != nil {
		if result, ok := c.reply(cmd); ok {
			return result
		}
	}
	var value any
	switch cmd.Argv[0] {
	case "hdiutil":
		if cmd.Argv[1] == "detach" {
			return Result{Status: 16, Stderr: []byte("Resource busy")}
		}
		value = map[string]any{"images": []any{map[string]any{
			"image-path": projectedImagePath(c.image), "hdid-pid": 123,
			"system-entities": []any{
				map[string]any{"dev-entry": "/dev/disk42"},
				map[string]any{"dev-entry": "/dev/disk42s1"},
				map[string]any{"dev-entry": "/dev/disk43"},
				map[string]any{"dev-entry": "/dev/disk43s1"},
			},
		}}}
	case "plutil":
		return Result{Stdout: cmd.Stdin}
	case "/usr/sbin/ioreg":
		return Result{Stdout: []byte{0, 0xff, '\r', '\n'}}
	case "diskutil":
		node := cmd.Argv[len(cmd.Argv)-1]
		value = map[string]any{"DeviceNode": node, "Mounted": node == "/dev/disk43s1" && c.mountPoint != "", "MountPoint": c.mountPoint}
	case "/usr/sbin/lsof":
		return Result{Status: 1, Stdout: []byte("expected backend backing-file FD; cause unknown\n")}
	case "/bin/ps":
		return Result{Stdout: []byte("123 1 native-backend\n")}
	default:
		return Result{Status: -1, Err: errors.New("unexpected diagnostic command")}
	}
	b, err := json.Marshal(value)
	return Result{Stdout: b, Err: err}
}

func TestBusyDetachEvidenceIncludesFreshRelatedDevicesWithoutAnotherClose(t *testing.T) {
	instantWaits(t)
	att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42", RDev: "/dev/rdisk42", Container: "disk999", Volumes: []*AttachedVolume{{Dev: "/dev/disk999s1", Mount: "/stale/private/pin"}}}
	c := &attachmentEvidenceCommander{image: att.Image}
	d := imageTestDisk(c)
	err := d.Detach(context.Background(), att)
	var busy *NotSettledError
	if !errors.As(err, &busy) || busy.Checks != BusyWait.Attempts {
		t.Fatalf("diagnostics changed the fatal native result: %v", err)
	}
	closes, scopes := 0, 0
	var holderArgs []string
	for _, cmd := range c.calls {
		if cmd.Argv[0] == "hdiutil" && cmd.Argv[1] == "detach" {
			closes++
		}
		if cmd.Argv[0] == "/usr/sbin/ioreg" {
			scopes++
		}
		if cmd.Argv[0] == "/usr/sbin/lsof" {
			holderArgs = cmd.Argv
		}
		if slices.Contains(cmd.Argv, "/dev/disk999s1") || slices.Contains(cmd.Argv, "/stale/private/pin") {
			t.Fatalf("diagnostics trusted stale attachment fields: %v", cmd.Argv)
		}
	}
	if closes != BusyWait.Attempts || scopes != 4 {
		t.Fatalf("expected six existing closes and four independent scopes; closes=%d scopes=%d", closes, scopes)
	}
	for _, node := range []string{"/dev/disk42", "/dev/rdisk42", "/dev/disk42s1", "/dev/rdisk42s1", "/dev/disk43", "/dev/rdisk43", "/dev/disk43s1", "/dev/rdisk43s1"} {
		if !slices.Contains(holderArgs, node) {
			t.Fatalf("holder evidence omitted a freshly bound related node %s: %v", node, holderArgs)
		}
	}
}

func TestBusyDetachEvidenceRetainsIndependentScopesWhenBindingCannotBeInterpreted(t *testing.T) {
	for _, name := range []string{"malformed", "foreign"} {
		t.Run(name, func(t *testing.T) {
			att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42"}
			c := &attachmentEvidenceCommander{image: att.Image}
			c.reply = func(cmd Command) (Result, bool) {
				if cmd.Label != "busy-detach-fresh-binding" {
					return Result{}, false
				}
				if name == "malformed" {
					return Result{Stdout: []byte("not a property list")}, true
				}
				data, _ := json.Marshal(map[string]any{"images": []any{attachedImage(detachImage(t, t.TempDir()), att.Dev)}})
				return Result{Stdout: data}, true
			}
			d := imageTestDisk(c)
			if err := d.recordBusyDetachEvidence(context.Background(), att); err == nil {
				t.Fatal("unknown binding was presented as complete evidence")
			}
			scopes := 0
			for _, cmd := range c.calls {
				if cmd.Argv[0] == "/usr/sbin/ioreg" {
					scopes++
				}
				if cmd.Argv[0] == "diskutil" || cmd.Argv[0] == "/usr/sbin/lsof" || cmd.Argv[0] == "/bin/ps" {
					t.Fatalf("supplemental query had no current target binding: %v", cmd.Argv)
				}
			}
			if scopes != 4 {
				t.Fatalf("interpretation failure lost raw independent scopes: %d", scopes)
			}
		})
	}
}

func TestBusyDetachEvidenceRoundTripsOriginalBinaryStreamsAndJoinsLaunchFailures(t *testing.T) {
	instantWaits(t)
	att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42"}
	c := &attachmentEvidenceCommander{image: att.Image}
	cause := errors.New("registry launch refused")
	original := []byte{0, 0xff, '\r', '\n'}
	c.reply = func(cmd Command) (Result, bool) {
		if cmd.Label == "busy-detach-modern-inventory" {
			return Result{Status: -1, Stdout: original, Stderr: []byte("original\r\n"), Err: cause}, true
		}
		return Result{}, false
	}
	d := imageTestDisk(c)
	err := d.Detach(context.Background(), att)
	var busy *NotSettledError
	if !errors.As(err, &busy) || !errors.Is(err, cause) {
		t.Fatalf("evidence failure masked the native failure: %v", err)
	}
	var receipt struct {
		ReceiptCommand int
		Probes         []attachmentDiagnosticProbe
	}
	last := d.T.Commands[len(d.T.Commands)-1]
	if last.Label != "busy-detach-evidence" || json.Unmarshal([]byte(last.StdoutText), &receipt) != nil {
		t.Fatal("failure receipt is not reconstructable JSON")
	}
	// Native continuation handoffs prepend other phases. The receipt itself
	// anchors its source ordinals after such a merge, without rewriting bytes.
	merged := append(slices.Clone(d.T.Commands[:1]), d.T.Commands...)
	offset := len(merged) - 1 - receipt.ReceiptCommand
	gotScope := false
	for _, probe := range receipt.Probes {
		command := merged[probe.Command+offset]
		if command.Label != "busy-detach-modern-inventory" {
			continue
		}
		gotScope = true
		if !bytes.Equal(probe.Stdout.Data, original) || probe.Stdout.Bytes != len(original) || probe.Stdout.SHA256 != fmt.Sprintf("%x", sha256.Sum256(original)) || probe.Stdout.StoredSHA256 != probe.Stdout.SHA256 || command.StdoutSHA256 != probe.Stdout.SHA256 || probe.Error == "" {
			t.Fatal("raw binary/CRLF failure bytes or their original binding changed")
		}
	}
	if !gotScope {
		t.Fatal("failed registry launch was omitted from the receipt")
	}
}

func TestBusyDetachEvidenceQueriesOnlyVerifiedMountedOnDevices(t *testing.T) {
	for _, state := range []string{"mounted", "gone", "foreign", "unknown-fsid"} {
		t.Run(state, func(t *testing.T) {
			att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42"}
			pin := filepath.Join(t.TempDir(), "private-mount")
			c := &attachmentEvidenceCommander{image: att.Image, mountPoint: pin}
			d := imageTestDisk(c)
			d.mountProbe = func(path string) (mountIdentity, error) {
				if path != pin {
					t.Errorf("probe escaped fresh native mount point: %q", path)
				}
				identity := mountIdentity{MountPoint: pin, Source: "/dev/disk43s1", FSID: [2]int32{42, 7}}
				switch state {
				case "gone":
					identity.MountPoint, identity.Source = filepath.Dir(pin), "/dev/disk0s1"
				case "foreign":
					identity.Source = "/dev/disk99s1"
				case "unknown-fsid":
					identity.FSID = [2]int32{}
				}
				return identity, nil
			}
			err := d.recordBusyDetachEvidence(context.Background(), att)
			if (err == nil) != (state == "mounted") {
				t.Fatalf("mount disposition lost its uncertainty: %v", err)
			}
			queries := 0
			for _, cmd := range c.calls {
				if cmd.Label != "busy-detach-filesystem-holders" {
					continue
				}
				queries++
				if !slices.Contains(cmd.Argv, "+f") || cmd.Argv[len(cmd.Argv)-1] != "/dev/disk43s1" || slices.Contains(cmd.Argv, pin) {
					t.Fatalf("filesystem query can select the containing host mount: %v", cmd.Argv)
				}
			}
			if (queries == 1) != (state == "mounted") {
				t.Fatalf("unqualified filesystem holder query: state=%s queries=%d", state, queries)
			}
		})
	}
}

func TestBusyDetachEvidenceStopsSupplementalProbesWhenTheDeviceIsReassigned(t *testing.T) {
	att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42"}
	c := &attachmentEvidenceCommander{image: att.Image}
	infos := 0
	c.reply = func(cmd Command) (Result, bool) {
		if cmd.Label == "busy-detach-device" {
			infos++
		}
		if cmd.Label == "busy-detach-fresh-binding" && infos > 0 {
			data, _ := json.Marshal(map[string]any{"images": []any{attachedImage(detachImage(t, t.TempDir()), att.Dev)}})
			return Result{Stdout: data}, true
		}
		return Result{}, false
	}
	d := imageTestDisk(c)
	if err := d.recordBusyDetachEvidence(context.Background(), att); err == nil {
		t.Fatal("reassigned diagnostic target was not marked unknown")
	}
	if infos != 1 {
		t.Fatalf("stale binding authorized later device queries: %d", infos)
	}
	for _, cmd := range c.calls {
		if cmd.Argv[0] == "/usr/sbin/lsof" || cmd.Argv[0] == "/bin/ps" {
			t.Fatalf("queried holders after reassignment: %v", cmd.Argv)
		}
	}
}

func TestBusyDetachEvidenceRetainsExplicitOutputBounds(t *testing.T) {
	att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42"}
	c := &attachmentEvidenceCommander{image: att.Image}
	original := make([]byte, busyEvidenceStreamLimit+1)
	original[len(original)-1] = 1
	c.reply = func(cmd Command) (Result, bool) {
		if cmd.Label == "busy-detach-modern-inventory" {
			return Result{Stdout: original}, true
		}
		return Result{}, false
	}
	d := imageTestDisk(c)
	if err := d.recordBusyDetachEvidence(context.Background(), att); err == nil || !strings.Contains(err.Error(), "bounds") {
		t.Fatal("truncated evidence was presented as complete", err)
	}
	var receipt struct{ Probes []attachmentDiagnosticProbe }
	if err := json.Unmarshal([]byte(d.T.Commands[len(d.T.Commands)-1].StdoutText), &receipt); err != nil {
		t.Fatal(err)
	}
	for _, probe := range receipt.Probes {
		if d.T.Commands[probe.Command].Label == "busy-detach-modern-inventory" && (probe.Stdout.Bytes != len(original) || len(probe.Stdout.Data) != busyEvidenceStreamLimit || probe.Stdout.SHA256 == probe.Stdout.StoredSHA256) {
			t.Fatal("original and retained-prefix byte bindings are not distinguished")
		}
	}
}

func TestBusyDetachEvidenceHonorsCancellationDuringAMountObservation(t *testing.T) {
	att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42"}
	c := &attachmentEvidenceCommander{image: att.Image, mountPoint: t.TempDir()}
	d := imageTestDisk(c)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	d.mountProbe = func(string) (mountIdentity, error) {
		cancel()
		<-release
		return mountIdentity{}, nil
	}
	if err := d.recordBusyDetachEvidence(ctx, att); !errors.Is(err, context.Canceled) {
		t.Fatal("blocked observation lost caller cancellation", err)
	}
	for _, cmd := range c.calls {
		if cmd.Argv[0] == "/usr/sbin/lsof" {
			t.Fatalf("holder query ran after cancellation: %v", cmd.Argv)
		}
	}
}

func TestBusyDetachEvidenceRefusesUnboundedRelatedDeviceSelections(t *testing.T) {
	att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42"}
	c := &attachmentEvidenceCommander{image: att.Image}
	c.reply = func(cmd Command) (Result, bool) {
		if cmd.Label != "busy-detach-fresh-binding" {
			return Result{}, false
		}
		entities := []any{map[string]any{"dev-entry": att.Dev}}
		for i := range busyEvidenceTargets {
			entities = append(entities, map[string]any{"dev-entry": fmt.Sprintf("/dev/disk42s%d", i+1)})
		}
		data, _ := json.Marshal(map[string]any{"images": []any{map[string]any{"image-path": projectedImagePath(att.Image), "system-entities": entities}}})
		return Result{Stdout: data}, true
	}
	d := imageTestDisk(c)
	if err := d.recordBusyDetachEvidence(context.Background(), att); err == nil || !strings.Contains(err.Error(), "count outside bounds") {
		t.Fatal("unbounded related-device inventory was accepted", err)
	}
	for _, cmd := range c.calls {
		if cmd.Argv[0] == "diskutil" || cmd.Argv[0] == "/usr/sbin/lsof" || cmd.Argv[0] == "/bin/ps" {
			t.Fatalf("unbounded native selection reached supplemental probes: %v", cmd.Argv)
		}
	}
}
