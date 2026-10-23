package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestDetachLeavesReassignedDeviceUntouchedOnFirstCall(t *testing.T) {
	root := t.TempDir()
	original := detachImage(t, filepath.Join(root, "original"))
	other := detachImage(t, filepath.Join(root, "current"))
	att := &Attachment{Image: original, Dev: "/dev/disk42"}
	inventory, err := json.Marshal(map[string]any{"images": []any{attachedImage(other, att.Dev)}})
	if err != nil {
		t.Fatal(err)
	}
	commander := &fakeCommander{results: map[string]Result{
		"hdiutil": {Stdout: []byte("native image inventory")},
		"plutil":  {Stdout: inventory},
	}}
	disk := imageTestDisk(commander)
	if err := disk.Detach(context.Background(), att); err != nil {
		t.Fatal(err)
	}
	if detachCalls(commander) != 0 {
		t.Fatalf("stale attachment detached another image on its first cleanup call: %v", commander.calls)
	}
}

type attachmentLifetimeCommander struct {
	calls      []Command
	inventory  []byte
	refresh    Result
	cleanupErr error
	probeErr   error
	cancel     context.CancelFunc
	cancelAt   string
}

func (c *attachmentLifetimeCommander) Run(_ context.Context, command Command) Result {
	c.calls = append(c.calls, command)
	if c.cancel != nil && command.Label == c.cancelAt {
		c.cancel()
	}
	switch command.Argv[0] {
	case "plutil":
		return Result{Stdout: command.Stdin}
	case "hdiutil":
		switch command.Argv[1] {
		case "attach":
			return Result{Stdout: []byte(`{"system-entities":[{"dev-entry":"/dev/disk42","potentially-mountable":false}]}`)}
		case "info":
			if c.probeErr != nil {
				return Result{Status: -1, Err: c.probeErr}
			}
			return Result{Stdout: c.inventory}
		case "detach":
			if c.cleanupErr != nil {
				return Result{Status: -1, Err: c.cleanupErr}
			}
			return Result{}
		}
	case "diskutil":
		return c.refresh
	}
	return Result{Status: -1, Err: errors.New("unexpected native command")}
}

func TestAttachFailureClosesOnlyItsOwnedImageAndRetainsTheFailure(t *testing.T) {
	for _, scenario := range []string{"owned", "native list failure", "foreign", "absent", "malformed", "cleanup failure", "cancelled", "cancelled cleanup probe"} {
		t.Run(scenario, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			root := t.TempDir()
			image := detachImage(t, filepath.Join(root, "original"))
			owner := image
			if scenario == "foreign" {
				owner = detachImage(t, filepath.Join(root, "current"))
			}
			inventory := map[string]any{"images": []any{attachedImage(owner, "/dev/disk42")}}
			switch scenario {
			case "absent":
				inventory["images"] = []any{}
			case "malformed":
				inventory["images"] = "unknown"
			}
			data, err := json.Marshal(inventory)
			if err != nil {
				t.Fatal(err)
			}
			cause := errors.New("discovery failed")
			commander := &attachmentLifetimeCommander{inventory: data, refresh: Result{Status: -1, Err: cause}}
			cleanupCause := errors.New("owned cleanup failed")
			if scenario == "cleanup failure" {
				commander.cleanupErr = cleanupCause
			}
			if scenario == "cancelled" {
				commander.cancel = cancel
				commander.cancelAt = "list"
			}
			if scenario == "cancelled cleanup probe" {
				commander.cancel = cancel
				commander.cancelAt = "hdiutil-info"
				commander.probeErr = cleanupCause
			}
			if scenario == "native list failure" {
				commander.refresh = Result{Status: 1, Stdout: []byte(`{"Error":true,"ErrorMessage":"Could not find disk for /dev/disk42","ExitCode":1}`)}
			}
			disk := imageTestDisk(commander)
			attachment, err := disk.Attach(ctx, image, AttachOptions{ReadOnly: true})
			if attachment != nil || err == nil || scenario != "native list failure" && !errors.Is(err, cause) {
				t.Fatalf("discovery failure was lost or admitted: attachment=%v, err=%v", attachment, err)
			}
			if scenario == "native list failure" && !strings.Contains(err.Error(), "diskutil list -plist /dev/disk42: exit 1") {
				t.Fatalf("native discovery exit was changed: %v", err)
			}
			if (scenario == "cleanup failure" || scenario == "cancelled cleanup probe") && !errors.Is(err, cleanupCause) {
				t.Fatalf("cleanup failure replaced or lost an original cause: %v", err)
			}
			if scenario == "malformed" && !strings.Contains(err.Error(), "hdiutil inventory has no valid image list") {
				t.Fatalf("unknown cleanup ownership was not retained: %v", err)
			}
			if strings.HasPrefix(scenario, "cancelled") && !errors.Is(err, context.Canceled) {
				t.Fatalf("cleanup ignored cancellation: %v", err)
			}
			lists, detaches, probes := 0, 0, 0
			for _, command := range commander.calls {
				switch command.Label {
				case "list":
					lists++
				case "detach":
					detaches++
				case "hdiutil-info":
					probes++
				}
			}
			want := 0
			if scenario == "owned" || scenario == "native list failure" || scenario == "cleanup failure" {
				want = 1
			}
			wantProbes := 1
			if scenario == "cancelled" {
				wantProbes = 0
			}
			if lists != 1 || detaches != want || probes != wantProbes {
				t.Fatalf("failed discovery retried or escaped owned cleanup: lists=%d, detaches=%d (want %d), probes=%d", lists, detaches, want, probes)
			}
		})
	}
}

func TestDetachStopsIfItsOwnerProbeIsCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	image := detachImage(t, t.TempDir())
	data, err := json.Marshal(map[string]any{"images": []any{attachedImage(image, "/dev/disk42")}})
	if err != nil {
		t.Fatal(err)
	}
	commander := &attachmentLifetimeCommander{inventory: data, cancel: cancel, cancelAt: "hdiutil-info"}
	disk := imageTestDisk(commander)
	if err := disk.Detach(ctx, &Attachment{Image: image, Dev: "/dev/disk42"}); !errors.Is(err, context.Canceled) {
		t.Fatal("owner probe lost cancellation", err)
	}
	for _, command := range commander.calls {
		if command.Label == "detach" {
			t.Fatal("cancelled owner probe allowed a native detach")
		}
	}
}
