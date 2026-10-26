package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func detachImage(t *testing.T, directory string) string {
	t.Helper()
	if err := os.MkdirAll(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "writable.raw")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func attachedImage(path, dev string) map[string]any {
	return map[string]any{"image-path": projectedImagePath(path), "system-entities": []any{map[string]any{"dev-entry": dev}}}
}

func detachCommander(t *testing.T, inventory map[string]any) *fakeCommander {
	t.Helper()
	data, err := json.Marshal(inventory)
	if err != nil {
		t.Fatal(err)
	}
	return &fakeCommander{
		sequence: map[string][]Result{"hdiutil": {
			{Stdout: []byte("native image inventory")},
			{Status: 16, Stderr: []byte("Resource busy")},
			{Stdout: []byte("native image inventory")},
			{},
		}},
		results: map[string]Result{"plutil": {Stdout: data}},
	}
}

func detachCalls(commander *fakeCommander) int {
	n := 0
	for _, argv := range commander.calls {
		if len(argv) > 1 && (argv[0] == "hdiutil" && argv[1] == "detach" || argv[0] == "diskutil" && argv[1] == "eject") {
			n++
		}
	}
	return n
}

func TestDetachUsesNormalDiskEjectAfterRepeatedLegacyBusy(t *testing.T) {
	instantWaits(t)
	att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42"}
	commander := busyDetachCommander(t, att)
	commander.sequence["diskutil"] = []Result{{Stdout: []byte("Disk /dev/disk42 ejected\n")}}
	disk := imageTestDisk(commander)
	if err := disk.Detach(context.Background(), att); err != nil {
		t.Fatal(err)
	}
	actions, guards := 0, 0
	for _, cmd := range disk.T.Commands {
		if cmd.Label == "hdiutil-info" {
			guards++
		}
		if cmd.Label != "detach" {
			continue
		}
		actions++
		if actions < BusyWait.Attempts {
			if cmd.Argv[0] != "hdiutil" || cmd.Status != "16" {
				t.Fatalf("legacy busy action was replaced or lost: %+v", cmd)
			}
		} else if !reflect.DeepEqual(cmd.Argv, []string{"diskutil", "eject", att.Dev}) || cmd.Status != "0" || cmd.StdoutText != "Disk /dev/disk42 ejected\n" {
			t.Fatalf("final normal eject was not retained: %+v", cmd)
		}
	}
	if actions != BusyWait.Attempts || guards != actions || detachCalls(commander) != actions {
		t.Fatalf("ejection changed the action bound or omitted an ownership check: actions=%d guards=%d", actions, guards)
	}
}

func TestDetachRefusesFinalDiskEjectWhenImageOwnershipChanges(t *testing.T) {
	instantWaits(t)
	att := &Attachment{Image: detachImage(t, t.TempDir()), Dev: "/dev/disk42"}
	commander := busyDetachCommander(t, att)
	for range BusyWait.Attempts - 1 {
		commander.sequence["plutil"] = append(commander.sequence["plutil"], commander.results["plutil"])
	}
	foreign, err := json.Marshal(map[string]any{"images": []any{attachedImage(detachImage(t, t.TempDir()), att.Dev)}})
	if err != nil {
		t.Fatal(err)
	}
	commander.sequence["plutil"] = append(commander.sequence["plutil"], Result{Stdout: foreign})
	err = imageTestDisk(commander).Detach(context.Background(), att)
	var refusal *AttachmentOwnershipError
	if !errors.As(err, &refusal) || refusal.State != OwnershipForeign || detachCalls(commander) != BusyWait.Attempts-1 {
		t.Fatalf("final request did not refuse the reassigned device: %v, calls=%v", err, commander.calls)
	}
}

func TestDetachConfirmsExactImageOwnershipBeforeRetryingBusyDevice(t *testing.T) {
	instantWaits(t)
	image := detachImage(t, t.TempDir())
	att := &Attachment{Image: image, Dev: "/dev/disk42"}
	commander := detachCommander(t, map[string]any{"images": []any{attachedImage(image, att.Dev)}})
	disk := imageTestDisk(commander)
	if err := disk.Detach(context.Background(), att); err != nil {
		t.Fatal(err)
	}
	want := [][]string{{"hdiutil", "info", "-plist"}, {"plutil", "-convert", "json", "-o", "-", "-"}, {"hdiutil", "detach", att.Dev}, {"hdiutil", "info", "-plist"}, {"plutil", "-convert", "json", "-o", "-", "-"}, {"hdiutil", "detach", "-debug", att.Dev}}
	if !reflect.DeepEqual(commander.calls, want) {
		t.Fatalf("busy detach did not verify ownership before its normal second attempt: %v", commander.calls)
	}
	commands := disk.T.Commands
	if len(commands) != 6 || commands[5].Label != "busy-detach-evidence" || commands[0].Label != "hdiutil-info" || commands[1].Status != "16" || commands[2].Label != "wait:detach-busy" || commands[3].Label != "hdiutil-info" || commands[3].StdoutText != "native image inventory" || commands[3].StdoutSHA256 == "" || commands[4].Status != "0" {
		t.Fatalf("detach, ownership probe and wait outcomes must all remain in the native transcript: %+v", commands)
	}
}

func TestDetachLeavesReusedDeviceWithSameBasenameInAnotherDirectoryAlone(t *testing.T) {
	instantWaits(t)
	root := t.TempDir()
	image := detachImage(t, filepath.Join(root, "original-lineage"))
	other := detachImage(t, filepath.Join(root, "another-lineage"))
	att := &Attachment{Image: image, Dev: "/dev/disk42"}
	commander := detachCommander(t, map[string]any{"images": []any{attachedImage(other, att.Dev)}})
	disk := imageTestDisk(commander)
	err := disk.Detach(context.Background(), att)
	var refusal *AttachmentOwnershipError
	if !errors.As(err, &refusal) || refusal.State != OwnershipForeign {
		t.Fatalf("foreign device was not reported as an unreleased attachment: %v", err)
	}
	if detachCalls(commander) != 0 {
		t.Fatalf("another lineage's writable.raw was detached after the original device disappeared: %v", commander.calls)
	}
}

func TestAttachmentOwnershipResolvesDeclaredFilesystemAliases(t *testing.T) {
	root := t.TempDir()
	image := detachImage(t, filepath.Join(root, "physical"))
	alias := filepath.Join(root, "alias")
	linked := filepath.Join(alias, filepath.Base(image))
	for _, paths := range [][2]string{{image, linked}, {linked, image}} {
		t.Run(paths[0], func(t *testing.T) {
			instantWaits(t)
			att := &Attachment{Image: paths[0], Dev: "/dev/disk42"}
			commander := detachCommander(t, map[string]any{"images": []any{attachedImage(paths[1], att.Dev)}})
			disk := imageTestDisk(commander)
			disk.imagePathResolver = projectedImageResolver(map[string]string{linked: image})
			if err := disk.Detach(context.Background(), att); err != nil || detachCalls(commander) != 2 {
				t.Fatalf("complete declared aliases did not establish the original image: %v, calls=%v", err, commander.calls)
			}
		})
	}
}

func TestAttachmentOwnershipRejectsUnknownOrAmbiguousTarget(t *testing.T) {
	for _, scenario := range []string{"missing image list", "invalid image list", "missing target path", "unresolvable target path", "unresolvable expected path", "duplicate device owner", "duplicate device entry", "unidentified device inventory"} {
		t.Run(scenario, func(t *testing.T) {
			instantWaits(t)
			image := detachImage(t, t.TempDir())
			att := &Attachment{Image: image, Dev: "/dev/disk42"}
			owner := attachedImage(image, att.Dev)
			inventory := map[string]any{"images": []any{owner}}
			switch scenario {
			case "missing image list":
				delete(inventory, "images")
			case "invalid image list":
				inventory["images"] = "not an inventory"
			case "missing target path":
				delete(owner, "image-path")
			case "unresolvable target path":
				owner["image-path"] = projectedImagePath(filepath.Join(t.TempDir(), "missing.raw"))
			case "unresolvable expected path":
				att.Image = filepath.Join(t.TempDir(), "missing.raw")
			case "duplicate device owner":
				inventory["images"] = []any{owner, owner}
			case "duplicate device entry":
				owner["system-entities"] = []any{map[string]any{"dev-entry": att.Dev}, map[string]any{"dev-entry": att.Dev}}
			case "unidentified device inventory":
				inventory["images"] = []any{map[string]any{"image-path": image}}
			}
			commander := detachCommander(t, inventory)
			disk := imageTestDisk(commander)
			err := disk.Detach(context.Background(), att)
			if err == nil || detachCalls(commander) != 0 {
				t.Fatalf("unknown ownership permitted a detach: %v, calls=%v", err, commander.calls)
			}
			if strings.HasPrefix(scenario, "unresolvable") && !errors.Is(err, fs.ErrNotExist) {
				t.Fatalf("canonical path failure lost its original cause: %v", err)
			}
		})
	}
}

func TestAttachmentOwnershipDoesNotResolveUnrelatedIncompleteImages(t *testing.T) {
	instantWaits(t)
	image := detachImage(t, t.TempDir())
	att := &Attachment{Image: image, Dev: "/dev/disk42"}
	inventory := map[string]any{"images": []any{
		attachedImage("/missing/unrelated/writable.raw", "/dev/disk43"),
		map[string]any{"image-path": "/missing/incomplete/writable.raw"},
		attachedImage(image, att.Dev),
		attachedImage("", "/dev/disk44"),
	}}
	commander := detachCommander(t, inventory)
	disk := imageTestDisk(commander)
	if err := disk.Detach(context.Background(), att); err != nil || detachCalls(commander) != 2 {
		t.Fatalf("unrelated incomplete metadata invalidated a positively identified target: %v, calls=%v", err, commander.calls)
	}
}

func TestDetachRequiresKernelCorroborationBeforeAcceptingFrameworkDeviceAbsence(t *testing.T) {
	instantWaits(t)
	image := detachImage(t, t.TempDir())
	foreign := detachImage(t, t.TempDir())
	att := &Attachment{Image: image, Dev: "/dev/disk42"}
	commander := detachCommander(t, map[string]any{"images": []any{attachedImage(foreign, "/dev/disk43")}})
	commander.sequence["/usr/sbin/ioreg"] = []Result{{Stdout: registryArchive()}, {Stdout: registryArchive()}, {Stdout: registryArchive(registryMedia("disk0"), registryMedia("disk43"))}}
	disk := imageTestDisk(commander)
	if err := disk.Detach(context.Background(), att); err != nil || detachCalls(commander) != 0 {
		t.Fatalf("corroborated absence caused a detach: %v, calls=%v", err, commander.calls)
	}
}

func TestDetachStopsOnFailedOwnershipProbeAndRetainsNativeCause(t *testing.T) {
	for _, failure := range []string{"inventory exit", "inventory deadline", "inventory launch", "conversion exit", "conversion launch", "invalid inventory JSON"} {
		t.Run(failure, func(t *testing.T) {
			instantWaits(t)
			image := detachImage(t, t.TempDir())
			att := &Attachment{Image: image, Dev: "/dev/disk42"}
			commander := detachCommander(t, map[string]any{"images": []any{attachedImage(image, att.Dev)}})
			cause := errors.New("image inventory unavailable")
			var expected error
			switch failure {
			case "inventory exit":
				commander.sequence["hdiutil"][0] = Result{Status: 1, Stderr: []byte(cause.Error())}
			case "inventory deadline":
				expected = context.DeadlineExceeded
				commander.sequence["hdiutil"][0] = Result{Status: -1, Err: expected}
			case "inventory launch":
				expected = cause
				commander.sequence["hdiutil"][0] = Result{Status: -1, Err: expected}
			case "conversion exit":
				commander.results["plutil"] = Result{Status: 1, Stderr: []byte(cause.Error())}
			case "conversion launch":
				expected = cause
				commander.results["plutil"] = Result{Status: -1, Err: expected}
			case "invalid inventory JSON":
				commander.results["plutil"] = Result{Stdout: []byte("{not JSON}")}
			}
			disk := imageTestDisk(commander)
			err := disk.Detach(context.Background(), att)
			if err == nil || detachCalls(commander) != 0 || expected != nil && !errors.Is(err, expected) {
				t.Fatalf("failed probe permitted a detach or lost its native cause: %v, calls=%v", err, commander.calls)
			}
			if failure == "invalid inventory JSON" {
				var syntax *json.SyntaxError
				if !errors.As(err, &syntax) {
					t.Fatalf("invalid inventory lost its decoder cause: %v", err)
				}
			}
			commands := disk.T.Commands
			if len(commands) != 1 || commands[0].Label != "hdiutil-info" {
				t.Fatalf("failed ownership probe was not retained: %+v", commands)
			}
		})
	}
}
