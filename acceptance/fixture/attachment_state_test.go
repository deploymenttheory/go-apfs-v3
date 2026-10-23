package fixture

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestForeignAttachmentCleanupDoesNotClaimRelease(t *testing.T) {
	image := detachImage(t, filepath.Join(t.TempDir(), "expected"))
	foreign := detachImage(t, filepath.Join(t.TempDir(), "foreign"))
	att := &Attachment{Image: image, Dev: "/dev/disk42"}
	commander := detachCommander(t, map[string]any{"images": []any{attachedImage(foreign, att.Dev)}})
	disk := imageTestDisk(commander)
	var refusal *AttachmentOwnershipError
	if err := disk.Detach(context.Background(), att); !errors.As(err, &refusal) || refusal.State != OwnershipForeign || refusal.Device != att.Dev || refusal.Image != att.Image {
		t.Fatalf("foreign attachment must remain explicitly unreleased: %v", err)
	}
	if detachCalls(commander) != 0 {
		t.Fatal("a foreign device was detached")
	}
}

func TestCapturedLiveImageWithAStaleDeviceCannotBeReportedReleased(t *testing.T) {
	for _, capture := range retainedNativePlatformCaptures(t) {
		t.Run(fmt.Sprint(capture.Major), func(t *testing.T) {
			commander := capture.commander(t, "after-attach-second")
			disk := &HostDisk{C: commander, T: &Transcript{}, imagePathResolver: capture.resolveImage}
			got, err := disk.kernelAttachmentOwnership(context.Background(), &Attachment{Image: capture.First.Image, Dev: "/dev/disk999"})
			if got != OwnershipUnknown || err == nil || !strings.Contains(err.Error(), "expected image remains in kernel ancestry") {
				t.Fatalf("visibly attached image with a stale device falsely classified as %s: %v", got, err)
			}
		})
	}
}

func TestFrameworkImageAtAnotherDeviceCannotBeReportedReleased(t *testing.T) {
	image := detachImage(t, t.TempDir())
	att := &Attachment{Image: image, Dev: "/dev/disk42"}
	commander := detachCommander(t, map[string]any{"images": []any{attachedImage(image, "/dev/disk43")}})
	commander.sequence["/usr/sbin/ioreg"] = []Result{{Stdout: registryArchive()}, {Stdout: registryArchive()}, {Stdout: registryArchive(registryMedia("disk0"), registryMedia("disk43"))}}
	disk := imageTestDisk(commander)
	err := disk.Detach(context.Background(), att)
	var refusal *AttachmentOwnershipError
	if !errors.As(err, &refusal) || refusal.State != OwnershipUnknown || !strings.Contains(err.Error(), "expected image remains in the framework inventory") {
		t.Fatalf("expected image at another device falsely reported released: %v", err)
	}
	if detachCalls(commander) != 0 {
		t.Fatal("stale handle retargeted a detach")
	}
}

func TestBusyDetachRetainsItsFailureWhenLaterOwnershipProofRefusesCleanup(t *testing.T) {
	for _, state := range []AttachmentOwnership{OwnershipForeign, OwnershipUnknown} {
		t.Run(string(state), func(t *testing.T) {
			instantWaits(t)
			image := detachImage(t, filepath.Join(t.TempDir(), "expected"))
			foreign := detachImage(t, filepath.Join(t.TempDir(), "foreign"))
			att := &Attachment{Image: image, Dev: "/dev/disk42"}
			commander := detachCommander(t, map[string]any{"images": []any{attachedImage(image, att.Dev)}})
			owned, err := json.Marshal(map[string]any{"images": []any{attachedImage(image, att.Dev)}})
			if err != nil {
				t.Fatal(err)
			}
			other, err := json.Marshal(map[string]any{"images": []any{attachedImage(foreign, att.Dev)}})
			if err != nil {
				t.Fatal(err)
			}
			proof := Result{Stdout: other}
			var failure error
			if state == OwnershipUnknown {
				failure = errors.New("ownership conversion failed")
				proof = Result{Status: -1, Err: failure}
			}
			commander.sequence["plutil"] = []Result{{Stdout: owned}, proof}
			disk := imageTestDisk(commander)
			err = disk.Detach(context.Background(), att)
			var refusal *AttachmentOwnershipError
			if !errors.As(err, &refusal) || refusal.State != state || !strings.Contains(err.Error(), "exit 16: Resource busy") || (failure != nil && !errors.Is(err, failure)) {
				t.Fatalf("later ownership refusal lost the earlier busy detach or proof cause: %v", err)
			}
			if detachCalls(commander) != 1 {
				t.Fatal("failed ownership proof admitted another detach action")
			}
		})
	}
}

func TestKernelOwnershipStatesReplayCompleteCapturedPlatformResults(t *testing.T) {
	for _, capture := range retainedNativePlatformCaptures(t) {
		t.Run(fmt.Sprint(capture.Major), func(t *testing.T) {
			for _, relation := range capture.Relations {
				t.Run(relation.Phase+"/"+relation.Image+"/"+relation.Device, func(t *testing.T) {
					images := map[string]string{"first": capture.First.Image, "second": capture.Second.Image, "alias": capture.Alias}
					devices := map[string]string{"first": capture.First.Dev, "second": capture.Second.Dev}
					states := map[string]AttachmentOwnership{"owned": OwnershipOwned, "foreign": OwnershipForeign, "post-detach": OwnershipAbsent}
					image, imageOK := images[relation.Image]
					device, deviceOK := devices[relation.Device]
					want, stateOK := states[relation.Relation]
					if !imageOK || !deviceOK || !stateOK {
						t.Fatal("invalid declared capture relation", relation)
					}
					commander := capture.commander(t, relation.Phase)
					disk := &HostDisk{C: commander, T: &Transcript{}, imagePathResolver: capture.resolveImage}
					got, err := disk.kernelAttachmentOwnership(context.Background(), &Attachment{Image: image, Dev: device})
					if err != nil || got != want {
						t.Fatalf("original platform results classified as %s, want %s: %v", got, want, err)
					}
					if want == OwnershipAbsent && len(commander.Calls) != 3 {
						t.Fatalf("absence needs modern, legacy and complete media scopes: %v", commander.Calls)
					}
				})
			}
		})
	}
}

func TestUnknownAttachmentRefusesCleanupAndPreservesProofFailure(t *testing.T) {
	failure := errors.New("registry launch failure")
	image := detachImage(t, t.TempDir())
	commander := &kernelOwnershipCommander{
		global:      []byte(`<plist><dict><key>images</key><array/></dict></plist>`),
		registryErr: failure,
	}
	disk := imageTestDisk(commander)
	att := &Attachment{Image: image, Dev: "/dev/disk42"}
	err := disk.Detach(context.Background(), att)
	var refusal *AttachmentOwnershipError
	if !errors.As(err, &refusal) || refusal.State != OwnershipUnknown || !errors.Is(err, failure) {
		t.Fatalf("unknown attachment lost the original proof failure: %v", err)
	}
	if commander.count("detach") != 0 {
		t.Fatal("unknown attachment admitted device action")
	}
}

func TestSuccessfulEmptyScopedQueriesRequireAnIndependentCompleteMediaProof(t *testing.T) {
	for _, test := range []struct {
		name  string
		media []byte
		want  AttachmentOwnership
	}{
		{"complete media excludes target", registryArchive(registryMedia("disk0")), OwnershipAbsent},
		{"empty complete media output", nil, OwnershipUnknown},
		{"empty complete media archive", registryArchive(), OwnershipUnknown},
		{"complete media still contains target", registryArchive(registryMedia("disk42")), OwnershipUnknown},
	} {
		t.Run(test.name, func(t *testing.T) {
			commander := &kernelOwnershipCommander{images: nil, legacy: []byte{}, media: test.media}
			disk := imageTestDisk(commander)
			got, err := disk.kernelAttachmentOwnership(context.Background(), &Attachment{Image: "/Volumes/image/writable.raw", Dev: "/dev/disk42"})
			if got != test.want || (err == nil) != (test.want == OwnershipAbsent) {
				t.Fatalf("class misses classified as %s, want %s: %v", got, test.want, err)
			}
			if commander.count("ioreg-media-absence") != 1 || commander.count("detach") != 0 {
				t.Fatal("class misses skipped independent proof or admitted device action")
			}
		})
	}
}
