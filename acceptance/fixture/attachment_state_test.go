package fixture

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
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
