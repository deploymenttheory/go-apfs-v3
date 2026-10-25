package fixture

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"strings"
	"testing"
)

func TestSuccessfulBusyDetachPublishesImmutableOriginalReceiptSynchronously(t *testing.T) {
	instantWaits(t)
	image := detachImage(t, t.TempDir())
	att := &Attachment{Image: image, Dev: "/dev/disk42"}
	commander := detachCommander(t, map[string]any{"images": []any{attachedImage(image, att.Dev)}})
	disk := imageTestDisk(commander)
	var evidence AttachmentCleanupEvidence
	calls := 0
	disk.AttachmentCleanupEvidence = func(value AttachmentCleanupEvidence) error { calls++; evidence = value; return nil }
	start := len(disk.T.Commands)
	if err := disk.Detach(context.Background(), att); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("successful busy cleanup did not publish its completed raw receipt synchronously: calls=%d", calls)
	}
	if detachCalls(commander) != 2 {
		t.Fatal("retention changed existing native request count")
	}
	last := disk.T.Commands[len(disk.T.Commands)-1]
	if evidence.ReceiptJSON() != last.StdoutText || evidence.ReceiptSHA256() != last.StdoutSHA256 || fmt.Sprintf("%x", sha256.Sum256([]byte(evidence.ReceiptJSON()))) != evidence.ReceiptSHA256() {
		t.Fatal("retention rewrote original receipt bytes/digest")
	}
	var receipt struct{ StartCommand, ReceiptCommand int }
	if err := json.Unmarshal([]byte(evidence.ReceiptJSON()), &receipt); err != nil {
		t.Fatal(err)
	}
	if evidence.StartCommand() != start || receipt.StartCommand != start || receipt.ReceiptCommand != evidence.ReceiptCommand() || evidence.ReceiptCommand() != len(disk.T.Commands)-1 {
		t.Fatal("original local ordinal anchors changed")
	}
	commands := evidence.Commands()
	for _, row := range commands {
		if !reflect.DeepEqual(row.Command, disk.T.Commands[row.Ordinal]) {
			t.Fatal("command was projected or rebased")
		}
	}
	saved := evidence.Commands()
	commands[0].Command.Argv[0] = "mutated getter copy"
	commands[0].Command.Status = "corrupt"
	if !reflect.DeepEqual(evidence.Commands(), saved) {
		t.Fatal("getter exposed mutable payload state")
	}
	disk.T.Commands[start].Argv[0] = "later transcript mutation"
	if !reflect.DeepEqual(evidence.Commands(), saved) {
		t.Fatal("payload retained aliases into original transcript")
	}
}

func TestBusyDetachRetentionFailurePreservesNativeSuccessAndOriginalReceipt(t *testing.T) {
	instantWaits(t)
	image := detachImage(t, t.TempDir())
	att := &Attachment{Image: image, Dev: "/dev/disk42"}
	commander := detachCommander(t, map[string]any{"images": []any{attachedImage(image, att.Dev)}})
	disk := imageTestDisk(commander)
	disk.AttachmentCleanupEvidence = func(AttachmentCleanupEvidence) error { return fs.ErrPermission }
	err := disk.Detach(context.Background(), att)
	var retention *AttachmentCleanupRetentionError
	var native *NotSettledError
	if !errors.As(err, &retention) || !errors.Is(err, fs.ErrPermission) || errors.As(err, &native) {
		t.Fatalf("retention failure was hidden or rewrote successful normal cleanup: %v", err)
	}
	if detachCalls(commander) != 2 || len(commander.calls) != 6 {
		t.Fatal("retention failure issued extra actions or probes")
	}
	last := disk.T.Commands[len(disk.T.Commands)-1]
	if last.Status != "0" || last.Label != "busy-detach-evidence" || strings.Contains(last.StdoutText, fs.ErrPermission.Error()) {
		t.Fatal("retention error rewrote original receipt outcome")
	}
	var receipt struct {
		Actions []struct{ Status int }
		Error   string
	}
	if err := json.Unmarshal([]byte(last.StdoutText), &receipt); err != nil {
		t.Fatal(err)
	}
	if len(receipt.Actions) != 2 || receipt.Actions[0].Status != 16 || receipt.Actions[1].Status != 0 || receipt.Error != "" {
		t.Fatal("original operation outcomes changed")
	}
}

func TestBusyDetachRetentionFailureJoinsTheOriginalExhaustedBusyVerdict(t *testing.T) {
	instantWaits(t)
	image := detachImage(t, t.TempDir())
	commander := &detachActionCommander{image: image}
	disk := imageTestDisk(commander)
	calls := 0
	disk.AttachmentCleanupEvidence = func(AttachmentCleanupEvidence) error { calls++; return fs.ErrPermission }
	err := disk.Detach(context.Background(), &Attachment{Image: image, Dev: "/dev/disk42"})
	var native *NotSettledError
	var retention *AttachmentCleanupRetentionError
	if !errors.As(err, &native) || native.Checks != 6 || !errors.As(err, &retention) || !errors.Is(err, fs.ErrPermission) || commander.actions != 6 || calls != 1 {
		t.Fatalf("retention masked the native failure or changed its budget: %v", err)
	}
	if strings.Contains(disk.T.Commands[len(disk.T.Commands)-1].StdoutText, fs.ErrPermission.Error()) {
		t.Fatal("hook failure was inserted into the original receipt")
	}
}

func TestDetachWithoutBusyNeverCallsTheCleanupEvidenceSink(t *testing.T) {
	for _, state := range []string{"first-success", "permanent-failure", "cancelled"} {
		t.Run(state, func(t *testing.T) {
			instantWaits(t)
			image := detachImage(t, t.TempDir())
			att := &Attachment{Image: image, Dev: "/dev/disk42"}
			commander := detachCommander(t, map[string]any{"images": []any{attachedImage(image, att.Dev)}})
			commander.sequence["hdiutil"][1] = Result{}
			if state == "permanent-failure" {
				commander.sequence["hdiutil"][1] = Result{Status: 5, Stderr: []byte("input/output error")}
			}
			disk := imageTestDisk(commander)
			calls := 0
			disk.AttachmentCleanupEvidence = func(AttachmentCleanupEvidence) error { calls++; return errors.New("unexpected callback") }
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if state == "cancelled" {
				cancel()
			}
			err := disk.Detach(ctx, att)
			if calls != 0 {
				t.Fatal("healthy/permanent/cancelled first request created a busy packet")
			}
			switch state {
			case "first-success":
				if err != nil || detachCalls(commander) != 1 {
					t.Fatal("first success changed", err)
				}
			case "permanent-failure":
				if err == nil || detachCalls(commander) != 1 {
					t.Fatal("permanent error was retried or suppressed", err)
				}
			case "cancelled":
				if !errors.Is(err, context.Canceled) || len(commander.calls) != 0 {
					t.Fatal("cancellation issued a command or lost its cause", err)
				}
			}
		})
	}
}

func TestBusyDetachPayloadPreservesCurrentAndPriorTranscriptUnmountOrdinals(t *testing.T) {
	for _, scope := range []string{"current", "prior"} {
		t.Run(scope, func(t *testing.T) {
			instantWaits(t)
			disk, att, _, identity := priorUnmountDisk(t)
			disk.mountProbe = func(string) (mountIdentity, error) { return identity, nil }
			if err := disk.Unmount(context.Background(), att.Volumes[0]); err != nil {
				t.Fatal(err)
			}
			unmount := att.Volumes[0].priorUnmount.Command
			originalUnmount := disk.T.Commands[unmount]
			if scope == "prior" {
				disk.SetTranscript(&Transcript{})
				if err := disk.T.RecordFS("unrelated", []string{"ordinary-file"}, nil, "0"); err != nil {
					t.Fatal(err)
				}
			}
			start := len(disk.T.Commands)
			var payload AttachmentCleanupEvidence
			disk.AttachmentCleanupEvidence = func(value AttachmentCleanupEvidence) error { payload = value; return nil }
			var native *NotSettledError
			if err := disk.Detach(context.Background(), att); !errors.As(err, &native) || native.Checks != 6 {
				t.Fatal("original busy verdict changed", err)
			}
			if payload.StartCommand() != start {
				t.Fatal("detach entry ordinal was shifted to an earlier anchor")
			}
			var receipt struct{ PriorUnmounts []priorUnmountObservation }
			if err := json.Unmarshal([]byte(payload.ReceiptJSON()), &receipt); err != nil {
				t.Fatal(err)
			}
			if len(receipt.PriorUnmounts) != 1 || receipt.PriorUnmounts[0].UnmountTranscript != scope || receipt.PriorUnmounts[0].UnmountCommand != unmount {
				t.Fatal("prior unmount marker or local ordinal was rewritten")
			}
			anchors := payload.Commands()
			if scope == "current" {
				if anchors[0].Ordinal != unmount || !reflect.DeepEqual(anchors[0].Command, originalUnmount) || anchors[1].Ordinal != start {
					t.Fatal("same-transcript unmount anchor was lost/rebased")
				}
			} else if anchors[0].Ordinal != start {
				t.Fatal("prior transcript ordinal was rebound to an unrelated current command")
			}
			for _, row := range anchors {
				if !reflect.DeepEqual(row.Command, disk.T.Commands[row.Ordinal]) {
					t.Fatal("retained anchor differs from original command")
				}
			}
		})
	}
}
