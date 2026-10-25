package native

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
)

// Only the Commander is synthetic: the real ForSubtest and HostDisk.Detach
// generate the original receipt, then a real transcript handoff and ordinary
// scratch removal reproduce its successful native caller's lifetime.
type cleanupRetentionCommander struct {
	image    string
	detaches int
}

func (c *cleanupRetentionCommander) Run(_ context.Context, cmd fixture.Command) fixture.Result {
	if cmd.Argv[0] == "plutil" {
		return fixture.Result{Stdout: append([]byte(nil), cmd.Stdin...)}
	}
	if cmd.Argv[0] == "hdiutil" && cmd.Argv[1] == "info" {
		raw, err := json.Marshal(map[string]any{"images": []any{map[string]any{
			"image-path": c.image, "system-entities": []any{map[string]any{"dev-entry": "/dev/disk42"}},
		}}})
		return fixture.Result{Stdout: raw, Err: err}
	}
	if cmd.Argv[0] == "hdiutil" && cmd.Argv[1] == "detach" {
		c.detaches++
		if c.detaches == 1 {
			return fixture.Result{Status: 16, Stderr: []byte("synthetic detach: Resource busy\n")}
		}
		return fixture.Result{Stdout: []byte("synthetic detach success\n")}
	}
	return fixture.Result{Status: -1, Err: os.ErrInvalid}
}

func TestSuccessfulBusyDetachRetainsEvidenceAfterTranscriptHandoffAndScratchRemoval(t *testing.T) {
	work := t.TempDir()
	scratch := filepath.Join(work, "continuation", "output")
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	image := filepath.Join(scratch, "writable.raw")
	if err := os.WriteFile(image, []byte("ordinary test backing file"), 0o600); err != nil {
		t.Fatal(err)
	}
	commander := &cleanupRetentionCommander{image: image}
	parent := &Verifier{Work: work, C: commander, attachmentCleanup: newAttachmentCleanupSink(work)}
	child := parent.ForSubtest()
	host := child.Disk.(*fixture.HostDisk)
	if err := host.Detach(context.Background(), &fixture.Attachment{Image: image, Dev: "/dev/disk42"}); err != nil {
		t.Fatal("scripted busy then successful detach changed its verdict", err)
	}
	if commander.detaches != 2 {
		t.Fatal("retention changed the original detach action count", commander.detaches)
	}
	if got := host.T.Commands[len(host.T.Commands)-1]; got.Label != "busy-detach-evidence" || got.StdoutText == "" {
		t.Fatal("the real detach call did not generate its original busy receipt")
	}
	child.setTranscript(&fixture.Transcript{})
	if err := os.RemoveAll(scratch); err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(work, "native-attachment-cleanup", "*.json.gz"))
	if err != nil || len(files) != 1 {
		t.Fatalf("successful cleanup lost its rare original busy receipt after handoff/removal: retained files=%v (%v)", files, err)
	}
}

func TestSuccessfulBusyDetachReturnsItsActualSinkIOFailure(t *testing.T) {
	work := t.TempDir()
	image := filepath.Join(work, "writable.raw")
	if err := os.WriteFile(image, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(work, "native-attachment-cleanup"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	commander := &cleanupRetentionCommander{image: image}
	parent := &Verifier{Work: work, C: commander, attachmentCleanup: newAttachmentCleanupSink(work)}
	child := parent.ForSubtest()
	host := child.Disk.(*fixture.HostDisk)
	err := host.Detach(context.Background(), &fixture.Attachment{Image: image, Dev: "/dev/disk42"})
	var retention *fixture.AttachmentCleanupRetentionError
	var pathError *os.PathError
	if !errors.As(err, &retention) || !errors.As(err, &pathError) || commander.detaches != 2 {
		t.Fatal("real sink failure lost its typed/native outcome or repeated a detach", err, commander.detaches)
	}
	if onlyKnownLimit(errors.Join(KnownLimit{Refusal: "tracked source"}, err)) {
		t.Fatal("tracked product limit hid a real sink failure")
	}
	last := host.T.Commands[len(host.T.Commands)-1]
	if last.Label != "busy-detach-evidence" || last.Status != "0" {
		t.Fatal("sink failure rewrote the original successful cleanup receipt", last)
	}
}
