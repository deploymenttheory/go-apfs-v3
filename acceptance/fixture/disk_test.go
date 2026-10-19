package fixture

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateImageRetriesWhileTheDiskImageFrameworkIsBusy(t *testing.T) {
	busy := Result{Status: 1, Stderr: []byte("hdiutil: create failed - Resource busy")}
	cmd := &fakeCommander{sequence: map[string][]Result{"hdiutil": {busy, {Status: 0}}}}
	d := &HostDisk{C: cmd, T: &Transcript{}}
	path := filepath.Join(t.TempDir(), "image.dmg")
	if err := d.CreateImage(context.Background(), path, "64m", "GPTSPUD", "APFS", "", "Fixture"); err != nil {
		t.Fatalf("a busy framework followed by success should create the image: %v", err)
	}
	if len(cmd.calls) != 2 || len(d.T.Commands) != 2 {
		t.Fatalf("expected both attempts to run and be recorded, got %d calls and %d transcript entries", len(cmd.calls), len(d.T.Commands))
	}
}

func TestCreateImageGivesUpAfterThreeBusyAttempts(t *testing.T) {
	busy := Result{Status: 1, Stderr: []byte("hdiutil: create failed - Resource busy")}
	cmd := &fakeCommander{sequence: map[string][]Result{"hdiutil": {busy, busy, busy, {Status: 0}}}}
	d := &HostDisk{C: cmd, T: &Transcript{}}
	err := d.CreateImage(context.Background(), filepath.Join(t.TempDir(), "image.dmg"), "64m", "GPTSPUD", "APFS", "", "Fixture")
	if err == nil || !strings.Contains(err.Error(), "Resource busy") {
		t.Fatalf("expected the busy error after the last attempt, got %v", err)
	}
	if len(cmd.calls) != 3 {
		t.Fatalf("expected exactly three attempts, got %d", len(cmd.calls))
	}
}

func TestCreateImageDoesNotRetryOtherFailures(t *testing.T) {
	cmd := &fakeCommander{sequence: map[string][]Result{"hdiutil": {{Status: 1, Stderr: []byte("hdiutil: create failed - No space left on device")}, {Status: 0}}}}
	d := &HostDisk{C: cmd, T: &Transcript{}}
	if err := d.CreateImage(context.Background(), filepath.Join(t.TempDir(), "image.dmg"), "64m", "GPTSPUD", "APFS", "", "Fixture"); err == nil {
		t.Fatal("a non-busy failure must return at once")
	}
	if len(cmd.calls) != 1 {
		t.Fatalf("expected one attempt, got %d", len(cmd.calls))
	}
}
