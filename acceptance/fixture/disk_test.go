package fixture

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

func TestCreateImageRetriesWhileTheDiskImageFrameworkIsBusy(t *testing.T) {
	instantWaits(t)
	busy := Result{Status: 1, Stderr: []byte("hdiutil: create failed - Resource busy")}
	cmd := &fakeCommander{sequence: map[string][]Result{"hdiutil": {busy, {Status: 0}}}}
	d := &HostDisk{C: cmd, T: &Transcript{}}
	path := filepath.Join(t.TempDir(), "image.dmg")
	if err := d.CreateImage(context.Background(), path, "64m", "GPTSPUD", "APFS", "", "Fixture"); err != nil {
		t.Fatalf("a busy framework followed by success should create the image: %v", err)
	}
	if len(cmd.calls) != 2 || len(d.T.Commands) != 3 {
		t.Fatalf("expected both attempts and the wait between them in the transcript, got %d calls and %d transcript entries", len(cmd.calls), len(d.T.Commands))
	}
}

func TestCreateImageGivesUpWhenTheBusyBudgetIsSpent(t *testing.T) {
	instantWaits(t)
	busy := Result{Status: 1, Stderr: []byte("hdiutil: create failed - Resource busy")}
	var queue []Result
	for range BusyWait.Attempts {
		queue = append(queue, busy)
	}
	cmd := &fakeCommander{sequence: map[string][]Result{"hdiutil": append(queue, Result{Status: 0})}}
	d := &HostDisk{C: cmd, T: &Transcript{}}
	err := d.CreateImage(context.Background(), filepath.Join(t.TempDir(), "image.dmg"), "64m", "GPTSPUD", "APFS", "", "Fixture")
	if err == nil || !strings.Contains(err.Error(), "Resource busy") {
		t.Fatalf("expected the busy error after the last attempt, got %v", err)
	}
	if len(cmd.calls) != BusyWait.Attempts {
		t.Fatalf("expected exactly %d attempts, got %d", BusyWait.Attempts, len(cmd.calls))
	}
}

func TestCreateImageDoesNotRetryOtherFailures(t *testing.T) {
	instantWaits(t)
	cmd := &fakeCommander{sequence: map[string][]Result{"hdiutil": {{Status: 1, Stderr: []byte("hdiutil: create failed - No space left on device")}, {Status: 0}}}}
	d := &HostDisk{C: cmd, T: &Transcript{}}
	if err := d.CreateImage(context.Background(), filepath.Join(t.TempDir(), "image.dmg"), "64m", "GPTSPUD", "APFS", "", "Fixture"); err == nil {
		t.Fatal("a non-busy failure must return at once")
	}
	if len(cmd.calls) != 1 {
		t.Fatalf("expected one attempt, got %d", len(cmd.calls))
	}
}

func TestUnmountPathRetriesOnlyTransientBusySnapshot(t *testing.T) {
	instantWaits(t)
	path := "/tmp/fixture-snapshot"
	busy := Result{Status: 1, Stderr: []byte("umount: Resource busy -- try 'diskutil unmount'")}
	cmd := &fakeCommander{sequence: map[string][]Result{"/sbin/umount": {busy, {Status: 0}}}}
	d := &HostDisk{C: cmd, T: &Transcript{}}
	if err := d.UnmountPath(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if len(cmd.calls) != 2 || len(d.T.Commands) != 3 ||
		d.T.Commands[0].Status != "1" ||
		d.T.Commands[1].Label != "wait:snapshot-unmount-busy" ||
		d.T.Commands[2].Status != "0" {
		t.Fatalf("busy unmount attempts were not retained: calls=%v transcript=%+v", cmd.calls, d.T.Commands)
	}
}

func TestUnmountPathStopsAtNonBusyFailure(t *testing.T) {
	instantWaits(t)
	cmd := &fakeCommander{sequence: map[string][]Result{"/sbin/umount": {
		{Status: 1, Stderr: []byte("umount: permission denied")}, {Status: 0},
	}}}
	d := &HostDisk{C: cmd, T: &Transcript{}}
	if err := d.UnmountPath(context.Background(), "/tmp/fixture-snapshot"); err == nil ||
		len(cmd.calls) != 1 {
		t.Fatalf("non-busy unmount should fail once: %v, calls=%v", err, cmd.calls)
	}
}

func TestUnmountPathDoesNotRetryCommandFailuresMentioningBusy(t *testing.T) {
	for _, status := range []int{-1, 1} {
		t.Run(fmt.Sprintf("status-%d", status), func(t *testing.T) {
			instantWaits(t)
			cause := errors.New("launch failed: Resource busy")
			cmd := &fakeCommander{sequence: map[string][]Result{"/sbin/umount": {
				{Status: status, Err: cause, Stderr: []byte("Resource busy")}, {Status: 0},
			}}}
			d := &HostDisk{C: cmd, T: &Transcript{}}
			err := d.UnmountPath(context.Background(), "/tmp/fixture-snapshot")
			if !errors.Is(err, cause) || len(cmd.calls) != 1 || len(d.T.Commands) != 1 {
				t.Fatalf("command failure was retried or lost: %v, calls=%v, transcript=%+v", err, cmd.calls, d.T.Commands)
			}
		})
	}
}

func TestUnmountPathDoesNotRunAfterCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	cmd := &fakeCommander{}
	d := &HostDisk{C: cmd, T: &Transcript{}}
	if err := d.UnmountPath(ctx, "/tmp/fixture-snapshot"); !errors.Is(err, context.Canceled) || len(cmd.calls) != 0 {
		t.Fatalf("cancelled unmount ran a command or lost cancellation: %v, calls=%v", err, cmd.calls)
	}
}

func TestUnmountPathStopsAfterBusyBudget(t *testing.T) {
	instantWaits(t)
	busy := Result{Status: 1, Stderr: []byte("umount: Resource busy")}
	queue := make([]Result, BusyWait.Attempts)
	for i := range queue {
		queue[i] = busy
	}
	cmd := &fakeCommander{sequence: map[string][]Result{"/sbin/umount": queue}}
	d := &HostDisk{C: cmd, T: &Transcript{}}
	err := d.UnmountPath(context.Background(), "/tmp/fixture-snapshot")
	if err == nil || !strings.Contains(err.Error(), "Resource busy") ||
		len(cmd.calls) != BusyWait.Attempts {
		t.Fatalf("busy unmount exceeded its retry budget: %v, calls=%v", err, cmd.calls)
	}
}

func TestWholeDiskIsTheImagesPartitionedDisk(t *testing.T) {
	gpt, store := "GUID_partition_scheme", "EF57347C-0000-11AA-AA11-00306543ECAC"
	for _, tc := range []struct {
		entries []diskEntity
		want    string
	}{
		// The synthesized container took a lower, freed device number.
		{[]diskEntity{{"/dev/disk6", store}, {"/dev/disk6s1", "41504653-0000-11AA-AA11-00306543ECAC"}, {"/dev/disk7", gpt}, {"/dev/disk7s1", store}}, "/dev/disk7"},
		{[]diskEntity{{"/dev/disk12", gpt}, {"/dev/disk12s1", store}, {"/dev/disk13", store}}, "/dev/disk12"},
		{[]diskEntity{{"/dev/disk9", "Apple_partition_scheme"}, {"/dev/disk9s1", "Apple_partition_map"}, {"/dev/disk9s2", "Apple_HFS"}}, "/dev/disk9"},
		// Without a partition map: the lowest-numbered whole disk.
		{[]diskEntity{{"/dev/disk5", store}, {"/dev/disk4", store}, {"/dev/disk5s1", "41504653-0000-11AA-AA11-00306543ECAC"}}, "/dev/disk4"},
		{[]diskEntity{{"/dev/disk4", "Apple_HFS"}}, "/dev/disk4"},
	} {
		if got, ok := wholeDisk(tc.entries); !ok || got != tc.want {
			t.Errorf("wholeDisk(%v) = %q, want %q", tc.entries, got, tc.want)
		}
	}
	if _, ok := wholeDisk([]diskEntity{{"/dev/disk4s1", "Apple_HFS"}}); ok {
		t.Error("a slice alone is not a whole disk")
	}
}
