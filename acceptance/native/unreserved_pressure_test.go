package native

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
)

func TestUnreservedPressureRetainsFullAndPartialFilesThroughProtectedAllocation(t *testing.T) {
	for _, outcome := range []string{"not created", "partial", "sync"} {
		t.Run(outcome, func(t *testing.T) {
			v, att, out, volume := containerPressureProtocol(t)
			volume.pressureOutcome = outcome
			if _, err := v.containerWrites(context.Background(), att, out, "writable.raw"); err != nil {
				t.Fatal(err)
			}
			directory := filepath.Join("/container", "Fresh Empty", "container-continuation", "pressure")
			want := []string{filepath.Join(directory, "00000"), filepath.Join(directory, "00001")}
			if outcome != "not created" {
				want = append(want, filepath.Join(directory, "00002"))
			}
			if volume.pressureAttempts != 3 || !reflect.DeepEqual(volume.unlinkedPressure, want) {
				t.Fatalf("full/partial pressure was not released exactly once in order: attempts=%d, removed=%v", volume.pressureAttempts, volume.unlinkedPressure)
			}
		})
	}
}

func TestUnreservedPartialFileCleanupFailureIsFatal(t *testing.T) {
	v, att, out, volume := containerPressureProtocol(t)
	volume.pressureOutcome = "partial"
	filename := filepath.Join("/container", "Fresh Empty", "container-continuation", "pressure", "00002")
	volume.fail = "unlink:" + filename
	if _, err := v.containerWrites(context.Background(), att, out, "writable.raw"); !errors.Is(err, syscall.EIO) || volume.failCalls != 1 || volume.peerWrites != 0 || len(v.Disk.(*containerPressureDisk).events) != 0 {
		t.Fatalf("partial-file cleanup failure was ignored, retried or reached clean close: %v", err)
	}
}

// pressureSequenceVolume lets the bounded-allocation controls run without
// retaining 256 MiB in memory. Successful writes and syncs still have to name
// distinct files in the required order and use the exact native chunk size.
type pressureSequenceVolume struct {
	fixture.Volume
	writeErr, syncErr error
	failAt            int
	writes, syncs     int
	last              string
}

func (v *pressureSequenceVolume) WriteFile(filename string, data []byte, exclusive bool) error {
	i := v.writes
	v.writes++
	if !exclusive || len(data) != unreservedPressureChunk || filepath.Base(filename) != fmt.Sprintf("%05d", i) {
		return fmt.Errorf("pressure file does not match native geometry")
	}
	v.last = filename
	if i == v.failAt && v.writeErr != nil {
		return v.writeErr
	}
	return nil
}

func (v *pressureSequenceVolume) Fullfsync(filename string) error {
	if filename != v.last {
		return fmt.Errorf("pressure sync did not follow its own file write")
	}
	i := v.syncs
	v.syncs++
	if i == v.failAt {
		return v.syncErr
	}
	return nil
}

func TestUnreservedPressureRequiresBoundedENOSPCAndASyncedFile(t *testing.T) {
	for _, tc := range []struct {
		name      string
		writeErr  error
		syncErr   error
		failAt    int
		wantCalls int
		accept    bool
	}{
		{"ENOSPC after a synced file", syscall.ENOSPC, nil, 1, 2, true},
		{"ENOSPC before any write", syscall.ENOSPC, nil, 0, 1, false},
		{"sync ENOSPC without its file", nil, syscall.ENOSPC, 1, 2, false},
		{"unrelated I/O failure", syscall.EIO, nil, 1, 2, false},
		{"permission refusal", syscall.EACCES, nil, 1, 2, false},
		{"unexpected quota", syscall.EDQUOT, nil, 1, 2, false},
		{"sync I/O failure", nil, syscall.EIO, 1, 2, false},
		{"no allocation limit", nil, nil, 0, unreservedPressureBound / unreservedPressureChunk, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			volume := &pressureSequenceVolume{Volume: fixture.NewMemoryVolume("/volume"), writeErr: tc.writeErr, syncErr: tc.syncErr, failAt: tc.failAt}
			v := &Verifier{Vol: volume}
			_, err := v.fillUnreservedPressure(context.Background(), filepath.Join("/volume", "pressure"))
			if (err == nil) != tc.accept || volume.writes != tc.wantCalls {
				t.Fatalf("pressure outcome=%v, writes=%d, want accept=%v/calls=%d", err, volume.writes, tc.accept, tc.wantCalls)
			}
			if !tc.accept && tc.writeErr != nil && tc.writeErr != syscall.ENOSPC && !errors.Is(err, tc.writeErr) {
				t.Fatalf("unexpected native failure lost its cause: %v", err)
			}
		})
	}
}

func TestUnreservedPressureCancellationDoesNotAllocate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	volume := &pressureSequenceVolume{Volume: fixture.NewMemoryVolume("/volume")}
	if _, err := (&Verifier{Vol: volume}).fillUnreservedPressure(ctx, filepath.Join("/volume", "pressure")); !errors.Is(err, context.Canceled) || volume.writes != 0 {
		t.Fatalf("cancelled pressure allocated files: %v, writes=%d", err, volume.writes)
	}
}

func TestUnreservedPressureReleaseRejectsMissingAndUnexpectedFiles(t *testing.T) {
	for _, missing := range []bool{true, false} {
		t.Run(fmt.Sprint("missing-", missing), func(t *testing.T) {
			memory := fixture.NewMemoryVolume("/volume")
			directory := filepath.Join("/volume", "pressure")
			if err := memory.Mkdir(directory, 0o755); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(directory, "00000")
			if !missing {
				for name, data := range map[string]string{file: "pressure", filepath.Join(directory, "unexpected"): "must remain"} {
					if err := memory.WriteFile(name, []byte(data), true); err != nil {
						t.Fatal(err)
					}
				}
			}
			err := (&Verifier{Vol: memory}).releaseUnreservedPressure(directory, []string{file})
			if err == nil || (missing && !errors.Is(err, syscall.ENOENT)) || (!missing && !strings.Contains(err.Error(), "remove pressure directory")) {
				t.Fatalf("unexpected pressure cleanup state was accepted: %v", err)
			}
		})
	}
}
