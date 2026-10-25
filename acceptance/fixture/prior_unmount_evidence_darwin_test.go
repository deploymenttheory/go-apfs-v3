package fixture

import (
	"context"
	"testing"
)

// These literal tuples are derived from release run 40162201430's original
// native26 artifact 12589521646 (ZIP SHA256
// 3641194bb3810281dd5b9b415dcabcfb2319c525f059a33b0fff725f733698b2).
// The original continuation-commands.json members remain unchanged. Their raw
// SHA256 values are bound to each case below; only Expected/Actual are replayed.
// Darwin paths stay literal, so this ordinary-file test has a Darwin filename.
// Its probe is entirely fake and performs no native filesystem operation.
func TestPriorUnmountObservationKeepsCapturedDarwinFilesystemChanges(t *testing.T) {
	for _, tc := range []struct {
		name, pin string
		expected  mountIdentity
	}{
		{
			// continuation/macos-26.snapshot-history.apfs.live.snapshot-edit.UDZO.dmg/
			// continuation-commands.json SHA256:
			// 10c4d4340186f38cfc454934aea0875ef7f666f90c1fb6cf8ce7503a8e3f75ca
			name: "snapshot history",
			pin:  "/Users/runner/work/_temp/native-work/continuation/macos-26.snapshot-history.apfs.live.snapshot-edit.UDZO.dmg/mnt/v3-snapshots",
			expected: mountIdentity{
				Source: "/dev/disk9s1",
				FSID:   [2]int32{16777243, 26},
			},
		},
		{
			// host-import/macos-26.workspace-edits.apfsx.before.edit.host-import.UDZO.dmg.continued/
			// darwin/continuation/macos-26.workspace-edits.apfsx.before.edit.host-import.UDZO.dmg/
			// continuation-commands.json SHA256:
			// 5ee9ebc872a376965e2381d2808de6429685a40a57e2496e1d817bee259eba33
			name: "host import",
			pin:  "/Users/runner/work/_temp/native-work/host-import/macos-26.workspace-edits.apfsx.before.edit.host-import.UDZO.dmg.continued/darwin/continuation/macos-26.workspace-edits.apfsx.before.edit.host-import.UDZO.dmg/mnt/workspace-edits",
			expected: mountIdentity{
				Source: "/dev/disk15s1",
				FSID:   [2]int32{16777255, 26},
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), busyProbeTimeout)
			defer cancel()
			tc.expected.MountPoint = tc.pin
			actual := mountIdentity{MountPoint: "/System/Volumes/Data", Source: "/dev/disk2s5", FSID: [2]int32{16777230, 26}}
			calls := 0
			row, err := probePriorUnmount(ctx, func(pin string) (mountIdentity, error) {
				calls++
				if pin != tc.pin {
					t.Fatalf("observation did not use the original private pin: %q", pin)
				}
				return actual, nil
			}, priorUnmountIdentity{Identity: tc.expected, Command: 8}, &diagnosticInvocationGate{})
			if err != nil || row.Outcome != "different-filesystem" || row.Error != "" {
				t.Fatalf("successful captured kernel observation was misclassified: outcome=%q, err=%v", row.Outcome, err)
			}
			if calls != 1 || row.Expected != tc.expected || row.Actual != actual || row.CanonicalPin != tc.pin || row.UnmountCommand != 8 || row.Started == "" || row.Returned == "" || row.Deadline == "" {
				t.Fatalf("classification changed original facts or invocation evidence: %+v (calls=%d)", row, calls)
			}
		})
	}
}
