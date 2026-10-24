package native

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// SnapshotEditClocks projects the declared live writes onto Apple's original
// live inventory. The producer temporarily replaces these streams, restores
// their independently captured contents, and creates/removes allocation-probe.
// Historical views never enter this projection and retain all four clocks.
func SnapshotEditClocks(live schema.View, profile string, clockNS int64) (schema.View, error) {
	steps := []schema.Step{
		{FS: &schema.FSStep{Op: "write", Path: "$MOUNT/Fixture/hard-link"}},
		{FS: &schema.FSStep{Op: "write", Path: "$MOUNT/Fixture/clone.bin"}},
		{FS: &schema.FSStep{Op: "write", Path: "$MOUNT/Fixture/example.txt/..namedfork/rsrc"}},
		{FS: &schema.FSStep{Op: "setxattr", Path: "$MOUNT/Fixture/example.txt", Name: "org.go-apfs.binary"}},
		{FS: &schema.FSStep{Op: "write", Path: "$MOUNT/Fixture/allocation-probe"}},
		{FS: &schema.FSStep{Op: "unlink", Path: "$MOUNT/Fixture/allocation-probe"}},
	}
	return ProjectEditedViewClocks(live, live, steps, profile, clockNS)
}

func (v *Verifier) snapshotEditClocks(out schema.Output, target *schema.Observation) (map[string]schema.View, error) {
	if out.Source.Stage != "live" || out.Source.Profile != "apfs" && out.Source.Profile != "apfsx" || out.Operation != "edit" || out.Format != "UDZO" || out.Encrypted || out.Password != "" || !expectationsEqual(out.Expect, schema.Expectation{CommandClockNS: replayCommandClock, Continuation: true}) || target == nil || len(target.Volumes) != 1 || target.Volumes[0].APFS == nil || len(target.Volumes[0].APFS.Snapshots) != 2 {
		return nil, fmt.Errorf("snapshot edit lacks its strict retained-history contract")
	}
	if len(target.Views) != 3 {
		return nil, fmt.Errorf("snapshot edit requires the original live and both historical views")
	}
	for _, snapshot := range target.Volumes[0].APFS.Snapshots {
		if _, err := observedView(target, target.Volumes[0].Index, snapshot.Name); err != nil {
			return nil, err
		}
	}
	live, err := onlyLiveView(target)
	if err != nil {
		return nil, err
	}
	projected, err := SnapshotEditClocks(live, out.Source.Profile, out.Expect.CommandClockNS)
	if err != nil {
		return nil, err
	}
	return map[string]schema.View{volumeName(target.Volumes[0]): projected}, nil
}

// requireSnapshotEditOutputs keeps retained-history editing mandatory even if
// every portable producer accidentally omits the same capability.
func requireSnapshotEditOutputs(pairs []Paired, cases map[string]corpus.Case, major int) error {
	counts := map[string]int{}
	for _, p := range pairs {
		o := p.Output
		if o.Source.Producer != major || o.Source.Recipe != "snapshot-history" || o.Operation != "edit" {
			continue
		}
		k, ok := cases[CaseKey(o.Source)]
		if !ok {
			return fmt.Errorf("snapshot edit lacks its original Apple control")
		}
		v := Verifier{}
		if _, err := v.snapshotEditClocks(o, k.Observation); err != nil {
			return err
		}
		if !o.Expect.Continuation || o.Expect.ContinuationRefusal != "" {
			return fmt.Errorf("snapshot edit requires successful native/Go/native continuation")
		}
		counts[CaseKey(o.Source)]++
	}
	for _, profile := range []string{"apfs", "apfsx"} {
		ref := schema.CaseRef{Producer: major, Recipe: "snapshot-history", Profile: profile, Stage: "live"}
		if _, ok := cases[CaseKey(ref)]; !ok || counts[CaseKey(ref)] != 1 {
			return fmt.Errorf("snapshot edit %s requires one original control and one output", CaseKey(ref))
		}
	}
	return nil
}

func hasHistoricalViews(observation *schema.Observation) bool {
	if observation != nil {
		for _, view := range observation.Views {
			if view.Snapshot != "" {
				return true
			}
		}
	}
	return false
}

// compareHistoricalViews is also used after native continuation: view counts
// alone cannot prove that historical streams or inode metadata survived.
func compareHistoricalViews(got, want *schema.Observation) error {
	if len(got.Views) != len(want.Views) {
		return fmt.Errorf("retained history view inventory changed")
	}
	for _, volume := range want.Volumes {
		actual, err := namedVolume(got, volumeName(volume))
		if err != nil {
			return err
		}
		for _, expected := range want.Views {
			if expected.Volume != volume.Index || expected.Snapshot == "" {
				continue
			}
			view, err := observedView(got, actual.Index, expected.Snapshot)
			if err != nil {
				return err
			}
			if differences := CompareViews(view, expected, CompareOptions{}); len(differences) != 0 {
				return fmt.Errorf("retained snapshot %q changed: %v", expected.Snapshot, differences)
			}
		}
	}
	return nil
}
