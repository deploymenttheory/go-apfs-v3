package native

import (
	"fmt"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// SnapshotDeletionReference projects only explicit inventory/view removal from
// Apple's original two-snapshot control. No output content supplies expectations.
// All survivor metadata, identities, streams and four clocks remain unchanged.
func SnapshotDeletionReference(original *schema.Observation, deleted []schema.SnapshotIdentity) (*schema.Observation, error) {
	if original == nil || len(original.Volumes) != 1 || original.Volumes[0].APFS == nil || len(original.Volumes[0].APFS.Snapshots) != 2 || len(original.Views) != 3 || len(deleted) < 1 || len(deleted) > 2 {
		return nil, fmt.Errorf("snapshot deletion requires the original live/two-history control")
	}
	inventory := original.Volumes[0].APFS.Snapshots
	names, xids := map[string]bool{}, map[uint64]bool{}
	for _, s := range inventory {
		if s.Name == "" || s.XID == 0 || names[s.Name] || xids[s.XID] {
			return nil, fmt.Errorf("ambiguous original snapshot identity")
		}
		names[s.Name], xids[s.XID] = true, true
		if _, err := observedView(original, original.Volumes[0].Index, s.Name); err != nil {
			return nil, err
		}
	}
	if _, err := onlyLiveView(original); err != nil {
		return nil, err
	}
	removed := map[string]bool{}
	for _, d := range deleted {
		found := false
		for _, s := range inventory {
			if s.Name == d.Name && s.XID == d.XID {
				found = true
			}
		}
		if !found || removed[d.Name] {
			return nil, fmt.Errorf("deleted snapshot is not a unique exact original identity: %+v", d)
		}
		removed[d.Name] = true
	}
	result := *original
	result.Volumes = append([]schema.Volume(nil), original.Volumes...)
	apfs := *original.Volumes[0].APFS
	apfs.Snapshots = nil
	for _, s := range inventory {
		if !removed[s.Name] {
			apfs.Snapshots = append(apfs.Snapshots, s)
		}
	}
	result.Volumes[0].APFS = &apfs
	result.Views = nil
	for _, view := range original.Views {
		if !removed[view.Snapshot] {
			result.Views = append(result.Views, view)
		}
	}
	return &result, nil
}

func snapshotOutputReference(out schema.Output, original *schema.Observation) (*schema.Observation, error) {
	if out.Operation != "delete-snapshot" && len(out.Expect.DeletedSnapshots) == 0 {
		return original, nil
	}
	expected := schema.Expectation{DeletedSnapshots: out.Expect.DeletedSnapshots, Continuation: true}
	if out.Operation != "delete-snapshot" || out.Source.Recipe != "snapshot-history" || out.Source.Stage != "live" || (out.Source.Profile != "apfs" && out.Source.Profile != "apfsx") || out.Format != "UDZO" || out.Encrypted || out.Password != "" || out.HostInput != nil || !expectationsEqual(out.Expect, expected) {
		return nil, fmt.Errorf("snapshot deletion lacks its strict original-history contract")
	}
	return SnapshotDeletionReference(original, out.Expect.DeletedSnapshots)
}

// SnapshotDeletionOrders enumerates the required states using only native XIDs.
func SnapshotDeletionOrders(original *schema.Observation) ([][]schema.SnapshotIdentity, error) {
	if original == nil || len(original.Volumes) != 1 || original.Volumes[0].APFS == nil || len(original.Volumes[0].APFS.Snapshots) != 2 {
		return nil, fmt.Errorf("snapshot deletion requires two native snapshots")
	}
	s := append([]schema.Snapshot(nil), original.Volumes[0].APFS.Snapshots...)
	sort.Slice(s, func(i, j int) bool { return s[i].XID < s[j].XID })
	a, b := schema.SnapshotIdentity{Name: s[0].Name, XID: s[0].XID}, schema.SnapshotIdentity{Name: s[1].Name, XID: s[1].XID}
	orders := [][]schema.SnapshotIdentity{{a}, {b}, {a, b}, {b, a}}
	for _, d := range orders {
		if _, err := SnapshotDeletionReference(original, d); err != nil {
			return nil, err
		}
	}
	return orders, nil
}

func requireSnapshotDeletionOutputs(pairs []Paired, cases map[string]corpus.Case, major int) error {
	counts := map[string]int{}
	for _, p := range pairs {
		o := p.Output
		if o.Operation != "delete-snapshot" && len(o.Expect.DeletedSnapshots) == 0 {
			continue
		}
		k, ok := cases[CaseKey(o.Source)]
		if !ok || o.Source.Producer != major {
			return fmt.Errorf("snapshot deletion lacks its selected native source")
		}
		if _, err := snapshotOutputReference(o, k.Observation); err != nil {
			return err
		}
		counts[fmt.Sprintf("%s:%v", CaseKey(o.Source), o.Expect.DeletedSnapshots)]++
	}
	for _, profile := range []string{"apfs", "apfsx"} {
		ref := schema.CaseRef{Producer: major, Recipe: "snapshot-history", Profile: profile, Stage: "live"}
		k, ok := cases[CaseKey(ref)]
		if !ok {
			return fmt.Errorf("missing original snapshot deletion control %s", CaseKey(ref))
		}
		orders, err := SnapshotDeletionOrders(k.Observation)
		if err != nil {
			return err
		}
		for _, order := range orders {
			if counts[fmt.Sprintf("%s:%v", CaseKey(ref), order)] != 1 {
				return fmt.Errorf("snapshot deletion %s requires each oldest/newest/final order exactly once", CaseKey(ref))
			}
		}
	}
	return nil
}
