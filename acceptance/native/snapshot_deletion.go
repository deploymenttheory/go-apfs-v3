package native

import (
	"fmt"
	"slices"
	"sort"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// SnapshotDeletionReference projects only explicit inventory/view removal from
// Apple's original two-snapshot control. No output content supplies expectations.
// All survivor metadata, identities, streams and four clocks remain unchanged.
func SnapshotDeletionReference(
	original *schema.Observation,
	deleted []schema.SnapshotIdentity,
) (*schema.Observation, error) {
	if original == nil || len(original.Volumes) != 1 {
		return nil, fmt.Errorf("snapshot deletion requires one explicitly selected volume")
	}
	return VolumeSnapshotDeletionReference(original, volumeName(original.Volumes[0]), deleted)
}

// VolumeSnapshotDeletionReference removes only selected snapshot identities;
// peer volumes, credentials and every surviving view remain original evidence.
func VolumeSnapshotDeletionReference(
	original *schema.Observation,
	name string,
	deleted []schema.SnapshotIdentity,
) (*schema.Observation, error) {
	if original == nil {
		return nil, fmt.Errorf("snapshot deletion requires an original observation")
	}
	volume, err := namedVolume(original, name)
	if err != nil || volume.APFS == nil || len(volume.APFS.Snapshots) != 2 || len(deleted) < 1 || len(deleted) > 2 {
		return nil, fmt.Errorf("snapshot deletion requires a selected live/two-history control")
	}
	inventory := volume.APFS.Snapshots
	names, xids := map[string]bool{}, map[uint64]bool{}
	for _, s := range inventory {
		if s.Name == "" || s.XID == 0 || names[s.Name] || xids[s.XID] {
			return nil, fmt.Errorf("ambiguous original snapshot identity")
		}
		names[s.Name], xids[s.XID] = true, true
		if _, err := observedView(original, volume.Index, s.Name); err != nil {
			return nil, err
		}
	}
	if _, err := observedView(original, volume.Index, ""); err != nil {
		return nil, err
	}
	selectedViews := 0
	for _, view := range original.Views {
		if view.Volume == volume.Index {
			selectedViews++
		}
	}
	if selectedViews != len(inventory)+1 {
		return nil, fmt.Errorf("snapshot deletion has an unexpected selected-volume view")
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
	apfs := *volume.APFS
	apfs.Snapshots = nil
	for _, s := range inventory {
		if !removed[s.Name] {
			apfs.Snapshots = append(apfs.Snapshots, s)
		}
	}
	for i := range result.Volumes {
		if result.Volumes[i].Index == volume.Index {
			result.Volumes[i].APFS = &apfs
		}
	}
	result.Views = nil
	for _, view := range original.Views {
		if view.Volume != volume.Index || !removed[view.Snapshot] {
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
	validSource := out.Source.Recipe == "snapshot-history" && out.Source.Stage == "live"
	outer, password := false, ""
	if out.Source.Recipe == "encrypted-snapshot-history" {
		_, validSource = encryptedSnapshotDeletionMatrix()[out.Source.Stage]
		expected.Volume = "EncryptedHistory"
		outer = out.Source.Stage == "aes128-nested" || out.Source.Stage == "aes256-nested"
		if outer {
			password = "encrypted-snapshot-history.image"
		}
	}
	if out.Operation != "delete-snapshot" || !validSource ||
		(out.Source.Profile != "apfs" && out.Source.Profile != "apfsx") ||
		out.Format != "UDZO" || out.Encrypted != outer || out.Password != password ||
		out.HostInput != nil || !expectationsEqual(out.Expect, expected) {
		return nil, fmt.Errorf("snapshot deletion lacks its strict original-history contract")
	}
	if expected.Volume != "" {
		orders, err := EncryptedSnapshotDeletionOrders(out.Source, original)
		if err != nil || !slices.ContainsFunc(orders, func(order []schema.SnapshotIdentity) bool {
			return slices.Equal(order, out.Expect.DeletedSnapshots)
		}) {
			return nil, fmt.Errorf("undeclared encrypted snapshot deletion order")
		}
		return VolumeSnapshotDeletionReference(original, expected.Volume, out.Expect.DeletedSnapshots)
	}
	return SnapshotDeletionReference(original, out.Expect.DeletedSnapshots)
}

// SnapshotDeletionOrders enumerates the required states using only native XIDs.
func SnapshotDeletionOrders(original *schema.Observation) ([][]schema.SnapshotIdentity, error) {
	if original == nil || len(original.Volumes) != 1 {
		return nil, fmt.Errorf("snapshot deletion requires one explicitly selected volume")
	}
	return VolumeSnapshotDeletionOrders(original, volumeName(original.Volumes[0]))
}

// VolumeSnapshotDeletionOrders enumerates both orders from a selected volume's
// native names and XIDs, independently of the other volumes' histories.
func VolumeSnapshotDeletionOrders(original *schema.Observation, name string) ([][]schema.SnapshotIdentity, error) {
	if original == nil {
		return nil, fmt.Errorf("snapshot deletion requires an original observation")
	}
	volume, err := namedVolume(original, name)
	if err != nil || volume.APFS == nil || len(volume.APFS.Snapshots) != 2 {
		return nil, fmt.Errorf("snapshot deletion requires two selected native snapshots")
	}
	s := append([]schema.Snapshot(nil), volume.APFS.Snapshots...)
	sort.Slice(s, func(i, j int) bool { return s[i].XID < s[j].XID })
	a, b := schema.SnapshotIdentity{Name: s[0].Name, XID: s[0].XID}, schema.SnapshotIdentity{Name: s[1].Name, XID: s[1].XID}
	orders := [][]schema.SnapshotIdentity{{a}, {b}, {a, b}, {b, a}}
	for _, d := range orders {
		if _, err := VolumeSnapshotDeletionReference(original, name, d); err != nil {
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
	for _, profile := range []string{"apfs", "apfsx"} {
		for stage := range encryptedSnapshotDeletionMatrix() {
			ref := schema.CaseRef{Producer: major, Recipe: "encrypted-snapshot-history", Profile: profile, Stage: stage}
			k, ok := cases[CaseKey(ref)]
			if !ok {
				return fmt.Errorf("missing encrypted snapshot deletion source %s", CaseKey(ref))
			}
			orders, err := EncryptedSnapshotDeletionOrders(ref, k.Observation)
			if err != nil {
				return err
			}
			for _, order := range orders {
				if counts[fmt.Sprintf("%s:%v", CaseKey(ref), order)] != 1 {
					return fmt.Errorf("encrypted snapshot deletion %s requires each declared order exactly once", CaseKey(ref))
				}
			}
		}
		for _, control := range encryptedSnapshotDeletionControls() {
			ref := schema.CaseRef{Producer: major, Recipe: "encrypted-snapshot-history", Profile: profile, Stage: control.stage}
			after, ok := cases[CaseKey(ref)]
			if !ok {
				return fmt.Errorf("missing positive native encrypted deletion control %s", CaseKey(ref))
			}
			ref.Stage = control.source
			before := cases[CaseKey(ref)]
			orders, err := VolumeSnapshotDeletionOrders(before.Observation, "EncryptedHistory")
			if err != nil {
				return err
			}
			want, err := VolumeSnapshotDeletionReference(before.Observation, "EncryptedHistory", orders[control.order])
			if err != nil {
				return err
			}
			diffs, err := compareObservationViews(after.Observation, want, CompareOptions{})
			if err != nil || len(diffs) != 0 {
				return fmt.Errorf("native encrypted deletion %s changed surviving state: %v: %v", control.stage, diffs, err)
			}
		}
	}
	return nil
}

func encryptedSnapshotDeletionMatrix() map[string][]int {
	return map[string][]int{
		"password-changed": {0, 1, 2, 3},
		"decrypted":        {0},
		"converted":        {1},
		"aes128-nested":    {0},
		"aes256-nested":    {3},
	}
}

// EncryptedSnapshotDeletionOrders selects the bounded encrypted/converted
// deletion journeys, using the original native identities for each source.
func EncryptedSnapshotDeletionOrders(
	source schema.CaseRef,
	original *schema.Observation,
) ([][]schema.SnapshotIdentity, error) {
	indices, ok := encryptedSnapshotDeletionMatrix()[source.Stage]
	if source.Recipe != "encrypted-snapshot-history" || !ok {
		return nil, fmt.Errorf("unqualified encrypted snapshot deletion source")
	}
	orders, err := VolumeSnapshotDeletionOrders(original, "EncryptedHistory")
	if err != nil {
		return nil, err
	}
	volume, err := namedVolume(original, "EncryptedHistory")
	if err != nil || volume.APFS.Encrypted != (source.Stage != "decrypted") {
		return nil, fmt.Errorf("native deletion source has the wrong volume encryption state")
	}
	result := make([][]schema.SnapshotIdentity, 0, len(indices))
	for _, index := range indices {
		result = append(result, orders[index])
	}
	return result, nil
}

func encryptedSnapshotDeletionControls() []struct {
	stage, source string
	order         int
} {
	return []struct {
		stage, source string
		order         int
	}{
		{stage: "oldest-deleted", source: "password-changed", order: 0},
		{stage: "newest-deleted", source: "password-changed", order: 1},
		{stage: "all-oldest-first", source: "password-changed", order: 2},
		{stage: "all-newest-first", source: "password-changed", order: 3},
		{stage: "decrypted-oldest-deleted", source: "decrypted", order: 0},
		{stage: "converted-newest-deleted", source: "converted", order: 1},
	}
}
