package native

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/fixture"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// comparePreservedVolumeMetadata compares immutable filesystem identities and
// policies using only Apple's observations and original diskutil transcripts.
// Attachment indices, free-space counters, mount paths and journal contents can
// change during observation or mutation and are deliberately not static facts.
func comparePreservedVolumeMetadata(got, want *schema.Observation) ([]Difference, error) {
	actual, err := metadataVolumes(got)
	if err != nil {
		return nil, fmt.Errorf("actual volume metadata: %w", err)
	}
	expected, err := metadataVolumes(want)
	if err != nil {
		return nil, fmt.Errorf("expected volume metadata: %w", err)
	}
	if len(actual) != len(expected) {
		return nil, fmt.Errorf("volume metadata inventory: got %d volumes, want %d", len(actual), len(expected))
	}
	var names []string
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	var diffs []Difference
	for _, name := range names {
		w := expected[name]
		g, ok := actual[name]
		if !ok {
			return nil, fmt.Errorf("missing preserved volume %q", name)
		}
		add := func(field string, actual, expected any) {
			a, e := fmt.Sprint(actual), fmt.Sprint(expected)
			if a != e {
				diffs = append(diffs, Difference{Path: name, Field: "volume." + field, Got: a, Want: e})
			}
		}
		add("APFS", g.APFS != nil, w.APFS != nil)
		add("HFS", g.HFS != nil, w.HFS != nil)
		if g.APFS != nil && w.APFS != nil {
			add("uuid", strings.ToUpper(g.APFS.VolumeUUID), strings.ToUpper(w.APFS.VolumeUUID))
			add("containerUUID", strings.ToUpper(g.APFS.ContainerUUID), strings.ToUpper(w.APFS.ContainerUUID))
			add("caseSensitive", g.APFS.CaseSensitive, w.APFS.CaseSensitive)
			add("role", g.APFS.Role, w.APFS.Role)
			add("groupUUID", strings.ToUpper(g.APFS.GroupUUID), strings.ToUpper(w.APFS.GroupUUID))
			add("reserveBytes", g.APFS.ReserveBytes, w.APFS.ReserveBytes)
			add("quotaBytes", g.APFS.QuotaBytes, w.APFS.QuotaBytes)
			add("encrypted", g.APFS.Encrypted, w.APFS.Encrypted)
			add("encRolled", g.APFS.EncRolled, w.APFS.EncRolled)
			d, err := compareSnapshotMetadata(name, g.APFS.Snapshots, w.APFS.Snapshots)
			if err != nil {
				return nil, err
			}
			diffs = append(diffs, d...)
		}
		if g.HFS != nil && w.HFS != nil {
			add("caseSensitive", g.HFS.CaseSensitive, w.HFS.CaseSensitive)
			add("journaled", g.HFS.Journaled, w.HFS.Journaled)
			if uuid, observed := w.Diskutil["VolumeUUID"]; observed {
				actual, ok := g.Diskutil["VolumeUUID"]
				if !ok {
					add("uuid", "absent", uuid)
				} else {
					add("uuid", strings.ToUpper(fmt.Sprint(actual)), strings.ToUpper(fmt.Sprint(uuid)))
				}
			}
			for _, field := range []string{"TotalSize", "Size", "VolumeAllocationBlockSize"} {
				value, observed := w.Diskutil[field]
				if !observed {
					continue
				}
				wantNumber, ok := metadataInteger(value)
				if !ok {
					return nil, fmt.Errorf("volume %s: invalid native %s %v", name, field, value)
				}
				gotValue, present := g.Diskutil[field]
				gotNumber, valid := metadataInteger(gotValue)
				if !present || !valid {
					add(field, "absent or invalid", wantNumber)
				} else {
					add(field, gotNumber, wantNumber)
				}
			}
		}
	}
	return diffs, nil
}

func metadataVolumes(obs *schema.Observation) (map[string]schema.Volume, error) {
	if obs == nil {
		return nil, fmt.Errorf("missing observation")
	}
	byName := make(map[string]schema.Volume, len(obs.Volumes))
	var apfsVolumes []schema.Volume
	for _, volume := range obs.Volumes {
		name, _ := volume.Diskutil["VolumeName"].(string)
		if name == "" {
			return nil, fmt.Errorf("unnamed observed volume")
		}
		if _, duplicate := byName[name]; duplicate {
			return nil, fmt.Errorf("duplicate observed volume name %q", name)
		}
		if volume.APFS != nil && volume.HFS != nil {
			return nil, fmt.Errorf("volume %s is both APFS and HFS", name)
		}
		byName[name] = volume
		if volume.APFS != nil {
			apfsVolumes = append(apfsVolumes, volume)
		}
	}
	if len(apfsVolumes) != 0 {
		// A mixed disk may also contain HFS volumes; only APFS records belong
		// in the independently retained APFS container listing.
		apfs := *obs
		apfs.Volumes = apfsVolumes
		enriched, err := fixture.APFSInventory(&apfs)
		if err != nil {
			return nil, err
		}
		for _, volume := range enriched {
			name, _ := volume.Diskutil["VolumeName"].(string)
			byName[name] = volume
		}
	}
	return byName, nil
}

func compareSnapshotMetadata(volume string, got, want []schema.Snapshot) ([]Difference, error) {
	index := func(snapshots []schema.Snapshot) (map[string]schema.Snapshot, error) {
		byName := make(map[string]schema.Snapshot, len(snapshots))
		for _, snapshot := range snapshots {
			if _, duplicate := byName[snapshot.Name]; snapshot.Name == "" || duplicate {
				return nil, fmt.Errorf("volume %s has unnamed or duplicate snapshot %q", volume, snapshot.Name)
			}
			byName[snapshot.Name] = snapshot
		}
		return byName, nil
	}
	actual, err := index(got)
	if err != nil {
		return nil, err
	}
	expected, err := index(want)
	if err != nil {
		return nil, err
	}
	var names []string
	for name := range expected {
		names = append(names, name)
	}
	sort.Strings(names)
	var diffs []Difference
	for _, name := range names {
		w := expected[name]
		g, ok := actual[name]
		field := "volume.snapshot." + name
		if !ok {
			diffs = append(diffs, Difference{Path: volume, Field: field, Got: "absent", Want: "present"})
			continue
		}
		g.UUID, w.UUID = strings.ToUpper(g.UUID), strings.ToUpper(w.UUID)
		if g != w {
			diffs = append(diffs, Difference{Path: volume, Field: field, Got: fmt.Sprint(g), Want: fmt.Sprint(w)})
		}
		delete(actual, name)
	}
	names = names[:0]
	for name := range actual {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		diffs = append(diffs, Difference{Path: volume, Field: "volume.snapshot." + name, Got: "present", Want: "absent"})
	}
	return diffs, nil
}

func metadataInteger(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), v >= 0
	case int64:
		return v, v >= 0
	case uint64:
		return int64(v), v <= math.MaxInt64
	case float64:
		if v >= 0 && v < float64(math.MaxInt64) && math.Trunc(v) == v {
			return int64(v), true
		}
	case json.Number:
		n, err := v.Int64()
		return n, err == nil && n >= 0
	}
	return 0, false
}
