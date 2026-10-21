package native

import (
	"fmt"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/corpus"
	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func volumeName(volume schema.Volume) string {
	name, _ := volume.Diskutil["VolumeName"].(string)
	return name
}

func namedVolume(obs *schema.Observation, name string) (schema.Volume, error) {
	var found []schema.Volume
	for _, volume := range obs.Volumes {
		if volumeName(volume) == name {
			found = append(found, volume)
		}
	}
	if len(found) != 1 {
		return schema.Volume{}, fmt.Errorf("volume %q: got %d matches, want exactly one", name, len(found))
	}
	return found[0], nil
}

func observedView(obs *schema.Observation, volume int, snapshot string) (schema.View, error) {
	var found []schema.View
	for _, view := range obs.Views {
		if view.Volume == volume && view.Snapshot == snapshot {
			found = append(found, view)
		}
	}
	if len(found) != 1 {
		return schema.View{}, fmt.Errorf("volume %d snapshot %q: got %d views, want exactly one", volume, snapshot, len(found))
	}
	return found[0], nil
}

func onlyLiveView(obs *schema.Observation) (schema.View, error) {
	if len(obs.Volumes) != 1 {
		return schema.View{}, fmt.Errorf("single-volume output has %d volumes", len(obs.Volumes))
	}
	return observedView(obs, obs.Volumes[0].Index, "")
}

// compareObservationViews matches volumes by name, rather than attachment order,
// and requires every live and historical view on both sides to be present.
func compareObservationViews(got, want *schema.Observation, opts CompareOptions) ([]Difference, error) {
	if len(got.Volumes) != len(want.Volumes) || len(got.Views) != len(want.Views) {
		return nil, fmt.Errorf("observation inventory: got %d volumes/%d views, want %d/%d", len(got.Volumes), len(got.Views), len(want.Volumes), len(want.Views))
	}
	var diffs []Difference
	metadataDiffs, err := comparePreservedVolumeMetadata(got, want)
	if err != nil {
		return nil, err
	}
	diffs = append(diffs, metadataDiffs...)
	for _, expected := range want.Volumes {
		volume, err := namedVolume(got, volumeName(expected))
		if err != nil {
			return nil, err
		}
		for _, view := range want.Views {
			if view.Volume != expected.Index {
				continue
			}
			actual, err := observedView(got, volume.Index, view.Snapshot)
			if err != nil {
				return nil, err
			}
			diffs = append(diffs, CompareViews(actual, view, opts)...)
		}
	}
	return diffs, nil
}

// compareEditedVolumes requires preservation of peer volumes as well as the
// selected edited volume. Relaxations apply only to the selected volume.
func (v *Verifier) compareEditedVolumes(got *schema.Observation, k corpus.Case, out schema.Output, opts CompareOptions) ([]Difference, error) {
	want := k.Observation
	if len(got.Volumes) != len(want.Volumes) || len(got.Views) != len(want.Views) {
		return nil, fmt.Errorf("edited inventory: got %d volumes/%d views, want %d/%d", len(got.Volumes), len(got.Views), len(want.Volumes), len(want.Views))
	}
	selected := out.Expect.Volume
	if selected == "" && len(want.Volumes) == 1 {
		selected = volumeName(want.Volumes[0])
	}
	var diffs []Difference
	metadataDiffs, err := comparePreservedVolumeMetadata(got, want)
	if err != nil {
		return nil, err
	}
	diffs = append(diffs, metadataDiffs...)
	for _, expected := range want.Volumes {
		name := volumeName(expected)
		actual, err := namedVolume(got, name)
		if err != nil {
			return nil, err
		}
		for _, expectedView := range want.Views {
			if expectedView.Volume != expected.Index {
				continue
			}
			actualView, err := observedView(got, actual.Index, expectedView.Snapshot)
			if err != nil {
				return nil, err
			}
			viewOptions := CompareOptions{}
			if name == selected && expectedView.Snapshot == "" {
				viewOptions = opts
				if out.Expect.NewIdentities {
					viewOptions.Existing = v.existingPaths(out.Source, expected.Index)
				}
			}
			for _, difference := range CompareViews(actualView, expectedView, viewOptions) {
				difference.Path = name + ":" + difference.Path
				diffs = append(diffs, difference)
			}
		}
	}
	return diffs, nil
}
