package native

import (
	"fmt"
	"math"
	"slices"
	"time"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// CloneCopyCommandClock derives the public replay clock from the complete
// independent native stage inventory, one hour after its latest inode clock.
func CloneCopyCommandClock(views []schema.View) (int64, error) {
	if len(views) != 7 {
		return 0, fmt.Errorf("clone-copy clock requires all seven native stage views")
	}
	var latest int64
	for _, view := range views {
		if view.Snapshot != "" || len(view.Entries) == 0 {
			return 0, fmt.Errorf("clone-copy clock requires nonempty live native views")
		}
		for _, entry := range view.Entries {
			latest = max(latest, entry.Times.Birth, entry.Times.Modify, entry.Times.Change, entry.Times.Access)
		}
	}
	if latest <= 0 || latest > math.MaxInt64-int64(time.Hour) {
		return 0, fmt.Errorf("clone-copy native clocks are outside replay bounds")
	}
	return time.Unix(0, latest).Add(time.Hour).Truncate(time.Second).UnixNano(), nil
}

func (v *Verifier) cloneCopyClockView(out schema.Output, target *schema.Observation) (schema.View, error) {
	stages := []string{"before", "copied", "data-replaced", "fork-replaced", "attribute-replaced", "source-removed", "refused"}
	if out.Source.Recipe != "clone-copy" || !slices.Contains([]string{"edit", "build"}, out.Operation) || !out.Expect.NewIdentities || len(out.Expect.IgnoreTimes) != 0 || out.Expect.Workspace != nil || out.Expect.Snapshot != "" {
		return schema.View{}, fmt.Errorf("clone-copy output lacks strict command-clock policy")
	}
	recipe, ok := v.Recipes[out.Source.Recipe]
	if !ok || len(recipe.Stages) != len(stages) {
		return schema.View{}, fmt.Errorf("clone-copy output lacks its complete declared native recipe")
	}
	views := make([]schema.View, len(stages))
	for index, name := range stages {
		stage := recipe.Stages[index]
		if stage.Name != name || stage.From != "" && (index == 0 || stage.From != stages[index-1]) {
			return schema.View{}, fmt.Errorf("unqualified clone-copy recipe stage %q", stage.Name)
		}
		ref := out.Source
		ref.Stage = name
		k, ok := v.Cases[CaseKey(ref)]
		if !ok || k.Observation == nil {
			return schema.View{}, fmt.Errorf("clone-copy clock lacks native stage %s", CaseKey(ref))
		}
		view, err := onlyLiveView(k.Observation)
		if err != nil {
			return schema.View{}, err
		}
		views[index] = view
	}
	clock, err := CloneCopyCommandClock(views)
	if err != nil || out.Expect.CommandClockNS != clock {
		return schema.View{}, fmt.Errorf("clone-copy command clock is not bound to native inventory: declared %d, expected %d: %v", out.Expect.CommandClockNS, clock, err)
	}
	to := slices.Index(stages, out.Expect.View)
	if to < 1 {
		return schema.View{}, fmt.Errorf("clone-copy output has no qualified target stage")
	}
	from := to - 1
	if out.Operation == "build" {
		from = 0
	}
	if out.Source.Stage != stages[from] {
		return schema.View{}, fmt.Errorf("clone-copy source stage %q does not bind target %q", out.Source.Stage, out.Expect.View)
	}
	var steps []schema.Step
	for i := from + 1; i <= to; i++ {
		steps = append(steps, recipe.Stages[i].Steps...)
	}
	after, err := onlyLiveView(target)
	if err != nil {
		return schema.View{}, err
	}
	return CloneCopyReference(views[from], after, steps, out.Source.Profile, clock)
}

// retainedCloneCopyIdentities selects paths whose inode actually survives the
// native command, excluding entries replaced by cp -c at an existing name.
func retainedCloneCopyIdentities(before, after schema.View) map[string]bool {
	ids := map[string]uint64{}
	for _, entry := range before.Entries {
		ids[entry.Path] = entry.ID
	}
	retained := map[string]bool{}
	for _, entry := range after.Entries {
		if ids[entry.Path] != 0 && ids[entry.Path] == entry.ID {
			retained[entry.Path] = true
		}
	}
	return retained
}
