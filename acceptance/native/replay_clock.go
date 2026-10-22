package native

import (
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// replayCommandClock is the explicit clock passed by the portable stage-replay
// producer to imageedit.Options, independent of Apple's capture wall clock.
const replayCommandClock int64 = 1749283750000000000

type replayClockNode struct {
	times schema.Times
}

type replayClockVolume struct {
	paths  map[string]*replayClockNode
	edited bool
}

// replayClockViews projects only a multi-volume replay's declared commands.
// The source observation supplies preserved clocks and hard-link identities;
// recipe commands supply changed clocks. No actual output values are consulted.
func (v *Verifier) replayClockViews(out schema.Output, target *schema.Observation) (map[string]schema.View, error) {
	if out.Source.Recipe == "apfs-clones" || out.Source.Recipe == "encrypted-image-edits" {
		return v.singleVolumeEditClocks(out, target)
	}
	if out.Operation != "edit" || !out.Expect.NewIdentities || out.Expect.View == "" || len(target.Volumes) < 2 {
		return nil, nil
	}
	source, ok := v.Cases[CaseKey(out.Source)]
	if !ok || source.Observation == nil {
		return nil, fmt.Errorf("multi-volume replay lacks its native source")
	}
	recipe, ok := v.Recipes[out.Source.Recipe]
	if !ok {
		return nil, fmt.Errorf("multi-volume replay lacks its command recipe")
	}
	var stage *schema.Stage
	for i := range recipe.Stages {
		if recipe.Stages[i].Name != out.Expect.View {
			continue
		}
		if stage != nil || i == 0 {
			return nil, fmt.Errorf("ambiguous replay target stage %q", out.Expect.View)
		}
		stage = &recipe.Stages[i]
		from := stage.From
		if from == "" {
			from = recipe.Stages[i-1].Name
		}
		if from != out.Source.Stage {
			return nil, fmt.Errorf("replay stage %q starts from %q, output names %q", stage.Name, from, out.Source.Stage)
		}
	}
	if stage == nil {
		return nil, fmt.Errorf("missing replay target stage %q", out.Expect.View)
	}
	volumes := map[string]*replayClockVolume{}
	for _, volume := range source.Observation.Volumes {
		view, err := observedView(source.Observation, volume.Index, "")
		if err != nil {
			return nil, err
		}
		state := &replayClockVolume{paths: map[string]*replayClockNode{}}
		objects := map[uint64]*replayClockNode{}
		for _, entry := range view.Entries {
			node := objects[entry.ID]
			if node == nil {
				node = &replayClockNode{times: entry.Times}
				objects[entry.ID] = node
			}
			state.paths[entry.Path] = node
		}
		volumes[volumeName(volume)] = state
	}
	for _, step := range stage.Steps {
		if len(step.Only) != 0 && !slices.Contains(step.Only, out.Source.Profile) {
			continue
		}
		var command schema.FSStep
		switch {
		case step.FS != nil:
			command = *step.FS
		case step.Tool != nil && step.Tool.Program == "ln" && step.Tool.Expect == "0" && len(step.Tool.Args) == 2:
			command = schema.FSStep{Op: "link", Path: step.Tool.Args[0], Target: step.Tool.Args[1]}
		case step.Host != nil:
			continue
		default:
			return nil, fmt.Errorf("unqualified multi-volume replay clock command")
		}
		name, rel, err := replayClockPath(command.Path)
		if err != nil {
			return nil, err
		}
		volume := volumes[name]
		if volume == nil {
			return nil, fmt.Errorf("replay clock command names unknown volume %q", name)
		}
		if command.Expect != "" && command.Expect != "0" {
			return nil, fmt.Errorf("refused command cannot define replay clocks")
		}
		if err := volume.apply(command, name, rel); err != nil {
			return nil, err
		}
		volume.edited = true
	}
	projected := map[string]schema.View{}
	for _, volume := range target.Volumes {
		name := volumeName(volume)
		state := volumes[name]
		if state == nil {
			return nil, fmt.Errorf("replay target introduced unknown volume %q", name)
		}
		if !state.edited {
			continue
		}
		view, err := observedView(target, volume.Index, "")
		if err != nil {
			return nil, err
		}
		view.Entries = append([]schema.Entry(nil), view.Entries...)
		for i := range view.Entries {
			node := state.paths[view.Entries[i].Path]
			if node == nil {
				return nil, fmt.Errorf("replayed path %s:%s has no declared clock source", name, view.Entries[i].Path)
			}
			view.Entries[i].Times = node.times
		}
		projected[name] = view
	}
	return projected, nil
}

func replayClockPath(value string) (string, string, error) {
	if !strings.HasPrefix(value, "$MOUNT:") {
		return "", "", fmt.Errorf("multi-volume replay path %q has no explicit volume", value)
	}
	name, rel, ok := strings.Cut(strings.TrimPrefix(value, "$MOUNT:"), "/")
	if !ok || name == "" || path.Clean(rel) != rel || rel == "." || strings.HasPrefix(rel, "../") {
		return "", "", fmt.Errorf("invalid multi-volume replay path %q", value)
	}
	return name, strings.TrimSuffix(rel, "/..namedfork/rsrc"), nil
}

func (v *replayClockVolume) parentChanged(rel string) {
	if parent := v.paths[path.Dir(rel)]; parent != nil {
		parent.times.Modify, parent.times.Change = replayCommandClock, replayCommandClock
	}
}

func (v *replayClockVolume) apply(command schema.FSStep, volume, rel string) error {
	node := v.paths[rel]
	switch command.Op {
	case "write":
		if node == nil {
			node = &replayClockNode{times: replayNewTimes()}
			v.paths[rel] = node
			v.parentChanged(rel)
		}
		node.times.Modify, node.times.Change = replayCommandClock, replayCommandClock
	case "mkdir":
		if node != nil {
			return fmt.Errorf("replay mkdir names existing path %s:%s", volume, rel)
		}
		v.paths[rel] = &replayClockNode{times: replayNewTimes()}
		v.parentChanged(rel)
	case "chmod", "chflags", "setxattr", "removexattr":
		if node == nil {
			return fmt.Errorf("replay metadata path %s:%s is missing", volume, rel)
		}
		node.times.Change = replayCommandClock
	case "settimes":
		if node == nil || command.Times == nil || command.Times.Birth != 0 {
			return fmt.Errorf("invalid replay clock command on %s:%s", volume, rel)
		}
		if ns := command.Times.Modify; ns != 0 {
			node.times.Modify = ns
			// The public APFS touch policy clips birth when backdating mtime.
			// Every alias borrows this same inode clock state.
			node.times.Birth = min(node.times.Birth, ns)
		}
		if ns := command.Times.Access; ns != 0 {
			node.times.Access = ns
		}
		node.times.Change = replayCommandClock
	case "link", "rename":
		targetVolume, target, err := replayClockPath(command.Target)
		if err != nil {
			return err
		}
		if node == nil || targetVolume != volume || v.paths[target] != nil {
			return fmt.Errorf("ambiguous replay %s from %s:%s", command.Op, volume, rel)
		}
		if command.Op == "rename" && strings.HasPrefix(target, rel+"/") {
			return fmt.Errorf("replay rename moves %s:%s into its own subtree", volume, rel)
		}
		node.times.Change = replayCommandClock
		v.parentChanged(target)
		if command.Op == "link" {
			v.paths[target] = node
		} else {
			v.parentChanged(rel)
			for name, child := range v.paths {
				if name == rel || strings.HasPrefix(name, rel+"/") {
					delete(v.paths, name)
					v.paths[target+strings.TrimPrefix(name, rel)] = child
				}
			}
		}
	default:
		return fmt.Errorf("unqualified multi-volume replay clock operation %q", command.Op)
	}
	return nil
}

func replayNewTimes() schema.Times {
	return schema.Times{Birth: replayCommandClock, Modify: replayCommandClock, Change: replayCommandClock, Access: replayCommandClock}
}
