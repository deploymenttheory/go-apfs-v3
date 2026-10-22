package native

import (
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

type editedClockNode struct {
	id     uint64
	kind   string
	target string
	times  schema.Times
}

type editedClockState struct {
	paths   map[string]*editedClockNode
	clock   int64
	profile string
}

// ProjectEditedViewClocks replaces only the four inode clocks in an independent
// native target view. Native source identities establish aliases; declared
// recipe operations and the supplied public operation clock establish changed
// clocks. No product output is an input. This deliberately supports only the
// commands qualified by the clone and encrypted-image edit recipes.
func ProjectEditedViewClocks(source, target schema.View, steps []schema.Step, profile string, clockNS int64) (schema.View, error) {
	if source.Snapshot != "" || target.Snapshot != "" || !slices.Contains([]string{"apfs", "apfsx", "hfsplus", "hfsx"}, profile) {
		return schema.View{}, fmt.Errorf("edited clock projection requires a qualified live filesystem profile")
	}
	if clockNS <= 0 || clockNS%1_000_000_000 != 0 {
		return schema.View{}, fmt.Errorf("edited view needs a positive whole-second command clock")
	}
	state := editedClockState{paths: map[string]*editedClockNode{}, clock: clockNS, profile: profile}
	objects := map[uint64]*editedClockNode{}
	for _, entry := range source.Entries {
		if entry.Path == "" || entry.Path == ".." || path.Clean(entry.Path) != entry.Path || strings.HasPrefix(entry.Path, "/") || strings.HasPrefix(entry.Path, "../") || entry.ID == 0 || state.paths[entry.Path] != nil || !slices.Contains([]string{"file", "dir", "symlink"}, entry.Kind) {
			return schema.View{}, fmt.Errorf("invalid native clock source path %q", entry.Path)
		}
		node := objects[entry.ID]
		if node == nil {
			node = &editedClockNode{id: entry.ID, kind: entry.Kind, target: entry.Target, times: entry.Times}
			objects[entry.ID] = node
		} else if node.kind != entry.Kind || node.target != entry.Target || !sameInodeClocks(node.times, entry.Times) {
			return schema.View{}, fmt.Errorf("native aliases disagree on clocks: %q", entry.Path)
		}
		state.paths[entry.Path] = node
	}
	for index, step := range steps {
		if len(step.Only) != 0 && !slices.Contains(step.Only, profile) {
			continue
		}
		var err error
		switch {
		case step.FS != nil && step.Tool == nil && step.Host == nil && step.Control == nil:
			if step.FS.Op == "clone" && step.FS.Expect == "EEXIST" {
				err = state.rejectedClone(*step.FS)
			} else {
				err = state.apply(*step.FS)
			}
		case step.Tool != nil && step.FS == nil && step.Host == nil && step.Control == nil:
			command := step.Tool
			if command.Program != "cp" || len(command.Args) != 3 || len(command.Stdin) != 0 || command.StdinBytes != "" {
				err = fmt.Errorf("unqualified edited clock tool command")
			} else if command.Args[0] == "-a" && command.Expect == "0" {
				err = state.archive(command.Args[1], command.Args[2])
			} else {
				err = state.cloneCopy(*command)
			}
		default:
			err = fmt.Errorf("unqualified edited clock step")
		}
		if err != nil {
			return schema.View{}, fmt.Errorf("edited clock step %d: %w", index+1, err)
		}
	}
	result := target
	result.Entries = slices.Clone(target.Entries)
	seen := map[string]bool{}
	identities := map[uint64]*editedClockNode{}
	aliases := map[*editedClockNode]uint64{}
	for i := range result.Entries {
		entry := &result.Entries[i]
		node := state.paths[entry.Path]
		if node == nil || seen[entry.Path] || entry.ID == 0 || node.kind != entry.Kind || node.id != 0 && node.id != entry.ID || identities[entry.ID] != nil && identities[entry.ID] != node || aliases[node] != 0 && aliases[node] != entry.ID {
			return schema.View{}, fmt.Errorf("native clock target path %q has no unique matching declared object", entry.Path)
		}
		seen[entry.Path] = true
		identities[entry.ID], aliases[node] = node, entry.ID
		entry.Times.Birth, entry.Times.Modify, entry.Times.Change, entry.Times.Access = node.times.Birth, node.times.Modify, node.times.Change, node.times.Access
	}
	if len(seen) != len(state.paths) {
		return schema.View{}, fmt.Errorf("native clock target omits declared paths")
	}
	return result, nil
}

func sameInodeClocks(a, b schema.Times) bool {
	return a.Birth == b.Birth && a.Modify == b.Modify && a.Change == b.Change && a.Access == b.Access
}

func editedClockPath(value string) (string, error) {
	if !strings.HasPrefix(value, "$MOUNT/") {
		return "", fmt.Errorf("edited clock path %q is not a single-volume mounted path", value)
	}
	rel := strings.TrimPrefix(value, "$MOUNT/")
	rel = strings.TrimSuffix(rel, "/")
	if rel == "" || rel == "." || path.Clean(rel) != rel || strings.HasPrefix(rel, "/") || rel == ".." || strings.HasPrefix(rel, "../") {
		return "", fmt.Errorf("invalid edited clock path %q", value)
	}
	return rel, nil
}

func (s *editedClockState) parentChanged(rel string) error {
	parent := path.Dir(rel)
	if parent == "." {
		return nil
	} // The observer does not include the volume root.
	node := s.paths[parent]
	if node == nil || node.kind != "dir" {
		return fmt.Errorf("edited clock parent %q is missing or not a directory", parent)
	}
	node.times.Modify, node.times.Change = s.clock, s.clock
	return nil
}

func (s *editedClockState) newNode(kind string) *editedClockNode {
	return &editedClockNode{kind: kind, times: schema.Times{Birth: s.clock, Modify: s.clock, Change: s.clock, Access: s.clock}}
}

func (s *editedClockState) apply(command schema.FSStep) error {
	if command.Expect != "" && command.Expect != "0" {
		return fmt.Errorf("rejected operation cannot define edited clocks")
	}
	rel, err := editedClockPath(command.Path)
	if err != nil {
		return err
	}
	fork := strings.HasSuffix(rel, "/..namedfork/rsrc")
	if fork {
		rel = strings.TrimSuffix(rel, "/..namedfork/rsrc")
	}
	node := s.paths[rel]
	switch command.Op {
	case "write", "truncate":
		if command.Op == "truncate" && (node == nil || command.Bytes != 0) || fork && node == nil {
			return fmt.Errorf("unqualified truncate or missing fork owner %q", rel)
		}
		if node == nil {
			if err := s.parentChanged(rel); err != nil {
				return err
			}
			node = s.newNode("file")
			s.paths[rel] = node
		}
		if node.kind != "file" {
			return fmt.Errorf("edited data target %q is not a file", rel)
		}
		node.times.Modify, node.times.Change = s.clock, s.clock
	case "chmod", "chflags", "setxattr", "removexattr":
		if node == nil || fork {
			return fmt.Errorf("missing metadata clock target %q", rel)
		}
		node.times.Change = s.clock
	case "mkdir", "symlink":
		if node != nil || fork {
			return fmt.Errorf("edited creation target %q already exists", rel)
		}
		if err := s.parentChanged(rel); err != nil {
			return err
		}
		kind := "dir"
		if command.Op == "symlink" {
			kind = "symlink"
		}
		s.paths[rel] = s.newNode(kind)
	case "link", "rename":
		target, err := editedClockPath(command.Target)
		if err != nil {
			return err
		}
		if node == nil || fork || s.paths[target] != nil || strings.HasPrefix(target, rel+"/") || command.Op == "link" && node.kind != "file" {
			return fmt.Errorf("unqualified edited %s from %q to %q", command.Op, rel, target)
		}
		if err := s.parentChanged(target); err != nil {
			return err
		}
		node.times.Change = s.clock
		if command.Op == "link" {
			s.paths[target] = node
			return nil
		}
		if err := s.parentChanged(rel); err != nil {
			return err
		}
		moved := map[string]*editedClockNode{}
		for name, child := range s.paths {
			if name == rel || strings.HasPrefix(name, rel+"/") {
				moved[target+strings.TrimPrefix(name, rel)] = child
				delete(s.paths, name)
			}
		}
		for name, child := range moved {
			s.paths[name] = child
		}
	case "unlink", "rmdir":
		if node == nil || fork || command.Op == "unlink" && node.kind == "dir" || command.Op == "rmdir" && node.kind != "dir" {
			return fmt.Errorf("missing or wrong-kind edited removal %q", rel)
		}
		for name := range s.paths {
			if strings.HasPrefix(name, rel+"/") {
				return fmt.Errorf("edited removal directory %q is not empty", rel)
			}
		}
		if err := s.parentChanged(rel); err != nil {
			return err
		}
		node.times.Change = s.clock
		delete(s.paths, rel)
	default:
		return fmt.Errorf("unqualified edited clock operation %q", command.Op)
	}
	return nil
}

func (s *editedClockState) archive(source, destination string) error {
	from, err := editedClockPath(source)
	if err != nil {
		return err
	}
	to, err := editedClockPath(destination)
	if err != nil {
		return err
	}
	if s.paths[from] == nil || s.paths[from].kind != "dir" || s.paths[to] != nil || strings.HasPrefix(to, from+"/") {
		return fmt.Errorf("unqualified archive copy from %q to %q", from, to)
	}
	var names []string
	for name := range s.paths {
		if name == from || strings.HasPrefix(name, from+"/") {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	for _, name := range names {
		original := s.paths[name]
		dest := to + strings.TrimPrefix(name, from)
		if err := s.parentChanged(dest); err != nil {
			return err
		}
		node := s.newNode(original.kind)
		// Apple's cp uses utimensat, not a creation-time setter. New objects
		// retain creation time unless an earlier copied mtime lowers it.
		node.times.Birth = min(s.clock, original.times.Modify)
		node.times.Modify, node.times.Access = original.times.Modify, original.times.Access
		s.paths[dest] = node
	}
	// cp -a restores directory metadata after copying descendants.
	for _, name := range names {
		original := s.paths[name]
		if original.kind == "dir" {
			node := s.paths[to+strings.TrimPrefix(name, from)]
			node.times.Modify, node.times.Access = original.times.Modify, original.times.Access
		}
	}
	return nil
}
