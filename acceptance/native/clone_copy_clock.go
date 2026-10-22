package native

import (
	"fmt"
	"path"
	"slices"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

// CloneCopyReference projects the explicit command clock through declared
// clone-copy operations. Independent native inode IDs retain hard-link aliases;
// each successful cp -c regular-file copy creates a separate inode. Native
// source and target views remain unchanged, and no product output is an input.
// Callers replaying a session supply all steps from the initial native view;
// existing-image callers supply the single target stage's steps.
func CloneCopyReference(before, after schema.View, steps []schema.Step, profile string, clockNS int64) (schema.View, error) {
	return ProjectEditedViewClocks(before, after, steps, profile, clockNS)
}

func (s *editedClockState) resolveCloneSource(name string) (string, error) {
	for range 32 {
		node := s.paths[name]
		if node == nil {
			return "", fmt.Errorf("clone clock source %q is absent", name)
		}
		if node.kind != "symlink" {
			return name, nil
		}
		if node.target == "" || strings.HasPrefix(node.target, "/") {
			return "", fmt.Errorf("unqualified clone clock source symlink %q", name)
		}
		name = path.Join(path.Dir(name), node.target)
		if name == "." || name == ".." || strings.HasPrefix(name, "../") {
			return "", fmt.Errorf("clone clock source symlink escapes observed view")
		}
	}
	return "", fmt.Errorf("clone clock source symlink loop")
}

func (s *editedClockState) rejectedClone(command schema.FSStep) error {
	from, err := editedClockPath(command.Path)
	if err != nil {
		return err
	}
	to, err := editedClockPath(command.Target)
	if err != nil {
		return err
	}
	if !slices.Contains([]string{"apfs", "apfsx"}, s.profile) || s.paths[from] == nil || s.paths[from].kind != "file" || s.paths[to] == nil {
		return fmt.Errorf("clone EEXIST control lacks its source or occupied target")
	}
	return nil
}

func (s *editedClockState) cloneCopy(command schema.ToolStep) error {
	flag := command.Args[0]
	if !slices.Contains([]string{"-c", "-cp", "-cR", "-cX", "-cn"}, flag) {
		return fmt.Errorf("unqualified clone clock copy flags %q", flag)
	}
	from, err := editedClockPath(command.Args[1])
	if err != nil {
		return err
	}
	to, err := editedClockPath(command.Args[2])
	if err != nil {
		return err
	}
	if command.Expect == "1" && flag == "-cX" {
		return nil // cp rejects the incompatible options before any filesystem call.
	}
	if flag != "-cR" {
		from, err = s.resolveCloneSource(from)
		if err != nil {
			return err
		}
	}
	source, destination := s.paths[from], s.paths[to]
	if source == nil {
		return fmt.Errorf("clone clock copy has no source %q", from)
	}
	if command.Expect == "1" && (flag == "-cn" && destination != nil || flag == "-c" && source == destination) {
		return nil
	}
	if command.Expect != "0" || flag == "-cX" || flag == "-cn" || source == destination || strings.HasPrefix(to, from+"/") {
		return fmt.Errorf("clone clock copy has an unproved success or refusal")
	}
	if source.kind == "dir" {
		if flag != "-cR" || destination != nil {
			return fmt.Errorf("unqualified recursive clone clock destination")
		}
		var names []string
		for name := range s.paths {
			if name == from || strings.HasPrefix(name, from+"/") {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			if err := s.copyCloneClockNode(name, to+strings.TrimPrefix(name, from), false); err != nil {
				return err
			}
		}
		return nil
	}
	if source.kind != "file" || flag == "-cR" {
		return fmt.Errorf("unqualified regular clone clock source")
	}
	if destination != nil {
		if destination.kind == "dir" {
			return fmt.Errorf("unqualified occupied clone clock directory")
		}
		// cp unlinks the named entry before clonefile, also when the entry is
		// a symlink or clonefile subsequently falls back to ordinary copying.
		if err := s.apply(schema.FSStep{Op: "unlink", Path: command.Args[2]}); err != nil {
			return err
		}
	}
	return s.copyCloneClockNode(from, to, flag == "-cp")
}

func (s *editedClockState) copyCloneClockNode(from, to string, preserve bool) error {
	if s.paths[to] != nil {
		return fmt.Errorf("clone clock creation target %q is occupied", to)
	}
	if err := s.parentChanged(to); err != nil {
		return err
	}
	source := s.paths[from]
	node := s.newNode(source.kind)
	node.target = source.target
	if source.kind == "file" && slices.Contains([]string{"apfs", "apfsx"}, s.profile) {
		// clonefile copies the three source clocks even without -p. Its new
		// inode's ctime is the operation clock. It does not join hard links.
		node.times.Birth, node.times.Modify, node.times.Access = source.times.Birth, source.times.Modify, source.times.Access
	} else if preserve {
		node.times.Birth = min(s.clock, source.times.Modify)
		node.times.Modify, node.times.Access = source.times.Modify, source.times.Access
	}
	s.paths[to] = node
	return nil
}
