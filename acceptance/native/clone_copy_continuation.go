package native

import (
	"fmt"
	"sort"
	"strings"

	"github.com/deploymenttheory/go-apfs-v3/acceptance/schema"
)

func usesCloneCopyContinuation(out schema.Output) bool {
	return out.Source.Recipe == "clone-copy" && (out.Source.Profile == "apfs" || out.Source.Profile == "apfsx") && (out.Operation == "edit" || out.Operation == "build")
}

// These two final-state copies retain complete dense data/fork sharing after
// the original source is removed. A session build places Fixture at its root.
func cloneCopyContinuationPeers(out schema.Output) (string, string) {
	source, sibling := "Fixture/followed", "Fixture/overwrite"
	if out.Expect.Subtree != "" {
		source = strings.TrimPrefix(source, out.Expect.Subtree+"/")
		sibling = strings.TrimPrefix(sibling, out.Expect.Subtree+"/")
	}
	return source, sibling
}

func requireCloneCopyPartial(view schema.View, sourcePath string) error {
	var source, partial schema.Entry
	for _, entry := range view.Entries {
		switch entry.Path {
		case sourcePath:
			source = entry
		case retainedPartialClone:
			partial = entry
		}
	}
	forks, err := cloneCopyPhysicalForks(view, []string{sourcePath, retainedPartialClone})
	if err != nil {
		return err
	}
	if source.ID == 0 || source.Kind != "file" || partial.Kind != "file" || partial.ID == 0 || partial.ID == source.ID || partial.Links != 1 || partial.Size != source.Size {
		return fmt.Errorf("retained native clone-copy partial lacks independent identity/size")
	}
	for _, fork := range []string{"data", "resource"} {
		original, copied := forks[sourcePath+"/"+fork], forks[retainedPartialClone+"/"+fork]
		shared := sharedPhysicalBytes(original, copied)
		if physicalBytes(original) != physicalBytes(copied) || shared <= 0 || shared >= physicalBytes(original) {
			return fmt.Errorf("retained native clone-copy partial lacks private and shared %s ranges", fork)
		}
	}
	return nil
}

// Both views here are Apple observations of the same continuation layout.
// Compare every dense relation, including the retained native partial clone;
// no source/target pathname projection or absolute-address equality is needed.
func compareCloneCopyContinuation(after, before *schema.Observation, out schema.Output) error {
	want, err := onlyLiveView(before)
	if err != nil {
		return err
	}
	got, err := onlyLiveView(after)
	if err != nil {
		return err
	}
	source, _ := cloneCopyContinuationPeers(out)
	for _, view := range []schema.View{want, got} {
		if err := requireCloneCopyPartial(view, source); err != nil {
			return err
		}
	}
	paths := append(cloneCopyExtentPaths(out.Expect.Subtree), retainedPartialClone)
	expected, err := cloneCopyPhysicalForks(want, paths)
	if err != nil {
		return err
	}
	actual, err := cloneCopyPhysicalForks(got, paths)
	if err != nil {
		return err
	}
	if len(expected) != len(actual) {
		return fmt.Errorf("continued clone-copy physical fork inventory differs")
	}
	var names []string
	for name := range expected {
		if _, exists := actual[name]; !exists {
			return fmt.Errorf("continued clone-copy output lacks measured fork %q", name)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for i, first := range names {
		for _, second := range names[i+1:] {
			if sharedPhysicalBytes(expected[first], expected[second]) != sharedPhysicalBytes(actual[first], actual[second]) {
				return fmt.Errorf("continued clone-copy physical sharing changed for %s <> %s", first, second)
			}
		}
	}
	return nil
}
