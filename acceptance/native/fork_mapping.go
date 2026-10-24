package native

import (
	"bytes"
	"context"
	"errors"
	"fmt"
)

// A failed physical predicate with confirmed release can collect its peer arm.
// Uncertain release must stop before another copy with the same filesystem
// identity is attached, while preserving every original failure.
func runForkMappingArms(ctx context.Context, run func(index int) (error, error)) error {
	var result error
	for index := range 2 {
		if err := ctx.Err(); err != nil {
			if errors.Is(result, err) {
				return result
			}
			return errors.Join(result, err)
		}
		operation, cleanup := run(index)
		result = errors.Join(result, operation)
		if cleanup != nil {
			if !errors.Is(result, cleanup) {
				result = errors.Join(result, cleanup)
			}
			if err := ctx.Err(); err != nil && !errors.Is(result, err) {
				result = errors.Join(result, err)
			}
			return result
		}
	}
	if err := ctx.Err(); err != nil && !errors.Is(result, err) {
		return errors.Join(result, err)
	}
	return result
}

func cloneForkMappingInputName(major int) string {
	if major != 26 {
		return ""
	}
	return "macos-26.clone-copy.apfs.refused.edit.clone-copy.UDZO.dmg"
}

func requireCloneForkMappingInput(pairs []Paired, major int) error {
	want := cloneForkMappingInputName(major)
	if want == "" {
		return nil
	}
	count := 0
	for _, p := range pairs {
		if p.Name != want {
			continue
		}
		count++
		o := p.Output
		if o.Name != want || o.Source.Producer != major || o.Source.Recipe != "clone-copy" || o.Source.Profile != "apfs" || o.Source.Stage != "source-removed" || o.Operation != "edit" || o.Format != "UDZO" || o.Encrypted || o.Expect.View != "refused" || !o.Expect.Continuation {
			return fmt.Errorf("paired fork mapping input %s lost its exact native continuation contract", want)
		}
	}
	if count != 1 {
		return fmt.Errorf("paired fork mapping requires exactly one %s, found %d", want, count)
	}
	return nil
}

// cloneForkCheckpoint observes only the retained-clone part of the existing
// writer. The original pre-intervention verdict remains the writer's verdict.
type cloneForkCheckpoint func(point string, original *nativeCloneState, verdict error) error

func cloneStateReadOrder(observer cloneForkCheckpoint, paths map[string]string, ordered ...string) []string {
	if observer != nil {
		return ordered // Identical read order in both diagnostic arms.
	}
	// Normal continuations keep the original map iteration and operations.
	var names []string
	for name := range paths {
		names = append(names, name)
	}
	return names
}

func (f cloneForkCheckpoint) record(point string, original *nativeCloneState, verdict error) error {
	if f == nil {
		return nil
	}
	if original != nil {
		copy := *original
		copy.DataRuns = append([][3]int64(nil), original.DataRuns...)
		copy.ForkRuns = append([][3]int64(nil), original.ForkRuns...)
		copy.Attrs = make(map[string][]byte, len(original.Attrs))
		for name, data := range original.Attrs {
			copy.Attrs[name] = bytes.Clone(data)
		}
		original = &copy
	}
	return f(point, original, verdict)
}
