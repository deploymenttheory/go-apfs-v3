package native

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// A failed physical predicate with confirmed release can collect its peer arm.
// Uncertain release must stop before another copy with the same filesystem
// identity is attached, while preserving every original failure.
func runForkMappingArms(ctx context.Context, run func(index int) (error, error)) error {
	return runForkMappingSeries(ctx, 2, run)
}

func runForkMappingSeries(ctx context.Context, count int, run func(index int) (error, error)) error {
	var result error
	for index := range count {
		if err := ctx.Err(); err != nil {
			if errors.Is(result, err) {
				return result
			}
			return errors.Join(result, err)
		}
		operation, cleanup := run(index)
		result = errors.Join(result, operation)
		if cleanup == nil && errors.Is(operation, errForkMappingEvidence) {
			return result
		}
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
	switch major {
	case 26:
		return "macos-26.clone-copy.apfs.refused.edit.clone-copy.UDZO.dmg"
	case 27:
		return "macos-27.clone-copy.apfsx.refused.edit.clone-copy.UDZO.dmg"
	default:
		return ""
	}
}

func requireCloneForkMappingInput(pairs []Paired, major int) error {
	want := cloneForkMappingInputName(major)
	if want == "" {
		return nil
	}
	profile := "apfs"
	if major == 27 {
		profile = "apfsx"
	}
	count := 0
	for _, p := range pairs {
		if p.Name != want {
			continue
		}
		count++
		o := p.Output
		if o.Name != want || o.Source.Producer != major || o.Source.Recipe != "clone-copy" || o.Source.Profile != profile || o.Source.Stage != "source-removed" || o.Operation != "edit" || o.Format != "UDZO" || o.Encrypted || o.Expect.View != "refused" || !o.Expect.Continuation {
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

// Eight predetermined pairs are independent trials, never verdict retries.
// Alternating order avoids confounding a target with always running second.
type forkMappingTrial struct {
	Pair   int
	Target string
}

func forkMappingTrials(major int) []forkMappingTrial {
	pairs := 1
	if major == 27 {
		pairs = 8
	} else if major != 26 {
		return nil
	}
	var trials []forkMappingTrial
	for pair := range pairs {
		targets := []string{"data", "resource"}
		if pair%2 != 0 {
			targets[0], targets[1] = targets[1], targets[0]
		}
		for _, target := range targets {
			trials = append(trials, forkMappingTrial{Pair: pair + 1, Target: target})
		}
	}
	return trials
}

func checkForkMappingRawBudget(bytes int64, arms int) error {
	if bytes <= 0 || bytes > 256<<20 || arms <= 0 || arms > 16 || bytes > (1<<30)/int64(arms) {
		return fmt.Errorf("paired raw evidence exceeds its 1GiB aggregate/256MiB member bound: %d bytes x %d arms", bytes, arms)
	}
	return nil
}

// The only observer action during the writer is persisting its original result.
// All additional native observations start after the writer returns naturally.
func runForkMappingObservedWriter(writer func(cloneForkCheckpoint) error, persist func(nativeCloneState, error) error, observe func() error) error {
	recorded, retained := false, false
	err := writer(func(_ string, original *nativeCloneState, verdict error) error {
		if original == nil {
			return nil
		}
		if recorded {
			return errors.New("paired original verdict recorded more than once")
		}
		recorded = true
		err := persist(*original, verdict)
		retained = err == nil
		return err
	})
	if errors.Is(err, errForkMappingEvidence) {
		return err
	}
	if !retained {
		if err == nil {
			return errors.New("paired writer returned without retained original verdict")
		}
		return err
	}
	return errors.Join(err, observe())
}

type forkMappingPhase struct{ Name, Action string }

// Both targets execute this exact fixed read/open/close sequence. The only
// intervention difference is which already-bound descriptor receives one sync.
func runForkMappingMeasurements(ctx context.Context, step func(forkMappingPhase) error) error {
	for _, phase := range []forkMappingPhase{
		{"retained-open", "open-retained"},
		{"before-reopen-old", "map-retained"},
		{"before-reopen-old-control", "map-retained"},
		{"before-reopen-new-open", "open-fresh"},
		{"before-reopen-new", "map-fresh"},
		{"before-reopen-old-again", "map-retained"},
		{"before-reopen-new-close", "close-fresh"},
		{"before-flush-readback", "read-retained"},
		{"before-extra-flush", "map-retained"},
		{"extra-flush", "flush"},
		{"after-extra-flush-old", "map-retained"},
		{"after-flush-new-open", "open-fresh"},
		{"after-flush-new", "map-fresh"},
		{"after-flush-old-again", "map-retained"},
		{"after-flush-old-readback", "read-retained"},
		{"after-flush-new-readback", "read-fresh"},
		{"after-flush-new-close", "close-fresh"},
		{"retained-close", "close-retained"},
	} {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := step(phase); err != nil {
			return fmt.Errorf("fork measurement %s: %w", phase.Name, err)
		}
	}
	return nil
}

func forkMappingRange(arg [20]byte, offset, size int64) (raw, logical [3]int64, err error) {
	length := int64(binary.LittleEndian.Uint64(arg[4:12]))
	physical := int64(binary.LittleEndian.Uint64(arg[12:20]))
	if offset < 0 || size <= offset || length <= 0 || physical < 0 || length > (1<<63-1)-offset || physical > (1<<63-1)-length {
		return raw, logical, errors.New("fork physical measurement returned invalid range")
	}
	return [3]int64{offset, physical, length}, [3]int64{offset, physical, min(length, size-offset)}, nil
}

func readForkMappingContents(size int64, read func([]byte, int64) (int, error)) (string, error) {
	if size <= 0 || size > 1<<20 {
		return "", errors.New("fork readback outside 1MiB bound")
	}
	data := make([]byte, size)
	n, err := read(data, 0)
	if err != nil || int64(n) != size {
		return "", errors.Join(errors.New("fork readback incomplete"), err)
	}
	var one [1]byte
	n, err = read(one[:], size)
	if n != 0 || !errors.Is(err, io.EOF) {
		return "", errors.Join(errors.New("fork EOF readback differs"), err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data)), nil
}
