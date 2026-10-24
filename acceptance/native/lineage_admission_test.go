package native

import (
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func awaitLineage[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(5 * time.Second):
		t.Fatal("lineage admission did not make progress")
		var zero T
		return zero
	}
}

func TestLineageAdmissionPreservesPriorityAtTheConcurrencyBound(t *testing.T) {
	a := newLineageAdmission(2)
	keys := []string{"longest", "next", "short", "unmeasured"}
	started := make(chan string, len(keys))
	release := map[string]chan struct{}{}
	for _, key := range keys {
		release[key] = make(chan struct{}, 1)
	}
	t.Cleanup(func() {
		for _, ch := range release {
			select {
			case ch <- struct{}{}:
			default:
			}
		}
	})
	done := make(chan struct{})
	go func() {
		a.run(keys, func(key string) {
			started <- key
			<-release[key]
		})
		close(done)
	}()
	first := []string{awaitLineage(t, started), awaitLineage(t, started)}
	slices.Sort(first)
	if !slices.Equal(first, []string{"longest", "next"}) {
		t.Fatalf("lower-priority work occupied an initial slot: %v", first)
	}
	release["next"] <- struct{}{}
	if got := awaitLineage(t, started); got != "short" {
		t.Fatalf("next admitted lineage = %q, want short", got)
	}
	release["short"] <- struct{}{}
	if got := awaitLineage(t, started); got != "unmeasured" {
		t.Fatalf("unmeasured lineage was lost or reordered: %q", got)
	}
	release["longest"] <- struct{}{}
	release["unmeasured"] <- struct{}{}
	awaitLineage(t, done)
}

func TestLineageAdmissionSharesItsBoundAcrossConcurrentBatches(t *testing.T) {
	a := newLineageAdmission(2)
	var active, maximum atomic.Int32
	var seen sync.Map
	started := make(chan struct{}, 6)
	release := make(chan struct{}, 6)
	t.Cleanup(func() { close(release) })
	done := make(chan struct{}, 2)
	for _, keys := range [][]string{{"a", "b", "c"}, {"d", "e", "f"}} {
		go func() {
			a.run(keys, func(key string) {
				if _, loaded := seen.LoadOrStore(key, true); loaded {
					t.Errorf("lineage %q ran twice", key)
				}
				n := active.Add(1)
				defer active.Add(-1)
				for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
				}
				started <- struct{}{}
				<-release
			})
			done <- struct{}{}
		}()
	}
	for range 6 {
		awaitLineage(t, started)
		release <- struct{}{}
	}
	awaitLineage(t, done)
	awaitLineage(t, done)
	if got := maximum.Load(); got > 2 {
		t.Fatalf("concurrent batches exceeded their shared bound: %d", got)
	}
	for _, key := range []string{"a", "b", "c", "d", "e", "f"} {
		if _, ok := seen.Load(key); !ok {
			t.Errorf("lineage %q was omitted", key)
		}
	}
}

func TestLineageAdmissionKeepsTheSlotThroughCleanupAndContinuesAfterAbortedWork(t *testing.T) {
	a := newLineageAdmission(1)
	cleanup := make(chan struct{})
	finishCleanup := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(finishCleanup) }) }
	t.Cleanup(finish)
	remaining := make(chan struct{})
	done := make(chan struct{})
	go func() {
		a.run([]string{"failed", "remaining"}, func(key string) {
			if key == "failed" {
				defer func() {
					close(cleanup)
					<-finishCleanup
				}()
				// Fatal aborts a test goroutine using Goexit. Admission must
				// still run its defers and every remaining required lineage.
				runtime.Goexit()
			}
			close(remaining)
		})
		close(done)
	}()
	awaitLineage(t, cleanup)
	select {
	case <-remaining:
		t.Fatal("a filesystem identity slot was released before cleanup")
	default:
	}
	finish()
	awaitLineage(t, remaining)
	awaitLineage(t, done)
}
